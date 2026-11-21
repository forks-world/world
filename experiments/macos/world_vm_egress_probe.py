"""One stream at a time through the real host policy proxy and an offline VM."""
import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit

BUDGET = 512 * 1024

GUEST_LINK = r"""
import os, socket, threading

with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(12)
    print(listener.getsockname()[1], flush=True)
    client, _ = listener.accept()
    listener.close()
    with client:
        client.settimeout(10)

        def from_host():
            left = 512 * 1024
            while data := os.read(0, 8192):
                left -= len(data)
                if left < 0:
                    client.close()
                    return
                client.sendall(data)
            client.shutdown(socket.SHUT_WR)

        worker = threading.Thread(target=from_host, daemon=True)
        worker.start()
        left = 512 * 1024
        while data := client.recv(8192):
            left -= len(data)
            if left < 0:
                raise ValueError('guest upload exceeded probe budget')
            view = memoryview(data)
            while view:
                view = view[os.write(1, view):]
"""

GUEST_REQUEST = r"""
import base64, http.client, json, os, socket, ssl, sys
from urllib.parse import urlsplit

assert os.getuid() == 1000
assert [name for _, name in socket.if_nameindex()] == ['lo']
authority, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
proxy = urlsplit(sys.stdin.readline().strip())
auth = base64.b64encode(f'{proxy.username}:{proxy.password}'.encode()).decode()
if mode == 'bad-credential':
    auth = base64.b64encode(b'world:wrong').decode()
header = 'Basic ' + auth

if mode == 'tls':
    connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=8,
                                             context=ssl.create_default_context())
    connection.set_tunnel(authority, 443, {'Proxy-Authorization': header})
    try:
        connection.request('GET', '/')
        response = connection.getresponse()
        assert response.status == 200, response.status
        assert b'Example Domain' in response.read(64 * 1024)
        print(json.dumps({'tls_http_status': response.status, 'certificate_verified': True}))
    finally:
        connection.close()
else:
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
    try:
        connection.request('CONNECT', authority, headers={'Proxy-Authorization': header})
        status = connection.getresponse().status
        assert status == (407 if mode == 'bad-credential' else 403), status
        print(json.dumps({'proxy_status': status}))
    except OSError:
        if mode != 'lost-broker':
            raise
        print(json.dumps({'closed': True}))
    else:
        assert mode != 'lost-broker', 'closed broker returned HTTP'
    finally:
        connection.close()
"""

GUEST_DIRECT = r"""
import errno, json, socket
assert [name for _, name in socket.if_nameindex()] == ['lo']
for family, kind, addr in [
    (socket.AF_INET, socket.SOCK_STREAM, ('192.168.64.1', 80)),
    (socket.AF_INET6, socket.SOCK_STREAM, ('2606:4700:4700::1111', 443)),
    (socket.AF_INET, socket.SOCK_DGRAM, ('192.168.64.1', 53)),
    (socket.AF_INET6, socket.SOCK_DGRAM, ('fd00::1', 53)),
]:
    with socket.socket(family, kind) as client:
        client.settimeout(2)
        assert client.connect_ex(addr) in (errno.ENETUNREACH, errno.EHOSTUNREACH), addr
print(json.dumps({'direct_ipv4_ipv6_dns_blocked': True}))
"""


async def stop(process):
    if process is not None and process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()


async def pump(reader, writer):
    left = BUDGET
    try:
        while data := await reader.read(8192):
            left -= len(data)
            if left < 0:
                raise ValueError('relay exceeded probe byte budget')
            writer.write(data)
            await writer.drain()
    finally:
        if not writer.is_closing():
            writer.write_eof()


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--world', type=Path, default=Path('target/debug/world'))
    parser.add_argument('--proxy', type=Path,
                        default=Path('target/debug/examples/vm_egress_proxy'))
    args = parser.parse_args()
    world, proxy_command = (str(p.resolve(strict=True)) for p in (args.world, args.proxy))
    evidence = Path(tempfile.mkdtemp(prefix='world-vm-egress-'))
    state = evidence / 'state'
    results = {}
    print(f'Evidence: {evidence}', flush=True)

    def record(label, value):
        results[label] = value
        (evidence / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(f'{label}: {value}', flush=True)

    def command(*argv, check=True):
        result = subprocess.run(argv, text=True, capture_output=True, timeout=90)
        if check and result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout

    def workspace(*options, check=True):
        return command(world, 'workspace', '--state-dir', str(state), *options, check=check)

    def start_guest(instance, code, *argv):
        return asyncio.create_subprocess_exec(
            'container', 'exec', '-i', '--user', '1000:1000', instance, 'python3', '-I', '-u',
            '-c', code, *map(str, argv),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def request(instance, proxy_url, authority, mode, *, disconnect=None):
        relay = client = None
        streams = []
        writer = None
        try:
            relay = await start_guest(instance, GUEST_LINK)
            port = int(await asyncio.wait_for(relay.stdout.readline(), 5))
            destination = urlsplit(proxy_url)
            reader, writer = await asyncio.open_connection(destination.hostname, destination.port)
            if disconnect is not None:
                disconnect.stdin.close()
                assert await asyncio.wait_for(disconnect.wait(), 5) == 0
            streams = [
                asyncio.create_task(pump(relay.stdout, writer)),
                asyncio.create_task(pump(reader, relay.stdin)),
            ]
            client = await start_guest(instance, GUEST_REQUEST, authority, port, mode)
            # Credentials stay in process pipes. The transcript includes responses only.
            output, _ = await asyncio.wait_for(client.communicate((proxy_url + '\n').encode()), 15)
            assert client.returncode == 0, f'guest {mode} request failed for {authority}'
            return json.loads(output)
        finally:
            for stream in streams:
                stream.cancel()
            outcomes = await asyncio.gather(*streams, return_exceptions=True)
            if writer is not None:
                writer.close()
            await stop(client)
            await stop(relay)
            for outcome in outcomes:
                if isinstance(outcome, ValueError):
                    raise outcome

    def policy(path, host):
        path.write_text(json.dumps({'network_id': 'vm-egress-probe',
                                    'allow': [{'host': host, 'port': 443}]}))

    denied_policy = evidence / 'denied.json'
    for address in ('127.0.0.1', '192.168.64.1', '::ffff:127.0.0.1', 'fd00::1', 'printer.local'):
        policy(denied_policy, address)
        result = subprocess.run([proxy_command, str(denied_policy)], input=b'',
                                capture_output=True, timeout=10)
        assert result.returncode and not result.stdout, f'loaded denied policy {address}'
    record('private-and-local-policies-rejected', True)
    allowed_policy = evidence / 'policy.json'
    policy(allowed_policy, 'example.com')
    vm = process = None
    try:
        vm = json.loads(workspace('create', 'probe', '--os', 'linux', '--network', 'offline',
                                  '--memory', '256M'))
        workspace('setup', 'probe')
        observed = json.loads(workspace('show', 'probe'))
        assert observed['capabilities']['offline_network']
        instance = vm['instance_id']
        with (evidence / 'proxy.stderr').open('wb') as errors:
            process = await asyncio.create_subprocess_exec(
                proxy_command, str(allowed_policy), stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=errors,
            )
        proxy_url = (await asyncio.wait_for(process.stdout.readline(), 10)).decode().strip()
        assert urlsplit(proxy_url).hostname == '127.0.0.1', 'host proxy failed to start'
        record('allowed-public-https', await request(instance, proxy_url, 'example.com', 'tls'))
        for name, authority in [
            ('other-domain', 'example.org:443'),
            ('other-port', 'example.com:80'),
            ('host-loopback', '127.0.0.1:443'),
            ('provider-gateway', '192.168.64.1:443'),
            ('private-ipv6', '[fd00::1]:443'),
            ('mapped-loopback', '[::ffff:127.0.0.1]:443'),
            ('local-discovery', 'printer.local:443'),
        ]:
            record('deny-' + name, await request(instance, proxy_url, authority, 'denied'))
        record('deny-wrong-credential',
               await request(instance, proxy_url, 'example.com:443', 'bad-credential'))
        direct = command(world, 'exec', 'probe', '--state-dir', str(state), '--',
                         'python3', '-I', '-c', GUEST_DIRECT)
        record('no-guest-route', json.loads(direct))
        record('broker-exit', await request(instance, proxy_url, 'example.com:443', 'lost-broker',
                                            disconnect=process))
    finally:
        await stop(process)
        if vm is not None:
            workspace('teardown', 'probe', check=False)
            command('container', 'stop', '--time', '1', vm['instance_id'], check=False)
            workspace('delete', 'probe', '--discard-runtime-data')
    print('Offline VM policy egress probe PASS', flush=True)


if __name__ == '__main__':
    asyncio.run(main())
