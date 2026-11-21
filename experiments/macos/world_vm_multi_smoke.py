"""Verify admission, loopback isolation, and optional policy egress with two real VMs."""

import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from world_vm_egress_exec_smoke import STOP_BRIDGE


NETWORK_PROBE = r"""
import errno
import os
import socket

assert os.getuid() == 1000
assert [name for _, name in socket.if_nameindex()] == ['lo']
for family, kind, endpoint in (
    (socket.AF_INET, socket.SOCK_STREAM, ('192.168.64.1', 80)),
    (socket.AF_INET, socket.SOCK_STREAM, ('192.168.64.2', 8080)),
    (socket.AF_INET, socket.SOCK_STREAM, ('198.51.100.1', 443)),
    (socket.AF_INET6, socket.SOCK_STREAM, ('2001:db8::1', 443)),
    (socket.AF_INET, socket.SOCK_DGRAM, ('192.168.64.1', 53)),
    (socket.AF_INET6, socket.SOCK_DGRAM, ('2001:db8::1', 53)),
):
    with socket.socket(family, kind) as sock:
        sock.settimeout(2)
        assert sock.connect_ex(endpoint) in (errno.ENETUNREACH, errno.EHOSTUNREACH), endpoint
print('only loopback, no IPv4/IPv6 routes to host, peers, internet, or DNS')
"""

EGRESS_WORKLOAD = r"""
import base64
from contextlib import closing
import http.client
import os
from pathlib import Path
import socket
import ssl
import sys
import time
import urllib.request
from urllib.parse import urlsplit

allowed, denied = sys.argv[1:]
assert [name for _, name in socket.if_nameindex()] == ['lo']
proxy = urlsplit(os.environ['HTTPS_PROXY'])
auth = base64.b64encode(f'{proxy.username}:{proxy.password}'.encode()).decode()
headers = {'Proxy-Authorization': 'Basic ' + auth}
with closing(http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=5)) as connection:
    connection.request('CONNECT', f'{denied}:443', headers=headers)
    assert connection.getresponse().status == 403, denied

def fetch():
    with urllib.request.urlopen(f'https://{allowed}/', timeout=8) as response:
        assert response.status == 200 and b'Example Domain' in response.read(64 * 1024)

fetch()
tunnel = http.client.HTTPSConnection(proxy.hostname, proxy.port, timeout=8,
                                     context=ssl.create_default_context())
try:
    tunnel.set_tunnel(allowed, 443, headers)
    tunnel.connect()
    marker = Path('egress-live.tmp')
    marker.write_text(str(os.getpid()))
    marker.rename('egress-live')
    deadline = time.monotonic() + 60
    while not Path('egress-release').exists():
        if time.monotonic() >= deadline:
            raise TimeoutError('egress workload was not released')
        time.sleep(0.1)
    tunnel.request('GET', '/')
    with tunnel.getresponse() as response:
        assert response.status == 200 and b'Example Domain' in response.read(64 * 1024)
    fetch()
    print(f'Existing and fresh HTTPS tunnels to {allowed} still work')
finally:
    tunnel.close()
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--world', type=Path, default=Path('target/debug/world'))
    parser.add_argument('--policy-egress', action='store_true',
                        help='also test concurrent execution policies using public HTTPS')
    args = parser.parse_args()
    world = str(args.world.resolve(strict=True))
    evidence = Path(tempfile.mkdtemp(prefix='world-vm-multi-'))
    print(f'Evidence: {evidence}', flush=True)
    entries = []
    owned = {}
    registries = {name: evidence / name for name in ('a', 'b', 'c')}

    def record(label, result, start, *, code=0, diagnostic=None):
        entries.append(dict(label=label, seconds=time.monotonic() - start, code=result.returncode,
                            stdout=result.stdout, stderr=result.stderr))
        (evidence / 'results.json').write_text(json.dumps(entries, indent=2) + '\n')
        print(f'{label}: {result.returncode}', flush=True)
        assert result.returncode == code, result.stderr
        if diagnostic:
            assert diagnostic in result.stderr, result.stderr
        return result.stdout

    def call(label, argv, **expected):
        start = time.monotonic()
        result = subprocess.run(argv, text=True, capture_output=True, timeout=120)
        return record(label, result, start, **expected)

    def workspace(label, name, action, *flags, **expected):
        return call(label, [world, 'workspace', '--state-dir', str(registries[name]),
                            action, name, *flags], **expected)

    def invocation(name, *argv, policy=None):
        options = ['--egress-policy', str(policy)] if policy else []
        return [world, 'exec', name, '--state-dir', str(registries[name]), *options, '--', *argv]

    def execute(label, name, *argv, **expected):
        return call(label, invocation(name, *argv), **expected)

    def service(label, name, action, *args, **expected):
        return call(label, [world, 'service', '--state-dir', str(registries[name]), action, name,
                            'web', *args], **expected)

    def read_port(port):
        # Disable inherited host proxy configuration for these loopback requests.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(30):
            try:
                with opener.open(f'http://127.0.0.1:{port}/index.html', timeout=2) as response:
                    return response.read().decode()
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise RuntimeError(f'loopback publication on {port} did not serve HTTP')

    def check_policy_egress(ports):
        hosts = {'a': 'example.com', 'b': 'www.example.com'}
        active = {}
        started = time.monotonic()

        def evidence_path(name, stream):
            return evidence / f'egress-{name}.{stream}'

        def finish(name, label, **expected):
            execution = active[name]
            execution.wait(timeout=20)
            return record(label, subprocess.CompletedProcess(
                execution.args, execution.returncode, evidence_path(name, 'stdout').read_text(),
                evidence_path(name, 'stderr').read_text()),
                started, **expected)

        def ready_pid(name):
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                execution = active[name]
                if execution.poll() is not None:
                    raise RuntimeError(evidence_path(name, 'stderr').read_text())
                result = subprocess.run(
                    ['container', 'exec', owned[name]['instance_id'], 'cat',
                     '/workspace/egress-live'], text=True, capture_output=True, timeout=5)
                if result.returncode == 0:
                    return int(result.stdout)
                time.sleep(0.2)
            raise TimeoutError(f'World {name} egress did not start')

        try:
            for name, peer in (('a', 'b'), ('b', 'a')):
                policy = evidence / f'egress-{name}.json'
                policy.write_text(json.dumps({'network_id': name, 'allow': [
                    {'host': hosts[name], 'port': 443}
                ]}))
                with evidence_path(name, 'stdout').open('w') as stdout, \
                        evidence_path(name, 'stderr').open('w') as stderr:
                    active[name] = subprocess.Popen(
                        invocation(name, 'python3', '-c', EGRESS_WORKLOAD, hosts[name], hosts[peer],
                                   policy=policy),
                        stdout=stdout, stderr=stderr)

            pids = {name: ready_pid(name) for name in hosts}
            assert all(execution.poll() is None for execution in active.values())
            record('both-policy-tunnels-ready', subprocess.CompletedProcess(
                [], 0, 'Both VMs verified HTTPS and rejected the other VM\'s target.\n', ''), started)

            diagnostics = evidence_path('a', 'stderr').read_text()
            token = re.search(r'execution ([0-9a-f]{32})', diagnostics)
            assert token, diagnostics
            call('stop-first-vm-egress-bridge',
                 ['container', 'exec', owned['a']['instance_id'], 'python3', '-c',
                  STOP_BRIDGE, token.group(1)])
            finish('a', 'first-vm-execution-cancelled', code=125, diagnostic='policy_unavailable')
            execute('first-vm-workload-reaped', 'a', 'test', '!', '-e', f'/proc/{pids["a"]}')
            assert ready_pid('b') == pids['b']
            execute('release-second-vm-execution', 'b', 'touch', 'egress-release')
            assert f'Existing and fresh HTTPS tunnels to {hosts["b"]} still work' in finish(
                'b', 'second-vm-egress-survived')
            assert read_port(ports['a']) == 'a'
            assert read_port(ports['b']) == 'b'
        finally:
            for execution in active.values():
                if execution.poll() is None:
                    execution.terminate()
                    try:
                        execution.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        execution.kill()
                        execution.wait(timeout=5)

    call('environment-macos', ['sw_vers'])
    call('environment-provider', ['container', '--version'])
    call('environment-memory', ['/usr/sbin/sysctl', '-n', 'hw.memsize'])
    call('host-pressure-before', ['/usr/bin/memory_pressure', '-Q'])
    try:
        for name in registries:
            owned[name] = json.loads(workspace('create-' + name, name, 'create', '--os', 'linux',
                                                '--network', 'offline', '--memory', '256M'))
        workspace('start-first', 'a', 'setup')
        workspace('default-remains-single', 'b', 'setup',
                  code=125, diagnostic='single-VM admission')
        workspace('start-second-with-budget', 'b', 'setup', '--vm-memory-budget', '1G')
        workspace('refuse-over-budget', 'c', 'setup', '--vm-memory-budget', '1G',
                  code=125, diagnostic='require 1536 MiB, budget is 1024 MiB')
        assert json.loads(workspace('check-rejected-vm', 'c', 'show'))['status'] == 'created'
        call('host-pressure-two-vms', ['/usr/bin/memory_pressure', '-Q'])

        # Reserve two distinct host ports until both have been chosen.
        with socket.socket() as a, socket.socket() as b:
            for listener in (a, b):
                listener.bind(('127.0.0.1', 0))
            ports = {'a': a.getsockname()[1], 'b': b.getsockname()[1]}

        for name in ('a', 'b'):
            observed = json.loads(workspace('show-' + name, name, 'show'))
            assert observed['status'] == 'ready' and observed['capabilities']['offline_network']
            assert observed['observed']['status']['networks'] == []
            execute('network-' + name, name, 'python3', '-c', NETWORK_PROBE)
            execute('write-' + name, name, 'python3', '-c',
                    'from pathlib import Path; import sys; Path("index.html").write_text(sys.argv[1])',
                    name)
            service('start-' + name, name, 'start', '--', 'python3', '-m', 'http.server',
                    '8080', '--bind', '127.0.0.1')
            service('publish-' + name, name, 'publish', '--name', 'http',
                    '--host-port', str(ports[name]), '--target-port', '8080')

        assert read_port(ports['a']) == 'a'
        assert read_port(ports['b']) == 'b'

        if args.policy_egress:
            check_policy_egress(ports)

        # Remove the offline readiness marker from this disposable VM only.
        provider_exec = ['container', 'exec', owned['b']['instance_id']]
        call('invalidate-offline-marker', [*provider_exec, 'mv', '/opt/world/offline',
                                           '/opt/world/offline.test'])
        try:
            observed = json.loads(workspace('show-policy-unavailable', 'b', 'show'))
            assert observed['status'] == 'policy_unavailable'
            execute('exec-rejects-unverified-policy', 'b', 'true', code=125,
                    diagnostic='policy_unavailable')
            service('restart-rejects-unverified-policy', 'b', 'restart', code=125,
                    diagnostic='policy_unavailable')
        finally:
            call('restore-offline-marker', [*provider_exec, 'mv', '/opt/world/offline.test',
                                            '/opt/world/offline'])

        workspace('stop-first', 'a', 'teardown')
        assert read_port(ports['b']) == 'b'
        execute('second-vm-still-ready', 'b', 'cat', 'index.html')
        workspace('stop-second', 'b', 'teardown')
        for name in registries:
            workspace('delete-' + name, name, 'delete', '--discard-runtime-data')
            del owned[name]
        call('host-pressure-after', ['/usr/bin/memory_pressure', '-Q'])
    finally:
        for name, vm in owned.items():
            subprocess.run([world, 'workspace', '--state-dir', str(registries[name]), 'teardown',
                            name], capture_output=True, timeout=30)
            for argv in (['stop', '--time', '1'], ['delete']):
                subprocess.run(['container', *argv, vm['instance_id']], capture_output=True, timeout=30)
    print('World multi-VM offline smoke PASS', flush=True)


if __name__ == '__main__':
    main()
