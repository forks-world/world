"""Real VM regression for world exec's execution-scoped egress policy."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

from world_vm_egress_probe import GUEST_DIRECT

WORKLOAD = r"""
import base64, concurrent.futures, http.client, os, socket, ssl, threading, time
from urllib.parse import urlsplit

assert [name for _, name in socket.if_nameindex()] == ['lo']
assert os.environ['HTTPS_PROXY'] == os.environ['https_proxy']
proxy = urlsplit(os.environ['HTTPS_PROXY'])
assert proxy.hostname == '127.0.0.1'
auth = base64.b64encode(f'{proxy.username}:{proxy.password}'.encode()).decode()
headers = {'Proxy-Authorization': 'Basic ' + auth}
ready = threading.Barrier(4)

def fetch(index):
    if index >= 0:
        ready.wait(timeout=5)
    connection = http.client.HTTPSConnection(proxy.hostname, proxy.port, timeout=8,
                                             context=ssl.create_default_context())
    try:
        connection.set_tunnel('example.com', 443, headers)
        if index < 0:
            connection.connect()
            time.sleep(2.5)  # Keep a real tunnel open across the route recheck.
        connection.request('GET', '/')
        response = connection.getresponse()
        assert response.status == 200 and b'Example Domain' in response.read(64 * 1024)
        return response.status
    finally:
        connection.close()

with socket.create_connection((proxy.hostname, proxy.port), timeout=3):
    # An idle stream must not prevent the four independent TLS handshakes.
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        assert list(pool.map(fetch, range(4))) == [200] * 4

assert fetch(-1) == 200

for target in ('example.org:443', 'example.com:80', '127.0.0.1:443', '[fd00::1]:443'):
    connection = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=5)
    try:
        connection.request('CONNECT', target, headers=headers)
        assert connection.getresponse().status == 403, target
    finally:
        connection.close()
print('parallel HTTPS and policy denials passed')
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--world', type=Path, default=Path('target/debug/world'))
    world = str(parser.parse_args().world.resolve(strict=True))
    evidence = Path(tempfile.mkdtemp(prefix='world-egress-exec-'))
    state = evidence / 'state'
    allowed, blocked = evidence / 'allowed.json', evidence / 'blocked.json'
    for path, host in ((allowed, 'example.com'), (blocked, '127.0.0.1')):
        path.write_text(json.dumps({'network_id': 'exec-acceptance',
                                    'allow': [{'host': host, 'port': 443}]}))
    print(f'Evidence: {evidence}', flush=True)
    results = []

    def record(label, outcome, code=0, diagnostic=None):
        results.append(dict(label=label, code=outcome.returncode,
                            stdout=outcome.stdout, stderr=outcome.stderr))
        (evidence / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(f'{label}: {outcome.returncode}', flush=True)
        assert outcome.returncode == code, outcome.stderr
        if diagnostic:
            assert diagnostic in outcome.stderr, outcome.stderr
        return outcome.stdout

    def run(label, args, **expected):
        return record(label, subprocess.run(args, text=True, capture_output=True, timeout=90),
                      **expected)

    def workspace(label, action, *flags, **expected):
        return run(label, [world, 'workspace', '--state-dir', str(state), action, 'test', *flags],
                   **expected)

    def invocation(*argv, policy=None):
        options = ['--egress-policy', str(policy)] if policy else []
        return [world, 'exec', 'test', '--state-dir', str(state), *options, '--', *argv]

    instance = None
    try:
        instance = json.loads(workspace('create-offline', 'create', '--os', 'linux',
                                       '--network', 'offline', '--memory', '256M'))['instance_id']
        workspace('start', 'setup')
        run('reject-private-policy-before-spawn',
            invocation('touch', '/workspace/invalid-policy-ran', policy=blocked),
            code=125, diagnostic='policy_unavailable')
        run('check-no-execution-on-rejection', invocation('test', '!', '-e', 'invalid-policy-ran'))
        v6_default = subprocess.run(['/sbin/route', '-n', 'get', '-inet6', 'default'],
                                    text=True, capture_output=True, timeout=5)
        if not v6_default.stdout.strip() and 'not in table' in v6_default.stderr:
            v6_policy = evidence / 'ipv6-only.json'
            v6_policy.write_text(json.dumps({
                'network_id': 'v6-no-default',
                'allow': [{'host': '2606:4700:4700::1111', 'port': 443}],
            }))
            run('reject-ipv6-only-without-default', invocation('true', policy=v6_policy),
                code=125, diagnostic='no usable default route')
        run('exec-parallel-https', invocation('python3', '-c', WORKLOAD, policy=allowed))
        run('exec-client-uses-standard-proxy-env', invocation('python3', '-c',
            'import urllib.request; assert urllib.request.urlopen("https://example.com/", timeout=8).status == 200',
            policy=allowed))
        run('egress-control-removed-after-exec',
            ['container', 'exec', instance, 'python3', '-c',
             'from pathlib import Path; assert not list(Path("/run/world-egress").glob("*.sock"))'])
        run('exec-no-proxy-inheritance', invocation('python3', '-c',
            'import os; assert not any(name.lower().endswith("_proxy") for name in os.environ)'))
        run('exec-no-direct-egress', invocation('python3', '-c', GUEST_DIRECT))

        # Kill the bridge in this disposable VM, then verify normal exec cleanup.
        with subprocess.Popen(
            invocation('python3', '-c', 'import os, time; from pathlib import Path; '
                       'Path("live").write_text(str(os.getpid())); time.sleep(90)', policy=allowed),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) as execution:
            try:
                for _ in range(40):
                    ready = subprocess.run(['container', 'exec', instance, 'test', '-f',
                                            '/workspace/live'], capture_output=True, timeout=5)
                    if ready.returncode == 0:
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError('execution did not start')
                announced = execution.stderr.readline()
                token = re.search(r'execution ([0-9a-f]{32})', announced).group(1)
                run('stop-owned-egress-bridge',
                    ['container', 'exec', instance, 'python3', '-c',
                     'import os, signal, sys; from pathlib import Path\n'
                     'matches = []\n'
                     'for path in Path("/proc").glob("[0-9]*/cmdline"):\n'
                     '    try: args = path.read_bytes().split(bytes(1))\n'
                     '    except FileNotFoundError: continue\n'
                     '    if args[-3:-1] == [b"egress-bridge", sys.argv[1].encode()]:\n'
                     '        matches.append(int(path.parent.name))\n'
                     'assert len(matches) == 1, matches\n'
                     'os.kill(matches[0], signal.SIGTERM)', token])
                stdout, stderr = execution.communicate(timeout=20)
                record('cancel-exec-on-egress-loss',
                       subprocess.CompletedProcess(execution.args, execution.returncode, stdout, announced + stderr),
                       code=125, diagnostic='policy_unavailable')
            finally:
                if execution.poll() is None:
                    execution.kill()
                    execution.wait(timeout=5)

        run('workload-reaped-after-egress-loss', invocation('python3', '-c',
            'from pathlib import Path; pid = int(Path("live").read_text()); '
            'assert not (Path("/proc") / str(pid)).exists()'))
        run('stop-provider-out-of-band', ['container', 'stop', '--time', '1', instance])
        run('restart-provider-out-of-band', ['container', 'start', instance])
        run('reject-previous-boot', invocation('true', policy=allowed), code=125,
            diagnostic='VM restarted outside World')
        workspace('verify-new-boot', 'setup')
        run('exec-after-new-boot', invocation('python3', '-c', WORKLOAD, policy=allowed))
        workspace('teardown', 'teardown')
        workspace('delete', 'delete', '--discard-runtime-data')
        instance = None
    finally:
        if instance is not None:
            for argv in (['stop', '--time', '1'], ['delete']):
                subprocess.run(['container', *argv, instance], capture_output=True, timeout=30)
    print('World execution egress smoke PASS', flush=True)


if __name__ == '__main__':
    main()
