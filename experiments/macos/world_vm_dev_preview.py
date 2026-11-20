"""Opt-in development preview on a real Apple container VM.

Requires a built World CLI, an already running container system service, and
public GitHub, PyPI, npm, and Alpine package access from the host. The guest installs from a
Linux wheel bundle. All VM state belongs to this run.
"""

import argparse
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import urlopen

from preview_model import NEW, OLD, PORT, TEMPLATE as GUEST_TEMPLATE

FLASK_REF = '3.1.2'
FLASK_COMMIT = '2c1b30d0503cfb064f1cb252e6614a06915a362a'
OPENCODE_VERSION = '1.18.35'
OPENCODE_SHA512 = (
    'f3uFZXwXPYHx8frgDzBTFFQmzVjm50Yg5gOSScPoXTgURZRfeU2zgV5iCvBhUSjlA0wvpZtBswUqwN9Kd4n8bw=='
)
TEMPLATE = Path(GUEST_TEMPLATE).relative_to('/workspace')
REQUIREMENTS = (f'Flask=={FLASK_REF}', 'pytest==8.4.2')
VENV = '/home/world/preview-venv'
AGENT = '/home/world/preview-opencode'
ALPINE_MAIN = 'https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64'
INSTALL_AGENT = """
import base64, hashlib, os, pathlib, shutil, sys, tarfile
path, integrity, destination = sys.argv[1:]
with open(path, 'rb') as archive:
    digest = hashlib.file_digest(archive, 'sha512')
    assert base64.b64encode(digest.digest()).decode() == integrity, 'OpenCode digest mismatch'
    archive.seek(0)
    with tarfile.open(fileobj=archive, mode='r|gz') as tar:
        for member in tar:
            if member.name not in ('package/bin/opencode', 'package/bin/opencode.exe'):
                continue
            assert member.isfile(), 'OpenCode archive entry is not a regular file'
            with tar.extractfile(member) as source, pathlib.Path(destination).open('xb') as target:
                shutil.copyfileobj(source, target)
            os.chmod(destination, 0o700)
            break
        else:
            raise RuntimeError('OpenCode executable was not found in the verified archive')
"""


def fetch(url, destination):
    with urlopen(url, timeout=30) as reply, destination.open('wb') as output:
        shutil.copyfileobj(reply, output)


def alpine_runtime(directory):
    # Choose compatible versions from the Alpine 3.22 aarch64 index.
    # The guest's apk verifies package signatures before installing them.
    with urlopen(f'{ALPINE_MAIN}/APKINDEX.tar.gz', timeout=30) as response:
        index = io.BytesIO(response.read())
    wanted = {'libgcc', 'libstdc++'}
    files = {}
    with tarfile.open(fileobj=index, mode='r:gz') as archive:
        listings = archive.extractfile('APKINDEX').read().decode()
    for listing in listings.split('\n\n'):
        props = dict(line.split(':', 1) for line in listing.splitlines() if ':' in line)
        if props.get('P') in wanted:
            files[props['P']] = f"{props['P']}-{props['V']}.apk"
    if files.keys() != wanted:
        raise RuntimeError('Alpine OpenCode runtime packages missing from the index')
    for name in files.values():
        fetch(f'{ALPINE_MAIN}/{name}', directory / name)
    return sorted(files.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--world', type=Path, default=Path('target/debug/world'))
    parser.add_argument('--memory', default='1G')
    args = parser.parse_args()
    world = str(args.world.resolve(strict=True))
    root = Path(tempfile.mkdtemp(prefix='world-dev-preview-'))
    print(f'Evidence: {root}', flush=True)

    def call(label, command, timeout=180):
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        (root / f'{label}.stdout').write_text(result.stdout)
        (root / f'{label}.stderr').write_text(result.stderr)
        print(f'{label}: rc={result.returncode}', flush=True)
        result.check_returncode()
        return result.stdout

    def workspace(label, action, *args):
        return call(label, [world, 'workspace', '--state-dir', str(root / 'state'),
                            action, 'preview', *args])

    def execute(label, *args, timeout=180):
        return call(label, [world, 'exec', 'preview', '--state-dir', str(root / 'state'),
                            '--timeout', f'{timeout}s', '--', *args], timeout=timeout + 30)

    def service(label, action, *args):
        return call(label, [world, 'service', '--state-dir', str(root / 'state'),
                            action, 'preview', *args])

    def assert_http(port, content):
        for _ in range(30):
            try:
                with urlopen(f'http://127.0.0.1:{port}/', timeout=2) as response:
                    html = response.read().decode()
            except OSError:
                time.sleep(0.1)
                continue
            assert content in html
            (root / 'host-response.html').write_text(html)
            return
        raise RuntimeError('published Flaskr endpoint did not respond')

    call('host-version', ['sw_vers'])
    call('provider-version', ['container', '--version'])
    call('provider-status', ['container', 'system', 'status'])
    checkout = root / 'upstream'
    call('clone-flask', ['git', 'clone', '--depth', '1', '--branch', FLASK_REF,
                        'https://github.com/pallets/flask.git', str(checkout)])
    revision = call('flask-revision', ['git', '-C', str(checkout), 'rev-parse', 'HEAD']).strip()
    assert revision == FLASK_COMMIT, revision
    source = root / 'source'
    shutil.copytree(checkout / 'examples' / 'tutorial', source)
    fixture = source / '.world-preview'
    fixture.mkdir()
    shutil.copyfile(Path(__file__).with_name('preview_model.py'), fixture / 'model.py')
    call('download-linux-wheels', [sys.executable, '-m', 'pip', '--disable-pip-version-check',
                                  'download', '--only-binary=:all:', '--platform',
                                  'musllinux_1_2_aarch64', '--implementation', 'cp',
                                  '--python-version', '3.13', '--abi', 'cp313', '-d',
                                  str(fixture / 'wheels'), *REQUIREMENTS, 'flit_core<4'])
    package = 'opencode-linux-arm64-musl'
    url = f'https://registry.npmjs.org/{package}/-/{package}-{OPENCODE_VERSION}.tgz'
    fetch(url, fixture / 'opencode.tgz')
    apk_files = alpine_runtime(fixture)
    config = {
        'model': 'preview/fixture',
        'enabled_providers': ['preview'],
        'shell': '/bin/sh',
        'snapshot': False,
        'lsp': False,
        'formatter': False,
        'provider': {'preview': {
            'name': 'World Preview',
            'npm': '@ai-sdk/openai-compatible',
            'options': {'baseURL': f'http://127.0.0.1:{PORT}/v1', 'apiKey': 'fixture'},
            'models': {'fixture': {'name': 'Fixture', 'tool_call': True,
                                   'limit': {'context': 32768, 'output': 4096}}},
        }},
        'permission': {'*': 'deny', 'read': 'allow', 'edit': 'allow',
                       'bash': {'*': 'deny', 'pwd': 'allow',
                                f'{VENV}/bin/python -m pytest -q': 'allow'}},
    }
    (source / 'opencode.json').write_text(json.dumps(config))
    assert OLD in (source / TEMPLATE).read_text()

    vm = json.loads(workspace('create', 'create', '--os', 'linux', '--memory', args.memory))
    try:
        workspace('setup', 'setup')
        workspace('import', 'import', '--source', str(source))
        # Trusted image bootstrap. The agent and all project commands remain UID 1000.
        call('install-agent-libraries', ['container', 'exec', vm['instance_id'], 'apk', 'add',
                                         '--no-network',
                                         *(f'/workspace/.world-preview/{name}' for name in apk_files)])
        execute('guest-python-version', 'python3', '--version')
        assert execute('guest-agent-identity', 'id', '-u').strip() == '1000'
        execute('venv', 'python3', '-m', 'venv', VENV)
        execute('install', f'{VENV}/bin/python', '-m', 'pip', 'install',
                '--no-index', '--find-links', '.world-preview/wheels', *REQUIREMENTS, '.')
        execute('dependencies', f'{VENV}/bin/python', '-m', 'pip', 'freeze')
        execute('initial-tests', f'{VENV}/bin/python', '-m', 'pytest', '-q')
        execute('install-agent', 'python3', '-c', INSTALL_AGENT, '.world-preview/opencode.tgz',
                OPENCODE_SHA512, AGENT)
        execute('clear-install-bundle', 'python3', '-c',
                "from pathlib import Path; import shutil; "
                "p=Path('.world-preview'); (p/'opencode.tgz').unlink(); "
                "shutil.rmtree(p/'wheels'); [item.unlink() for item in p.glob('*.apk')]")
        assert execute('agent-version', AGENT, '--version').strip() == OPENCODE_VERSION
        service('start-model', 'start', 'model', '--', 'python3', '-u', '.world-preview/model.py')
        try:
            execute('model-ready', 'python3', '-c',
                    f'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:{PORT}/health", timeout=2).status == 200')
            agent_output = execute('agent', 'env', 'OPENCODE_DISABLE_AUTOUPDATE=1', 'OPENCODE_DISABLE_MODELS_FETCH=1',
                    AGENT, 'run', '--pure', '--print-logs', '--log-level', 'INFO',
                    '--model', 'preview/fixture', '--dir', '/workspace', '--format', 'json',
                    'Update the Flaskr heading to Flaskr World Preview and run its tests.', timeout=120)
            assert 'The Flaskr heading was updated and the guest tests passed.' in agent_output
        finally:
            service('model-logs', 'logs', 'model')
            service('model-errors', 'logs', 'model', '--stream', 'stderr')
            service('stop-model', 'stop', 'model')
        execute('verify-agent-edit', 'python3', '-c',
                f'from pathlib import Path; assert {NEW!r} in Path({str(TEMPLATE)!r}).read_text()')
        assert OLD in (source / TEMPLATE).read_text()
        execute('init-flask-db', f'{VENV}/bin/python', '-m', 'flask', '--app', 'flaskr', 'init-db')
        service('start-flaskr', 'start', 'flaskr', '--', f'{VENV}/bin/python', '-m', 'flask',
                '--app', 'flaskr', 'run', '--host', '127.0.0.1', '--port', '8080')
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            host_port = reservation.getsockname()[1]
        service('publish-flaskr', 'publish', 'flaskr', '--name', 'browser',
                '--host-port', str(host_port), '--target-port', '8080')
        assert_http(host_port, NEW)
        service('stop-flaskr', 'stop', 'flaskr')
        exported = root / 'exported'
        workspace('export', 'export', '--destination', str(exported))
        assert NEW in (exported / TEMPLATE).read_text()
        assert OLD in (source / TEMPLATE).read_text()
        print('Development preview PASS', flush=True)
    finally:
        workspace('teardown', 'teardown')
        workspace('delete', 'delete', '--discard-runtime-data')


if __name__ == '__main__':
    main()
