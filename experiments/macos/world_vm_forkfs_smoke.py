"""Exercise forkfs-backed setup, workload admission and teardown on Apple Silicon."""

import argparse
import errno
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time

from forkfs_guest_mount_probe import RpcError, rpc, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('forkfsd', type=Path)
    parser.add_argument('--forkfsd-fault', type=Path, help='test online discard recovery with crash injection')
    parser.add_argument('--world', type=Path, default=Path('target/debug/world'))
    args = parser.parse_args()
    forkfsd = str(args.forkfsd.resolve(strict=True))
    world = str(args.world.resolve(strict=True))
    fault = str(args.forkfsd_fault.resolve(strict=True)) if args.forkfsd_fault else None
    evidence = Path(tempfile.mkdtemp(prefix='world-forkfs-smoke-', dir='/tmp'))
    state, endpoint = evidence / 'state', evidence / 'rpc.sock'
    store, wrong_store = evidence / 'store', evidence / 'other-store'
    name = 'test'
    print(f'Evidence: {evidence}', flush=True)
    results = []

    def record(label, **data):
        results.append(dict(label=label, **data))
        (evidence / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(label, flush=True)

    def call(label, cmd, *, exit_code=0, diagnostic=None):
        outcome = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        record(label, code=outcome.returncode, stdout=outcome.stdout, stderr=outcome.stderr)
        assert outcome.returncode == exit_code, outcome.stderr
        if diagnostic:
            assert diagnostic in outcome.stderr, outcome.stderr
        return outcome.stdout

    def workspace(label, action, *flags, **expected):
        return call(label, [world, 'workspace', '--state-dir', str(state), action, name, *flags],
                    **expected)

    def service(label, action, *flags, **expected):
        return call(label, [world, 'service', '--state-dir', str(state), action, name, 'worker',
                            *flags], **expected)

    def execute(label, *argv, **expected):
        return call(label, [world, 'exec', name, '--state-dir', str(state), '--', *argv], **expected)

    daemon = None
    vm = None

    def start_daemon(database, *, crash=None):
        nonlocal daemon
        env = dict(os.environ)
        if crash:
            env['FORKFS_TEST_CRASH'] = crash
        with (evidence / f'{database.name}.stderr').open('ab') as errors:
            daemon = subprocess.Popen(
                [fault if crash else forkfsd, 'serve', str(database), '--socket', str(endpoint), '--rpc'],
                stdout=subprocess.PIPE, stderr=errors, env=env,
            )
        assert select.select([daemon.stdout], [], [], 5)[0], 'forkfsd startup timeout'
        assert json.loads(daemon.stdout.readline())['state'] == 'leveldb'

    def stop_daemon():
        nonlocal daemon
        if daemon is not None:
            if daemon.poll() is None:
                daemon.terminate()
            daemon.wait(timeout=10)
            daemon.stdout.close()
            daemon = None
            endpoint.unlink(missing_ok=True)  # Fault injection can leave our private socket behind.

    def seed():
        rpc(endpoint, 'fs-init')
        rpc(endpoint, 'fs-write', '/baseline.txt', b'forkfs baseline')
        rpc(endpoint, 'fs-snapshot', 'base')
        rpc(endpoint, 'fs-fork', 'base', 'work')
        session = json.loads(rpc(endpoint, 'session-open', '5000'))['session']
        try:
            return json.loads(rpc(endpoint, 'inode-root', '--world', 'work', '--session', session))[
                'repository'
            ]
        finally:
            rpc(endpoint, 'session-close', session)

    try:
        record('environment', macos=run('sw_vers').decode(),
               provider=run('container', '--version').decode())
        run(forkfsd, 'init', str(store))
        start_daemon(store)
        repository = seed()
        stop_daemon()
        run(forkfsd, 'init', str(wrong_store))
        start_daemon(wrong_store)
        assert seed() != repository

        vm = json.loads(workspace(
            'create', 'create', '--os', 'linux', '--forkfs-socket', str(endpoint),
            '--forkfs-repository', repository, '--forkfs-branch', 'work',
        ))
        workspace('reject-wrong-repository', 'setup', exit_code=125,
                  diagnostic='forkfs repository identity mismatch')
        execute('reject-before-mount', 'true', exit_code=125, diagnostic='workspace is not ready')
        workspace('reject-diff-on-wrong-repository', 'diff', 'base', 'base',
                  exit_code=125, diagnostic='forkfs repository identity mismatch')
        rpc(endpoint, 'fs-write', '/wrong-store', b'lease released', '--world', 'work')
        stop_daemon()
        start_daemon(store)

        workspace('setup', 'setup')
        workspace('setup-idempotent', 'setup')
        ready = json.loads(workspace('show-ready', 'show'))
        assert ready['status'] == 'ready' and ready['capabilities']['worldfs']
        time.sleep(17)  # Longer than the lease, with no guest I/O.
        try:
            rpc(endpoint, 'fs-write', '/foreign', b'blocked', '--world', 'work')
        except RpcError as error:
            assert error.code == errno.EBUSY + 1, error
            record('idle-lease-excludes-foreign-write')
        else:
            raise AssertionError('exclusive lease expired while mounted')
        assert execute('read-baseline', 'cat', 'baseline.txt') == 'forkfs baseline'
        workspace('reject-import', 'import', '--source', str(evidence), exit_code=125,
                  diagnostic='seed the forkfs branch')
        worker = json.loads(service(
            'service-start', 'start', '--', 'python3', '-c',
            'import os,time; from pathlib import Path; assert os.getuid()==1000; '
            'Path("baseline.txt").write_text("updated in service"); '
            'Path("retained.txt").write_text("from service"); time.sleep(120)',
        ))
        assert worker['state'] == 'running'
        execute('service-and-exec-share-storage', 'python3', '-c',
                'import time; from pathlib import Path\n'
                'p=Path("retained.txt")\n'
                'for _ in range(50):\n'
                '    if p.exists() and p.read_text()=="from service": break\n'
                '    time.sleep(.1)\n'
                'else: raise AssertionError("service write not visible")')
        workspace('reject-checkpoint-with-active-service', 'checkpoint', 'saved',
                  exit_code=125, diagnostic='checkpoint requires a stopped workspace')
        assert 'saved' not in rpc(endpoint, 'fs-revisions').decode().splitlines()
        if fault:
            plan = json.loads(workspace('preview-discard-mounted', 'discard'))
            workspace('reject-discard-mounted', 'discard', '--expect-token', plan['token'],
                      exit_code=125, diagnostic='discard requires a stopped workspace')
        workspace('fork-baseline', 'fork', 'base', 'sibling')
        assert rpc(endpoint, 'fs-cat', '/baseline.txt', '--world', 'sibling') == b'forkfs baseline'
        assert b'retained.txt' not in rpc(endpoint, 'fs-ls', '/', '--world', 'sibling').splitlines()
        workspace('drain-unmount-and-stop', 'teardown')

        external = json.loads(rpc(endpoint, 'session-open', '15000'))['session']
        try:
            rpc(endpoint, 'fs-open', '/baseline.txt', 'rw', '--world', 'work', '--session', external)
            workspace('reject-checkpoint-with-external-handle', 'checkpoint', 'saved',
                      exit_code=125, diagnostic='checkpoint requires an exclusive forkfs lease')
        finally:
            rpc(endpoint, 'session-close', external)
        checkpoint = json.loads(workspace('checkpoint-stopped-workspace', 'checkpoint', 'saved'))
        workspace('reject-duplicate-checkpoint', 'checkpoint', 'saved',
                  exit_code=125, diagnostic='revision name already exists')
        changes, cursor = [], ''
        while True:
            page = json.loads(workspace('diff-page', 'diff', 'base', 'saved',
                                        '--limit', '1', '--after-path', cursor))
            assert page['after_revision_id'] == checkpoint['revision_id']
            assert len(page['changes']) <= 1
            changes.extend(page['changes'])
            if page['eof']:
                assert not page['next_after']
                break
            assert page['next_after'] > cursor
            cursor = page['next_after']
        assert {change['path']: change['change'] for change in changes if change['path'] != '/'} == {
            '/baseline.txt': 'modified', '/retained.txt': 'added',
        }
        assert next(change for change in changes if change['path'] == '/baseline.txt')['content_changed']
        workspace('fork-checkpoint', 'fork', 'saved', 'saved-copy')
        assert rpc(endpoint, 'fs-cat', '/baseline.txt', '--world', 'saved-copy') == b'updated in service'
        assert rpc(endpoint, 'fs-cat', '/retained.txt', '--world', 'saved-copy') == b'from service'
        workspace('reject-duplicate-branch', 'fork', 'base', 'saved-copy',
                  exit_code=125, diagnostic='World already exists')
        assert rpc(endpoint, 'fs-cat', '/retained.txt', '--world', 'saved-copy') == b'from service'
        assert rpc(endpoint, 'fs-cat', '/retained.txt', '--world', 'work') == b'from service'
        rpc(endpoint, 'fs-write', '/after-unmount', b'lease released', '--world', 'work')
        record('foreign-write-after-unmount')
        call('remove-owned-provider-instance', ['container', 'delete', vm['instance_id']])
        workspace('rebuild-runtime', 'setup', '--recreate-missing')
        after = json.loads(workspace('show-new-generation', 'show'))
        assert after['lifecycle']['generation'] > ready['lifecycle']['generation']
        assert after['status'] == 'ready'
        assert execute('read-retained-branch', 'cat', 'retained.txt') == 'from service'
        export = evidence / 'export'
        workspace('export-retained-branch', 'export', '--destination', str(export))
        assert (export / 'retained.txt').read_text() == 'from service'

        stop_daemon()
        # The guest RPC must fail even before the next scheduled keepalive.
        after_loss = json.loads(workspace('show-storage-unavailable', 'show'))
        assert after_loss['status'] == 'storage_unavailable'
        assert not after_loss['capabilities']['worldfs']
        execute('reject-exec-after-loss', 'true', exit_code=125, diagnostic='storage_unavailable')
        service('reject-service-after-loss', 'start', '--', 'true', exit_code=125,
                diagnostic='storage_unavailable')
        workspace('reject-export-after-loss', 'export', '--destination', str(evidence / 'failed-export'),
                  exit_code=125, diagnostic='storage_unavailable')
        workspace('teardown-after-loss', 'teardown')
        start_daemon(store)
        workspace('remount-after-daemon-recovery', 'setup')
        assert execute('read-after-recovery', 'cat', 'retained.txt') == 'from service'
        workspace('final-teardown', 'teardown')
        workspace('remove-workspace', 'delete', '--discard-runtime-data')
        vm = None
        assert rpc(endpoint, 'fs-cat', '/retained.txt', '--world', 'work') == b'from service'
        record('deleting-runtime-preserves-forkfs-branch')

        if fault:
            name = 'discard-test'
            workspace('bind-disposable-branch', 'create', '--os', 'linux',
                      '--forkfs-socket', str(endpoint), '--forkfs-repository', repository,
                      '--forkfs-branch', 'saved-copy')
            plan = json.loads(workspace('preview-discard', 'discard'))
            rpc(endpoint, 'fs-write', '/file', b'uncheckpointed', '--world', 'saved-copy')
            workspace('reject-stale-discard', 'discard', '--expect-token', plan['token'],
                      exit_code=125, diagnostic='discard plan is stale')
            plan = json.loads(workspace('preview-discard-again', 'discard'))
            token = plan['token']
            session = json.loads(rpc(endpoint, 'session-open', '15000'))['session']
            try:
                rpc(endpoint, 'fs-open', '/file', 'rw', '--world', 'saved-copy', '--session', session)
                workspace('reject-discard-with-external-handle', 'discard', '--expect-token', token,
                          exit_code=125, diagnostic='World has open file handles')
                assert json.loads(workspace('show-discard-rejected', 'show'))['status'] == 'created'
            finally:
                rpc(endpoint, 'session-close', session)

            for stage in ('leveldb_before_write', 'leveldb_after_write'):
                stop_daemon()
                start_daemon(store, crash=stage)
                workspace(f'discard-crash-{stage}', 'discard', '--expect-token', token,
                          exit_code=125, diagnostic='discard outcome unknown')
                assert daemon.wait(timeout=5) == 86
                stop_daemon()
                start_daemon(store)
                assert json.loads(workspace('show-discard-in-progress', 'show'))['status'] == 'discarding'
                workspace('reject-setup-during-discard', 'setup', exit_code=125,
                          diagnostic='workspace discard is pending or complete')
                worlds = rpc(endpoint, 'fs-worlds').splitlines()
                assert (b'saved-copy' in worlds) == (stage == 'leveldb_before_write')
                assert rpc(endpoint, 'fs-cat', '/retained.txt', '--revision', 'saved') == b'from service'
            result = json.loads(workspace('reconcile-discard', 'discard', '--expect-token', token))
            assert result['state'] == 'discarded'
            assert json.loads(workspace('show-discarded', 'show'))['status'] == 'discarded'
            workspace('recreate-branch-name', 'fork', 'saved', 'saved-copy')
            workspace('retry-discard-remains-idempotent', 'discard', '--expect-token', token)
            workspace('reject-setup-after-name-reuse', 'setup', exit_code=125,
                      diagnostic='workspace discard is pending or complete')
            assert rpc(endpoint, 'fs-cat', '/retained.txt', '--world', 'saved-copy') == b'from service'
            workspace('delete-discarded-registration', 'delete')
            workspace('bind-recreated-branch', 'create', '--os', 'linux',
                      '--forkfs-socket', str(endpoint), '--forkfs-repository', repository,
                      '--forkfs-branch', 'saved-copy')
            plan = json.loads(workspace('preview-recreated-branch', 'discard'))
            result = json.loads(workspace('discard-confirmed', 'discard', '--expect-token', plan['token']))
            assert result['state'] == 'discarded' and result['manifest_id'] == plan['manifest_id']
            workspace('delete-confirmed-discard-registration', 'delete')
            assert rpc(endpoint, 'fs-cat', '/retained.txt', '--world', 'work') == b'from service'
            record('discard-preserves-named-revision-and-other-branch')
    finally:
        try:
            if vm is not None:
                for command in (('stop', '--time', '1'), ('delete',)):
                    run('container', *command, vm['instance_id'], check=False)
        finally:
            stop_daemon()
    print('World VM forkfs smoke PASS', flush=True)


if __name__ == '__main__':
    main()
