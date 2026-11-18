"""Opt-in real VM integration test. Requires `container system start`.

Build first with cargo build --workspace, then run this script from the repo.
Creates at most one running 512 MiB VM, keeps evidence in a temporary directory,
removes only its own VM, and leaves the caller's provider service running.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

from vm_channel_probe import run as probe_channels


def main():
    root = Path(tempfile.mkdtemp(prefix='world-vm-smoke-'))
    binary = str(Path('target/debug/world').resolve())
    state = root / 'state'
    evidence = []
    vm = None
    print(f'Evidence: {root}', flush=True)

    def save(label, **values):
        evidence.append(dict(label=label, **values))
        (root / 'results.json').write_text(json.dumps(evidence, indent=2))

    def record(label, args, expected=0, input=None, limit=180, env=None, details=None):
        if args is None:
            save(label, **details)
            return
        start = time.monotonic()
        binary_io = isinstance(input, bytes)
        p = subprocess.run(args, input=input, capture_output=True,
                           text=not binary_io, timeout=limit, env=env)
        stdout = f'<{len(p.stdout)} bytes>' if binary_io else p.stdout
        stderr = p.stderr.decode(errors='replace') if binary_io else p.stderr
        save(label, seconds=time.monotonic() - start,
             code=p.returncode, stdout=stdout, stderr=stderr)
        print(f'{label}: rc={p.returncode}, {evidence[-1]["seconds"]:.3f}s', flush=True)
        assert p.returncode == expected, stderr + stdout
        return p

    def call(label, args, **kwargs):
        return record(label, [binary, *args], **kwargs)

    def workspace(*args):
        return ['workspace', '--state-dir', str(state), *args]

    def execute(*args, duration='5m'):
        return ['exec', 'test', '--state-dir', str(state), '--timeout', duration, '--', *args]

    record('macos-version', ['sw_vers'])
    record('provider-version', ['container', '--version'])
    record('provider-status', ['container', 'system', 'status'])

    try:
        vm = json.loads(call('create', workspace('create','test','--os','linux','--memory','512M')).stdout)
        call('reject-native-collision', workspace('create','test','--workdir',str(root)), expected=125)
        call('reject-workdir', workspace('create','other','--os','linux','--workdir',str(root)), expected=125)
        call('refuse-before-setup', execute('uname','-s'), expected=125)
        # The losing setup may see the workspace lock, or arrive after readiness.
        setup = [binary, *workspace('setup', 'test')]
        with ThreadPoolExecutor(max_workers=2) as pool:
            attempts = [pool.submit(subprocess.run, setup, capture_output=True,
                                    text=True, timeout=180) for _ in range(2)]
            results = [attempt.result() for attempt in attempts]
        for i, result in enumerate(results):
            save(f'concurrent-setup-{i}', code=result.returncode,
                 stdout=result.stdout, stderr=result.stderr)
            assert result.returncode == 0 or (
                result.returncode == 125 and 'workspace busy' in result.stderr
            ), result.stderr
        assert any(result.returncode == 0 for result in results)
        instances = json.loads(record('provider-instances', [
            'container', 'list', '--all', '--format', 'json',
        ]).stdout)
        owned = [item for item in instances if item['id'] == vm['instance_id']]
        assert len(owned) == 1
        call('setup-idempotent', workspace('setup','test'))
        status = json.loads(call('show-ready',workspace('show','test')).stdout)
        assert status['status'] == 'ready' and status['lifecycle']['generation'] == 1
        listed = json.loads(call('list', workspace('list')).stdout)
        assert len(listed) == 1 and listed[0]['id'] == 'test'
        # Provider errors must not hide registrations or claim absence.
        env = dict(os.environ, PATH='/nonexistent')
        p = call('list-without-provider', workspace('list'), env=env, limit=15)
        unknown = json.loads(p.stdout)[0]
        assert unknown['id'] == 'test' and unknown['status'] == 'unknown' and unknown['observation_error']
        before = unknown['lifecycle']
        call('setup-without-provider', workspace('setup', 'test'), env=env, expected=125)
        call('teardown-without-provider', workspace('teardown', 'test'), env=env, expected=125)
        observed = json.loads(call('provider-available-again', workspace('show', 'test')).stdout)
        assert observed['status'] == 'ready' and observed['lifecycle'] == before
        probe_channels(vm['instance_id'], record)
        call('reject-delete-running',workspace('delete','test','--discard-runtime-data'),expected=125)

        # Reject corrupt/unsafe streams before publishing any file.
        def bad_stream(label, records):
            payload = ''.join(json.dumps(r) + '\n' for r in records)
            p = subprocess.run(['container','exec','-i',vm['instance_id'],'python3','-I','/opt/world/supervisor.py','import'], input=payload, capture_output=True,text=True,timeout=20)
            assert p.returncode != 0, (label,p.stdout,p.stderr)
            call(label + '-workspace-unchanged', execute('sh','-ec','test -z "$(ls -A /workspace)"'))
        begin = {'type':'begin','protocol':1}
        bad_stream('truncated-import', [begin, {'type':'file','path':'partial','mode':420,'size':10}])
        bad_stream('path-traversal-import', [begin, {'type':'directory','path':'../escape','mode':493}])
        bad_stream('symlink-parent-import', [begin, {'type':'symlink','path':'link','target':'/tmp'}, {'type':'file','path':'link/escape','mode':420,'size':0}])
        source = root / 'source'
        source.mkdir()
        (source / 'sub').mkdir()
        data = bytes(range(256)) * 500  # Crosses multiple transfer records.
        (source / 'sub' / 'binary').write_bytes(data)
        script = source / 'check.sh'
        script.write_text('#!/bin/sh\nprintf IMPORTED\n')
        script.chmod(0o755)
        (source / 'relative-link').symlink_to('sub/binary')
        (source / 'outside-link').symlink_to('/host-only-secret-never-follow')
        fifo = source / 'fifo'
        os.mkfifo(fifo)
        call('reject-special-file-import', workspace('import','test','--source',str(source)), expected=125)
        fifo.unlink()
        call('import', workspace('import','test','--source',str(source)))
        import hashlib
        digest = hashlib.sha256(data).hexdigest()
        imported_check = "import hashlib,pathlib,os; p=pathlib.Path('/workspace'); assert hashlib.sha256((p/'sub/binary').read_bytes()).hexdigest()==" + repr(digest) + "; assert (p/'relative-link').read_bytes()==(p/'sub/binary').read_bytes(); assert os.readlink(p/'outside-link')=='/host-only-secret-never-follow'; assert (p/'sub/binary').stat().st_uid==1000"
        call('verify-imported-data', execute('python3','-c',imported_check))
        assert call('import-executable',execute('./check.sh')).stdout == 'IMPORTED'
        call('refuse-import-overwrite',workspace('import','test','--source',str(source)),expected=125)
        assert (source/'sub/binary').read_bytes() == data
        output = call('linux-nonroot-cwd', execute('sh','-ec','uname -s; id -u; pwd')).stdout
        assert output.splitlines() == ['Linux','1000','/workspace'], output
        output = call('stdin', execute('cat'), input='hello from host\n').stdout
        assert output == 'hello from host\n'
        tricky = 'spaces ; $(touch /workspace/injected) "quotes"'
        assert call('literal-argv', execute('printf','%s',tricky)).stdout == tricky
        call('no-injection', execute('test','!','-e','/workspace/injected'))
        call('exit-code', execute('sh','-c','exit 42'), expected=42)
        call('write', execute('sh','-c','printf saved > persisted'))
        call('no-host-home', execute('test','!','-e','/Users/hurricane'))
        call('protected-supervisor', execute('sh','-c','test ! -w /opt/world/supervisor.py && test ! -w /sys/fs/cgroup/cgroup.procs'))
        # A detached grandchild would write a marker if the execution cleanup leaks.
        program = "import subprocess; subprocess.Popen(['sh','-c','sleep 2; touch /workspace/leaked'],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
        call('detached-child', execute('python3','-c',program))
        time.sleep(2.3)
        call('detached-child-reaped', execute('test','!','-e','/workspace/leaked'))
        call('timeout', execute('sleep','20',duration='300ms'), expected=124)
        # Send cancellation only after the guest wrote the readiness marker.
        p = subprocess.Popen([binary, *execute('sh','-c','touch /workspace/cancel-ready; sleep 30')], stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(100):
                check = subprocess.run(['container','exec',vm['instance_id'],'test','-e','/workspace/cancel-ready'],capture_output=True,timeout=5)
                if check.returncode == 0:
                    break
                time.sleep(.1)
            else:
                raise AssertionError('cancel readiness not reached')
            p.send_signal(signal.SIGTERM)
            out, err = p.communicate(timeout=15)
            assert p.returncode == 124, (p.returncode,out,err)
            evidence.append(dict(label='cancel',code=p.returncode,stdout=out,stderr=err))
            print('cancel: rc=124',flush=True)
        finally:
            if p.poll() is None:
                p.kill(); p.wait()
        # Keep one foreground execution alive while another connects through localhost.
        server = subprocess.Popen([binary, *execute('python3','-m','http.server','8080','--bind','127.0.0.1')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            client = "import urllib.request,time; " + "\nfor _ in range(50):\n try:\n  print(urllib.request.urlopen('http://127.0.0.1:8080/persisted',timeout=1).read().decode()); break\n except OSError: time.sleep(.1)\nelse: raise RuntimeError('server not ready')"
            assert call('shared-localhost', execute('python3','-c',client)).stdout.strip() == 'saved'
            call('busy-teardown-refused', workspace('teardown','test'), expected=125)
            call('independent-timeout', execute('sleep','5',duration='200ms'), expected=124)
            assert call('server-survives-other-timeout', execute('python3','-c',client)).stdout.strip() == 'saved'
            server.send_signal(signal.SIGTERM)
            _, err = server.communicate(timeout=15)
            assert server.returncode == 124, err
        finally:
            if server.poll() is None:
                server.kill(); server.wait()
        call('still-running', execute('true'))
        call('teardown', workspace('teardown','test'))
        assert json.loads(call('show-stopped',workspace('show','test')).stdout)['status'] == 'stopped'
        call('reject-data-delete-without-flag',workspace('delete','test'),expected=125)

        call('refuse-stopped', execute('true'), expected=125)
        call('restart', workspace('setup','test'))
        assert call('file-persists', execute('cat','persisted')).stdout == 'saved'
        call('import-persists', execute('python3','-c',imported_check))
        final_status = json.loads(call('show', workspace('show','test')).stdout)
        assert final_status['lifecycle']['generation'] == 2
        # Lose the runtime after a command writes its first side effect.
        with subprocess.Popen(
            [binary, *execute('sh', '-ec', 'echo ran >> interrupted; sleep 45')],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as interrupted:
            try:
                for _ in range(50):
                    check = subprocess.run(
                        ['container', 'exec', vm['instance_id'], 'test', '-s', '/workspace/interrupted'],
                        capture_output=True, timeout=5,
                    )
                    if check.returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError('interrupted execution did not become ready')
                record('out-of-band-stop',
                       ['container', 'stop', '--time', '1', vm['instance_id']], limit=20)
                out, err = interrupted.communicate(timeout=25)
                save('interrupted-exec', code=interrupted.returncode, stdout=out, stderr=err)
                assert interrupted.returncode == 125 and 'status unknown' in err, err
            finally:
                if interrupted.poll() is None:
                    interrupted.kill()
                    interrupted.wait(timeout=5)
        stopped = json.loads(call('observe-external-stop', workspace('show', 'test')).stdout)
        assert stopped['status'] == 'stopped' and stopped['lifecycle']['phase'] == 'ready'
        call('refuse-exec-after-external-stop', execute('true'), expected=125)
        record('out-of-band-start', ['container', 'start', vm['instance_id']], limit=60)
        unverified = json.loads(call('observe-external-restart', workspace('show', 'test')).stdout)
        assert unverified['status'] == 'unverified' and unverified['lifecycle']['generation'] == 2
        call('refuse-exec-unverified-boot', execute('true'), expected=125)
        call('refuse-import-unverified-boot', workspace('import', 'test', '--source', str(source)),
             expected=125)
        call('recover-external-stop', workspace('setup', 'test'))
        recovered = json.loads(call('observe-recovered-vm', workspace('show', 'test')).stdout)
        assert recovered['status'] == 'ready' and recovered['lifecycle']['generation'] == 3
        assert call('external-stop-preserves-data', execute('cat', 'persisted')).stdout == 'saved'
        assert call('interrupted-command-not-replayed', execute('cat', 'interrupted')).stdout == 'ran\n'

        # Simulate an externally lost runtime: setup must not silently replace data.
        record('external-stop-before-delete', ['container', 'stop', '--time', '1', vm['instance_id']], limit=20)
        subprocess.run(['container','delete',vm['instance_id']],check=True,timeout=20,capture_output=True)
        assert json.loads(call('show-missing',workspace('show','test')).stdout)['status'] == 'missing'
        call('reject-implicit-recreation',workspace('setup','test'),expected=125)
        call('explicit-recreation',workspace('setup','test','--recreate-missing'))
        call('recreated-runtime-empty',execute('test','!','-e','/workspace/persisted'))
        call('stop-recreated-runtime',workspace('teardown','test'))
        # A native entry in the same registry must survive deletion of the VM.
        call('create-native',workspace('create','native','--workdir',str(root)))
        call('delete-runtime',workspace('delete','test','--discard-runtime-data'))
        remaining = json.loads(call('list-after-delete',workspace('list')).stdout)
        assert [r['id'] for r in remaining] == ['native']
        # Deleting an unprovisioned registration requires no data-discard flag.
        call('create-unprovisioned',workspace('create','fresh','--os','linux','--memory','256M'))
        assert json.loads(call('show-created',workspace('show','fresh')).stdout)['status'] == 'created'
        call('delete-unprovisioned',workspace('delete','fresh'))
        vm = None

        print('PASS', flush=True)
    finally:
        if vm:
            cleanup = subprocess.run(
                [binary, *workspace('teardown', 'test')], capture_output=True, text=True, timeout=40,
            )
            save('cleanup-teardown', code=cleanup.returncode, stderr=cleanup.stderr)
            if cleanup.returncode == 0:
                subprocess.run([binary, *workspace('delete', 'test', '--discard-runtime-data')],
                               timeout=40)
            else:
                print(f'Cleanup could not stop {vm["instance_id"]}; see {root}', flush=True)
        (root/'results.json').write_text(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()
