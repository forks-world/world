"""Opt-in real VM integration test. Requires `container system start`.

Build first with cargo build --workspace, then run this script from the repo.
Creates exactly one 256 MiB VM, keeps evidence in a temporary directory,
removes only its own VM, and leaves the caller's provider service running.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    root = Path(tempfile.mkdtemp(prefix='world-vm-smoke-'))
    binary = str(Path('target/debug/world').resolve())
    state = root / 'state'
    evidence = []
    vm = None
    print(f'Evidence: {root}', flush=True)

    def call(label, args, expected=0, input=None, limit=180):
        start = time.monotonic()
        p = subprocess.run([binary, *args], input=input, capture_output=True,
                           text=True, timeout=limit)
        evidence.append(dict(label=label, seconds=time.monotonic()-start,
                             code=p.returncode, stdout=p.stdout, stderr=p.stderr))
        (root/'results.json').write_text(json.dumps(evidence, indent=2))
        print(f'{label}: rc={p.returncode}, {evidence[-1]["seconds"]:.3f}s', flush=True)
        assert p.returncode == expected, p.stderr + p.stdout
        return p

    def workspace(*args):
        return ['workspace', '--state-dir', str(state), *args]

    def execute(*args, duration='5m'):
        return ['exec', 'test', '--state-dir', str(state), '--timeout', duration, '--', *args]

    try:
        vm = json.loads(call('create', workspace('create','test','--os','linux','--memory','256M')).stdout)
        call('reject-native-collision', workspace('create','test','--workdir',str(root)), expected=125)
        call('reject-workdir', workspace('create','other','--os','linux','--workdir',str(root)), expected=125)
        call('refuse-before-setup', execute('uname','-s'), expected=125)
        call('setup', workspace('setup','test'))
        call('setup-idempotent', workspace('setup','test'))
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
        call('refuse-stopped', execute('true'), expected=125)
        call('restart', workspace('setup','test'))
        assert call('file-persists', execute('cat','persisted')).stdout == 'saved'
        call('import-persists', execute('python3','-c',imported_check))
        call('show', workspace('show','test'))
        print('PASS', flush=True)
    finally:
        if vm:
            subprocess.run([binary,*workspace('teardown','test')],timeout=30)
            subprocess.run(['container','delete',vm['instance_id']],check=True,timeout=30)
        (root/'results.json').write_text(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()
