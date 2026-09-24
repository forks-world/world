"""Real native-process checks. macOS silo tests require configured loopback
aliases; Linux tests require unprivileged user namespaces.

cargo build --workspace && cargo build --workspace --examples
python3 -m unittest discover -s tests -v
WORLD_SILO_INTEGRATION=1 python3 -m unittest discover -s tests -v
"""
import concurrent.futures
import contextlib
import errno
import http.server
import json
import os
import pathlib
import select
import shutil
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORLD = ROOT / "target/debug/world"
PROBE = ROOT / "target/debug/examples/socket_probe"
MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
SANDBOX = MACOS or LINUX
# Seatbelt refuses denied operations (EPERM). A Linux network namespace has no
# route to host listeners: TCP is refused, while seccomp refuses Unix sockets.
DIAL_DENIED = 77 if MACOS else 78


def run(*args, **kwargs):
    # Independent of the runner's own stdin, which Linux network exec checks.
    if "stdin" not in kwargs and "input" not in kwargs:
        kwargs["stdin"] = subprocess.DEVNULL
    return subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=15, **kwargs)


@contextlib.contextmanager
def serving(args, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    process = subprocess.Popen([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
    try:
        if not select.select([process.stdout], [], [], 10)[0]:
            raise AssertionError("listener startup timed out")
        line = process.stdout.readline()
        if not line.startswith("READY "):
            process.terminate()
            raise AssertionError((line, process.communicate(timeout=5)))
        yield process, int(line.split()[1])
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


class CLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="world-runtime-")
        self.addCleanup(self.temp.cleanup)
        self.dir = pathlib.Path(self.temp.name)
        self.policy = self.dir / "policy.json"
        self.policy.write_text(json.dumps({"network_id": "test", "allow": []}))
        # Redirected socket names include the root: keep it short (sun_path is 104 bytes).
        self.short = tempfile.TemporaryDirectory(prefix=".wt-", dir=pathlib.Path.home())
        self.addCleanup(self.short.cleanup)
        self.world_tmp = self.temp_root("w")

    def temp_root(self, name):
        root = pathlib.Path(self.short.name) / name
        for sub in ["tmp", "var/tmp"]:
            (root / sub).mkdir(parents=True)
        return root

    def shim_env(self, root, **extra):
        ack = self.dir / "ack"
        ack.touch()
        return dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                    SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack),
                    WORLD_TMP=str(root), **extra)

    def network(self, *command, timeout="5s", **kwargs):
        return run(WORLD, "network", "exec", "--policy", self.policy,
                   "--workdir", self.dir, "--timeout", timeout, "--", *command, **kwargs)

    def test_invalid_policy_and_platform(self):
        self.policy.write_text('{"network_id":"test","typo":true}')
        self.assertEqual(self.network("/bin/echo", "never").returncode, 125)
        if not SANDBOX:
            self.policy.write_text('{"network_id":"test"}')
            result = self.network("/bin/echo", "never")
            self.assertEqual(result.returncode, 125)
            self.assertEqual(result.stdout, "")

    @unittest.skipUnless(sys.platform == "darwin", "Seatbelt requires macOS")
    def test_kernel_denials_and_children(self):
        for family, socktype, host, mode in [(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", "dial"),
                (socket.AF_INET6, socket.SOCK_STREAM, "::1", "dial"),
                (socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1", "udp-dial")]:
            with self.subTest(host=host, mode=mode), socket.socket(family, socktype) as listener:
                listener.bind((host, 0))
                if socktype == socket.SOCK_STREAM:
                    listener.listen()
                address = f"[{host}]:{listener.getsockname()[1]}" if ":" in host else f"{host}:{listener.getsockname()[1]}"
                self.assertEqual(run(PROBE, mode, address).returncode, 0)
                for prefix in [[], ["child"]]:
                    result = self.network(PROBE, *prefix, mode, address)
                    self.assertEqual(result.returncode, 77, result.stderr)
        with tempfile.TemporaryDirectory(dir="/tmp") as d, socket.socket(socket.AF_UNIX) as listener:
            path = str(pathlib.Path(d) / "s")
            listener.bind(path)
            listener.listen()
            self.assertEqual(run(PROBE, "unix", path).returncode, 0)
            result = self.network(PROBE, "unix", path)
            self.assertEqual(result.returncode, 77, result.stderr)
        self.assertEqual(self.network(PROBE, "serve", "127.0.0.1:0", "denied").returncode, 77)

    @unittest.skipUnless(LINUX, "network namespaces require Linux")
    def test_namespace_denials_and_children(self):
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            with self.subTest(host=host), socket.socket(family) as listener:
                listener.bind((host, 0))
                listener.listen()
                address = f"[{host}]:{listener.getsockname()[1]}" if ":" in host else f"{host}:{listener.getsockname()[1]}"
                self.assertEqual(run(PROBE, "dial", address).returncode, 0)
                for prefix in [[], ["child"]]:
                    result = self.network(PROBE, *prefix, "dial", address)
                    self.assertEqual(result.returncode, DIAL_DENIED, result.stderr)
        with serving([PROBE, "udp-serve", "127.0.0.1:0", "HOST"]) as (_, port):
            self.assertEqual(run(PROBE, "udp-get", f"127.0.0.1:{port}").stdout, "HOST")
            result = self.network(PROBE, "udp-get", f"127.0.0.1:{port}")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("HOST", result.stdout)
        with tempfile.TemporaryDirectory(dir="/tmp") as d, socket.socket(socket.AF_UNIX) as listener:
            path = str(pathlib.Path(d) / "s")
            listener.bind(path)
            listener.listen()
            self.assertEqual(run(PROBE, "unix", path).returncode, 0)
            for prefix in [[], ["child"]]:
                result = self.network(PROBE, *prefix, "unix", path)
                self.assertEqual(result.returncode, 77, result.stderr)
        with tempfile.TemporaryDirectory(dir="/tmp") as d, socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
            path = str(pathlib.Path(d) / "d")
            receiver.bind(path)
            self.assertEqual(run(PROBE, "pair-dgram", path).returncode, 0)
            self.assertEqual(receiver.recv(16), b"escape")
            receiver.setblocking(False)
            result = self.network(PROBE, "pair-dgram", path)
            self.assertEqual(result.returncode, 77, result.stderr)
            with self.assertRaises(BlockingIOError):
                receiver.recv(16)
        result = self.network(PROBE, "pair")
        self.assertEqual((result.returncode, result.stdout), (0, "pair"), result.stderr)
        with tempfile.TemporaryDirectory() as outside:
            target = pathlib.Path(outside) / "target"
            target.write_text("original")
            result = self.network("/usr/bin/truncate", "-s", "0", target)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_text(), "original")
            before = target.stat()
            for command in [["chmod", "600", target], ["touch", "-d", "2000-01-01", target],
                            ["ln", "-s", "x", pathlib.Path(outside) / "link"]]:
                result = self.network(*command)
                self.assertNotEqual(result.returncode, 0, command)
            # No new alias of an outside file: hard links cross mounts (EXDEV)
            # and writes through symlinks land on the read-only view.
            result = self.network("/bin/sh", "-c", f"ln {target} hard; ln -s {target} soft; echo x > soft")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.dir / "hard").exists())
            after = target.stat()
            self.assertEqual((after.st_mode, after.st_mtime_ns), (before.st_mode, before.st_mtime_ns))
            self.assertEqual(target.read_text(), "original")
            self.assertFalse((pathlib.Path(outside) / "link").exists())
        result = self.network("/bin/sh", "-c", 'echo in > inside && chmod 700 inside && touch -d 2000-01-01 inside && echo t > "$TMPDIR/t" && cat inside')
        self.assertEqual((result.returncode, result.stdout), (0, "in\n"), result.stderr)
        self.assertEqual((self.dir / "inside").stat().st_mode & 0o777, 0o700)
        # Only loopback exists, private to this execution.
        result = self.network("/bin/sh", "-c", "tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' '")
        self.assertEqual((result.returncode, result.stdout), (0, "lo\n"), result.stderr)

    @unittest.skipUnless(LINUX, "Landlock ptrace restriction requires Linux")
    def test_cannot_steal_host_descriptors(self):
        # The host process allows any tracer, as with Yama disabled; only
        # Landlock's ptrace restriction (all ABIs) stands in the way.
        target = subprocess.Popen([sys.executable, "-c", """
import ctypes, socket, time
ctypes.CDLL(None).prctl(0x59616d61, ctypes.c_ulong(2**64 - 1), 0, 0, 0)
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen()
print(s.fileno(), flush=True); time.sleep(30)
"""], stdout=subprocess.PIPE, text=True)
        self.addCleanup(target.wait)
        self.addCleanup(target.kill)
        fd = target.stdout.readline().strip()
        (self.dir / "steal.py").write_text("""
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
pidfd = libc.syscall(434, int(sys.argv[1]), 0)
got = libc.syscall(438, pidfd, int(sys.argv[2]), 0) if pidfd >= 0 else -1
print("stolen" if got >= 0 else os.strerror(ctypes.get_errno()))
""")
        control = run(sys.executable, self.dir / "steal.py", target.pid, fd)
        if pathlib.Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip() in ("0", "1"):
            self.assertEqual(control.stdout.strip(), "stolen", control.stderr)
        result = self.network("/usr/bin/python3", "steal.py", target.pid, fd)
        # The PID namespace hides the host process (ESRCH); Landlock refuses
        # the ptrace access check (EPERM) even when it is addressable.
        self.assertIn(result.stdout.strip(), [os.strerror(1), os.strerror(3)], result.stderr)

    @unittest.skipUnless(LINUX, "user namespaces require Linux")
    def test_workload_has_no_capabilities_even_for_root(self):
        script = "grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status | cut -f2 | sort -u; mount -o remount,rw / 2>/dev/null"
        # `unshare -r` makes the caller UID 0, as when root runs world; the
        # caller also raises its inheritable set, which exec must not keep.
        raise_inheritable = """
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
header = (ctypes.c_uint32 * 2)(0x20080522, 0)
data = (ctypes.c_uint32 * 6)()
assert libc.syscall(125, header, data) == 0
data[2] = data[1]  # inheritable = permitted (low word)
assert libc.syscall(126, header, data) == 0, ctypes.get_errno()
os.execv(sys.argv[1], sys.argv[1:])
"""
        for prefix in [[], ["unshare", "-r", sys.executable, "-c", raise_inheritable]]:
            with self.subTest(prefix=prefix[:2]):
                result = run(*prefix, WORLD, "network", "exec", "--policy", self.policy,
                             "--workdir", self.dir, "--", "/bin/sh", "-c", script)
                self.assertNotEqual(result.returncode, 0, "remount must fail")
                self.assertEqual(result.stdout, "0000000000000000\n", result.stderr)

    @unittest.skipUnless(LINUX, "Linux-specific isolation")
    def test_keyrings_devices_and_dev_paths(self):
        # KEYCTL_JOIN_SESSION_KEYRING: works on the host, refused by seccomp.
        keyring = "import ctypes, os\nlibc = ctypes.CDLL(None, use_errno=True)\nr = libc.syscall(250, 1, None)\nprint('id' if r >= 0 else os.strerror(ctypes.get_errno()))"
        self.assertIn("id", run(sys.executable, "-c", keyring).stdout)
        result = self.network("/usr/bin/python3", "-c", keyring)
        self.assertIn(os.strerror(1), result.stdout, result.stderr)
        # Device nodes anywhere in the view, the workdir included, are inert.
        options = "import os\nfor line in open('/proc/self/mountinfo'):\n    f = line.split()\n    if f[4] == os.getcwd(): print(f[5])"
        result = self.network("/usr/bin/python3", "-c", options)
        self.assertIn("nodev", result.stdout.strip().split(","), result.stderr)
        # The private /dev would hide paths beneath the host /dev.
        with tempfile.TemporaryDirectory(dir="/dev/shm") as shm:
            result = run(WORLD, "network", "exec", "--policy", self.policy, "--workdir", shm, "--", "/bin/true")
            self.assertEqual(result.returncode, 125)
            self.assertIn("workdir under /dev", result.stderr)
            result = self.network("/bin/sh", "-c", 'case "$TMPDIR" in /dev/*) exit 1;; esac; test -d "$TMPDIR"',
                                  env=dict(os.environ, TMPDIR=shm))
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(LINUX, "private /dev requires Linux")
    def test_host_terminal_and_devices_are_unreachable(self):
        import pty, termios
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        path = os.ttyname(slave)
        code = f"""
import os, termios
fd = os.open({path!r}, os.O_RDONLY | os.O_NOCTTY)
attrs = termios.tcgetattr(fd); attrs[3] &= ~termios.ECHO
termios.tcsetattr(fd, termios.TCSANOW, attrs)
"""
        result = self.network("/usr/bin/python3", "-c", code)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO, "host terminal was changed")
        script = "ls /dev | tr '\\n' ' '; test -e /dev/tty && echo tty; echo x > /dev/null && echo s > /dev/shm/s && cat /dev/shm/s; touch /dev/new 2>/dev/null || echo ro"
        result = self.network("/bin/sh", "-c", script)
        self.assertEqual(result.stdout, "fd full null random shm stderr stdin stdout urandom zero s\nro\n", result.stderr)

    @unittest.skipUnless(LINUX, "IPC namespaces require Linux")
    def test_host_sysv_ipc_is_unreachable(self):
        created = run("ipcmk", "-M", "4096")
        self.assertEqual(created.returncode, 0, created.stderr)
        shmid = created.stdout.split()[-1]
        self.addCleanup(run, "ipcrm", "-m", shmid)
        result = self.network("/bin/sh", "-c", f"ipcs -m | grep -c ' {shmid} '; ipcrm -m {shmid}")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "0")
        self.assertIn(f" {shmid} ", run("ipcs", "-m").stdout)

    @unittest.skipUnless(SANDBOX, "requires macOS Seatbelt or Linux namespaces")
    def test_exit_status_with_ignored_sigchld(self):
        # SIG_IGN survives exec; world must still collect the exit status.
        command = [str(WORLD), "network", "exec", "--policy", str(self.policy), "--workdir", str(self.dir),
                   "--", "/bin/sh", "-c", "exit 3"]
        result = run("/bin/sh", "-c", 'trap "" CHLD; exec "$@"', "sh", *command)
        self.assertEqual(result.returncode, 3, result.stderr)

    @unittest.skipUnless(LINUX, "PID namespaces require Linux")
    def test_escaped_descendants_are_killed(self):
        self.assertEqual(self.network("/bin/sh", "-c", "kill -9 $$").returncode, 137)
        script = 'setsid /bin/sh -c "sleep 2; echo escaped > marker" </dev/null >/dev/null 2>&1 & echo "$$"'
        for timeout in ["5s", "300ms"]:
            with self.subTest(timeout=timeout):
                command = ["/bin/sh", "-c", script + ("" if timeout == "5s" else "; sleep 5")]
                result = self.network(*command, timeout=timeout)
                self.assertEqual(result.returncode, 0 if timeout == "5s" else 124, result.stderr)
                if timeout == "5s":
                    self.assertEqual(result.stdout, "2\n")  # PID 1 is the reaper
                time.sleep(3)
                self.assertFalse((self.dir / "marker").exists())

    @unittest.skipUnless(LINUX, "Linux stdin policy")
    def test_stdin_must_be_a_pipe_or_null(self):
        # Any other inode could be modified through the inherited descriptor
        # (fchmod, futimens, fsetxattr, terminal ioctls).
        with tempfile.TemporaryDirectory() as outside:
            target = pathlib.Path(outside) / "target"
            target.write_text("content")
            fifo = pathlib.Path(outside) / "fifo"
            os.mkfifo(fifo)
            fd = os.open(fifo, os.O_RDWR)
            try:
                with open(target) as file:
                    for stdin in [file, fd]:
                        result = self.network("/bin/cat", stdin=stdin)
                        self.assertEqual(result.returncode, 125, result.stderr)
                        self.assertIn("stdin must be a pipe or /dev/null", result.stderr)
            finally:
                os.close(fd)
        # A pipe's write end would be a channel back to the host.
        r, w = os.pipe()
        try:
            result = self.network("/bin/true", stdin=w)
            self.assertEqual(result.returncode, 125, result.stderr)
            self.assertIn("stdin must be a pipe or /dev/null", result.stderr)
        finally:
            os.close(r)
            os.close(w)
        result = self.network("/bin/cat", input="piped")
        self.assertEqual((result.returncode, result.stdout), (0, "piped"), result.stderr)
        check = "import os\nst = os.fstat(0)\nprint(os.major(st.st_rdev), os.minor(st.st_rdev), os.read(0, 1) == b'')"
        result = self.network("/usr/bin/python3", "-c", check, stdin=subprocess.DEVNULL)
        self.assertEqual((result.returncode, result.stdout), (0, "1 3 True\n"), result.stderr)
        # The null device comes from the private read-only /dev.
        result = run("unshare", "-r", WORLD, "network", "exec", "--policy", self.policy, "--workdir", self.dir,
                     "--", "/usr/bin/python3", "-c", "import os; os.fchmod(0, 0o600)", stdin=subprocess.DEVNULL)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Read-only file system", result.stderr)

    @unittest.skipUnless(SANDBOX, "requires macOS Seatbelt or Linux namespaces")
    def test_writable_file_stdin_is_refused(self):
        with tempfile.TemporaryDirectory() as outside:
            target = pathlib.Path(outside) / "target"
            target.write_text("original")
            with open(target, "r+") as stdin:
                result = self.network("/bin/sh", "-c", "echo escape >&0", stdin=stdin)
            self.assertEqual(result.returncode, 125, result.stderr)
            self.assertIn("writable file stdin", result.stderr)
            self.assertEqual(target.read_text(), "original")
            with open(target) as stdin:
                result = self.network("/bin/cat", stdin=stdin)
            if MACOS:
                self.assertEqual((result.returncode, result.stdout), (0, "original"), result.stderr)
            else:
                self.assertEqual(result.returncode, 125, result.stderr)

    @unittest.skipUnless(SANDBOX, "requires macOS Seatbelt or Linux namespaces")
    def test_exit_timeout_and_open_stdin(self):
        self.assertEqual(self.network("/bin/sh", "-c", "exit 42").returncode, 42)
        result = self.network("/bin/echo", "closed-stdin-ok", preexec_fn=lambda: os.close(0))
        self.assertEqual((result.returncode, result.stdout), (0, "closed-stdin-ok\n"), result.stderr)
        self.assertEqual(self.network("/bin/sleep", "30", timeout="100ms").returncode, 124)
        r, w = os.pipe()
        try:
            self.assertEqual(self.network("/bin/echo", "ok", stdin=r).returncode, 0)
        finally:
            os.close(r)
            os.close(w)

    @unittest.skipUnless(SANDBOX, "requires macOS Seatbelt or Linux namespaces")
    def test_fd_and_host_write_guards(self):
        first, second = socket.socketpair()
        with first as sock, second:
            fd = sock.fileno()
            self.assertEqual(run(PROBE, "fd", fd, pass_fds=(fd,)).returncode, 99)
            result = self.network(PROBE, "fd", fd, pass_fds=(fd,))
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)
            result = self.network("/bin/echo", "never", stdin=fd)
            self.assertEqual(result.returncode, 125)
        with tempfile.TemporaryDirectory() as outside:
            result = self.network(PROBE, "write", str(pathlib.Path(outside) / "escape"))
            # Linux refuses on the read-only mount (EROFS) before Landlock (EACCES).
            self.assertIn(result.returncode, (77,) if MACOS else (77, 78), result.stderr)
            self.assertFalse((pathlib.Path(outside) / "escape").exists())
        if MACOS:
            self.assertNotEqual(self.network("/bin/launchctl", "list").returncode, 0)

    @unittest.skipUnless(SANDBOX, "requires macOS Seatbelt or Linux namespaces")
    def test_http_proxy_and_connect(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                assert "Proxy-Authorization" not in self.headers
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"allowed")
            def log_message(self, *args):
                pass
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_port
                self.policy.write_text(json.dumps({"network_id":"test","allow":[{"host":"127.0.0.1","port":port}]}))
                for extra in [[], ["--proxytunnel"]]:
                    result = self.network("/usr/bin/curl", "-fsS", *extra, f"http://127.0.0.1:{port}")
                    self.assertEqual((result.returncode, result.stdout), (0, "allowed"), result.stderr)
                self.assertEqual(self.network(PROBE, "dial", f"127.0.0.1:{port}").returncode, DIAL_DENIED)
                result = self.network("/usr/bin/curl", "-sS", "http://127.0.0.1:1")
                self.assertIn("destination denied", result.stdout)
            finally:
                server.shutdown()
                thread.join()

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_shim_injection_and_no_host_fallback_without_alias(self):
        ack = self.dir / "ack"
        ack.touch()
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp))
        with serving([PROBE, "serve", "127.0.0.1:0", "HOST"]) as (_, port):
            result = run(PROBE, "get", f"127.0.0.1:{port}", env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("HOST", result.stdout)
            self.assertEqual(ack.read_text(), "world-silo-v1")
        result = run(PROBE, "get", "127.77.254.253:12345", env=env)
        self.assertEqual(result.returncode, 77, result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_child_script_cannot_drop_injection(self):
        ack = self.dir / "ack"
        ack.touch()
        script = self.dir / "child.sh"
        script.write_text("#!/bin/sh\necho escaped\n")
        script.chmod(0o755)
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp),
                   PATH=str(self.dir))
        for mode in ["launch", "exec"]:
            result = run(PROBE, mode, script, env=env)
            self.assertEqual(result.returncode, 77, result.stderr)
            self.assertNotIn("escaped", result.stdout)
            self.assertEqual(ack.read_text(), "world-silo-v1")
        # A superficially non-SIP PATH replacement must not resolve back to /bin/sh.
        (self.dir / "bash").symlink_to("/bin/sh")
        for mode in ["launch", "exec"]:
            result = run(PROBE, mode, script, env=env)
            self.assertEqual(result.returncode, 77, result.stderr)
            self.assertNotIn("escaped", result.stdout)
        # Ordinary native children still execute with the inherited injection.
        for mode in ["launch", "exec"]:
            result = run(PROBE, mode, PROBE, "fd", "999", env=env)
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_shebang_preserves_interpreter_and_arguments(self):
        ack = self.dir / "ack"
        ack.touch()
        for name in ["bash", "zsh", "python3"]:
            (self.dir / name).symlink_to(PROBE)
        script = self.dir / "script"
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp), PATH=str(self.dir))
        for shebang, interpreter, options in [("/bin/zsh", "zsh", []),
                ("/usr/bin/env -S python3 -u -B", "python3", ["-u", "-B"])]:
            script.write_text(f"#!{shebang}\n")
            script.chmod(0o755)
            for mode in ["launch", "exec"]:
                result = run(PROBE, mode, script, "user-argument", env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), [str(self.dir / interpreter), *options, str(script), "user-argument"])
        (self.dir / "zsh").unlink()
        script.write_text("#!/bin/zsh\n")
        self.assertEqual(run(PROBE, "launch", script, env=env).returncode, 77)
        script.write_text('#!/usr/bin/env -S python3 "quoted argument"\n')
        self.assertEqual(run(PROBE, "launch", script, env=env).returncode, 77)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_child_shebang_path_and_permissions(self):
        ack = self.dir / "ack"
        ack.touch()
        parent, child = self.dir / "parent", self.dir / "child"
        parent.mkdir()
        child.mkdir()
        for directory in [parent, child]:
            (directory / "python3").symlink_to(PROBE)
        script = self.dir / "script"
        script.write_text("#!/usr/bin/env python3\n")
        script.chmod(0o755)
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp), PATH=str(parent))
        bad_dir, bad_link = self.dir / "bad-dir", self.dir / "bad-link"
        bad_dir.mkdir()
        bad_link.mkdir()
        (bad_dir / "python3").mkdir()
        (bad_link / "python3").symlink_to("/bin/sh")
        child_path = f"{bad_dir}:{bad_link}:{child}"
        for mode in ["launch-envpath", "exec-envpath"]:
            result = run(PROBE, mode, child_path, script, "arg", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [str(child / "python3"), str(script), "arg"])
            result = run(PROBE, mode, str(bad_dir), script, env=env)
            self.assertEqual(result.returncode, 77, result.stderr)
            script.chmod(0o644)
            result = run(PROBE, mode, child_path, script, env=env)
            self.assertEqual(result.returncode, 77, result.stderr)
            script.chmod(0o755)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_env_shebang_empty_path_components_use_cwd(self):
        ack = self.dir / "ack"
        ack.touch()
        (self.dir / "python3").symlink_to(PROBE)
        script = self.dir / "script"
        script.write_text("#!/usr/bin/env python3\n")
        script.chmod(0o755)
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp))
        for path in ["", ":/nonexistent", "/nonexistent:", "/nonexistent::/nonexistent"]:
            for mode in ["launch-envpath", "exec-envpath"]:
                result = run(PROBE, mode, path, script, env=env, cwd=self.dir)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), ["./python3", str(script)])

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_child_injection_values_are_immutable(self):
        ack = self.dir / "ack"
        ack.touch()
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp))
        for key, value in [("SILO_IP", "127.77.254.253"), ("DYLD_INSERT_LIBRARIES", "/usr/lib/libSystem.B.dylib"),
                           ("WORLD_TMP", str(self.temp_root("other-tmp")))]:
            for mode in ["launch", "exec"]:
                result = run(PROBE, "tamper-child", mode, key, value, env=env)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertNotIn("descriptor-closed", result.stdout)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_path_script_uses_resolved_shebang(self):
        ack = self.dir / "ack"
        ack.touch()
        (self.dir / "python3").symlink_to(PROBE)
        script = self.dir / "path-script"
        script.write_text("#!/usr/bin/env -S python3 -u\n")
        script.chmod(0o755)
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp), PATH=str(self.dir))
        result = run(PROBE, "launch", "path-script", "caller-arg", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [str(self.dir / "python3"), "-u", str(script), "caller-arg"])

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_non_path_launch_validates_current_directory(self):
        ack = self.dir / "ack"
        ack.touch()
        cwd, path = self.dir / "cwd", self.dir / "path"
        cwd.mkdir()
        path.mkdir()
        (cwd / "candidate").symlink_to("/bin/echo")
        (path / "candidate").symlink_to(PROBE)
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp), PATH=str(path))
        for mode in ["raw-spawn", "raw-exec"]:
            result = run(PROBE, mode, "candidate", "fd", "999", env=env, cwd=cwd)
            self.assertEqual(result.returncode, 77, result.stderr)
        (cwd / "candidate").unlink()
        (path / "candidate").unlink()
        (cwd / "candidate").symlink_to(PROBE)
        (path / "candidate").symlink_to("/bin/echo")
        for mode in ["raw-spawn", "raw-exec"]:
            result = run(PROBE, mode, "candidate", "fd", "999", env=env, cwd=cwd)
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_spawn_chdir_cannot_switch_relative_target(self):
        ack = self.dir / "ack"
        ack.touch()
        current, other = self.dir / "current", self.dir / "other"
        current.mkdir()
        other.mkdir()
        (current / "candidate").symlink_to(PROBE)
        (other / "candidate").symlink_to("/bin/echo")
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp))
        import ctypes
        modes = ["raw-spawn-chdir", "raw-spawn-fchdir"]
        if hasattr(ctypes.CDLL(None), "posix_spawn_file_actions_addchdir"):
            modes += ["raw-spawn-chdir-posix", "raw-spawn-fchdir-posix"]
        for mode in modes:
            baseline = run(PROBE, mode, "candidate", other, "fd", "999", cwd=current)
            self.assertEqual((baseline.returncode, baseline.stdout), (0, "fd 999\n"), baseline.stderr)
            result = run(PROBE, mode, "candidate", other, "fd", "999", cwd=current, env=env)
            self.assertEqual(result.returncode, 77, result.stderr)
            result = run(PROBE, mode, PROBE, other, "fd", "999", cwd=current, env=env)
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_privileged_child_mode_is_rejected(self):
        ack = self.dir / "ack"
        ack.touch()
        program = self.dir / "privileged"
        program.write_bytes(PROBE.read_bytes())
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), WORLD_TMP=str(self.world_tmp))
        for mode in [0o4755, 0o2755]:
            program.chmod(mode)
            for launch in ["raw-spawn", "raw-exec"]:
                result = run(PROBE, launch, program, "fd", "999", env=env)
                self.assertEqual(result.returncode, 77, result.stderr)
        program.chmod(0o755)
        result = run(PROBE, "raw-spawn", program, "fd", "999", env=env)
        self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_shared_temp_paths_are_redirected(self):
        name = f"wt-{uuid.uuid4().hex[:8]}"
        result = run(PROBE, "temp-suite", name, env=self.shim_env(self.world_tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        host = f"/private/tmp/{name}"
        self.assertEqual(report["read"], "data")
        self.assertEqual(report["readlink"], f"{host}/file")
        self.assertEqual(report["canonical"], f"{host}/file")
        self.assertEqual(report["cwd"], host)
        self.assertEqual(report["socket"], f"{host}/s.sock")
        self.assertTrue(report["mkstemp"].startswith(f"/tmp/{name}/mk."), report)
        self.assertEqual((report["entries"], report["var"]), (6, "var"))
        # "a/link/../x" is redirected only up to "a"; the kernel resolves the
        # relative symlink and ".." from there, so it lands on "a/b/x", not
        # a lexically-normalized (and nonexistent) "a/x".
        self.assertEqual(report["symlink_parent"], "symlink-parent")
        for leaked in [f"/tmp/{name}", f"/var/tmp/{name}"]:
            self.assertFalse(os.path.lexists(leaked), leaked)
        physical = self.world_tmp / "tmp" / name
        self.assertEqual((physical / "file").read_text(), "data")
        # Link targets are stored at the World location and resolved there.
        self.assertEqual(os.readlink(physical / "link"), str(physical / "file"))
        self.assertFalse((physical / "a" / "x").exists())
        self.assertEqual((self.world_tmp / "var/tmp" / name / "file").read_text(), "var")

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_short_getsockname_buffer_is_respected(self):
        name = f"wt-{uuid.uuid4().hex[:8]}"
        path = f"/tmp/{name}/s.sock"
        result = run(PROBE, "getsockname-short", path, "20", env=self.shim_env(self.world_tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        host = f"/private/tmp/{name}/s.sock"
        self.assertTrue(report["guard_intact"], report)
        self.assertEqual(report["prefix"], host[:18])
        self.assertEqual(report["len"], 2 + len(host) + 1)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_dotdot_escapes_a_redirected_temp_root_through_a_symlink(self):
        # A `..` chain long enough to leave the temp root, after a symlink
        # inside it: the kernel resolves the symlink first, so the escape
        # must land back in the *private* root, not walk the host's /tmp.
        name = f"wt-{uuid.uuid4().hex[:8]}"
        result = run(PROBE, "temp-escape", name, env=self.shim_env(self.world_tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["via_link"], "escaped-ok")
        self.assertTrue(report["hosts"], report)
        self.assertEqual(report["missing"], errno.ENOENT)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_getcwd_reports_the_host_name_even_in_a_small_buffer(self):
        name = f"wt-{uuid.uuid4().hex[:8]}"
        result = run(PROBE, "cwd-sized", name, env=self.shim_env(self.world_tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        host = f"/private/tmp/{name}"
        self.assertEqual(report["fit"], host)
        self.assertEqual(report["exact"], {"errno": errno.ERANGE})
        self.assertEqual(report["null_fit"], host)
        self.assertEqual(report["null_zero"], host)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_readlink_reports_the_host_name_even_when_truncated(self):
        name = f"wt-{uuid.uuid4().hex[:8]}"
        result = run(PROBE, "readlink-sized", name, env=self.shim_env(self.world_tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        host_target = f"/private/tmp/{name}/target"
        self.assertEqual(report["full"], host_target)
        self.assertEqual(report["full_ret"], len(host_target))
        self.assertEqual(report["short"], host_target[:10])
        self.assertEqual(report["short_ret"], 10)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_same_temp_lock_and_socket_names_do_not_conflict(self):
        path = f"/tmp/wt-{uuid.uuid4().hex[:8]}/service"
        a, b = self.temp_root("a"), self.temp_root("b")
        with serving([PROBE, "temp-hold", path], env=self.shim_env(a)):
            with serving([PROBE, "temp-hold", path], env=self.shim_env(b)):
                for root in [a, b]:
                    self.assertTrue((root / path.removeprefix("/")).with_suffix(".sock").exists())
            # The same World still shares its lock between processes.
            result = run(PROBE, "temp-hold", path, env=self.shim_env(a))
            self.assertEqual(result.returncode, 78, result.stderr)
        self.assertFalse(os.path.lexists(os.path.dirname(path)))

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_executable_below_shared_temp_is_redirected(self):
        name = f"wt-{uuid.uuid4().hex[:8]}"
        (self.world_tmp / "tmp" / name).mkdir()
        (self.world_tmp / "tmp" / name / "probe").symlink_to(PROBE)
        for mode in ["launch", "exec", "raw-spawn", "raw-exec"]:
            result = run(PROBE, mode, f"/tmp/{name}/probe", "fd", "999", env=self.shim_env(self.world_tmp))
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_active_shim_requires_private_temp_root(self):
        env = self.shim_env(self.world_tmp)
        for value in [None, "", "/private/tmp/world", "relative/world/tmp"]:
            if value is None:
                env.pop("WORLD_TMP")
            else:
                env["WORLD_TMP"] = value
            result = run(PROBE, "fd", "999", env=env)
            self.assertEqual(result.returncode, 125, value)

    @unittest.skipUnless(sys.platform == "darwin", "native shim requires macOS")
    def test_workspace_rejects_shared_temp_workdir(self):
        for workdir in ["/tmp", "/private/var/tmp"]:
            result = run(WORLD, "workspace", "--state-dir", self.dir / "state", "create", "X", "--workdir", workdir)
            self.assertEqual(result.returncode, 125)
            self.assertIn("must not be under /tmp or /var/tmp", result.stderr)

    @unittest.skipUnless(SANDBOX, "requires macOS Seatbelt or Linux namespaces")
    def test_slow_output_consumer_does_not_lose_tail(self):
        for destination in ["stdout", "stderr"]:
            r, w = os.pipe()
            try:
                os.set_blocking(w, False)
                prefix = 0
                while True:
                    try:
                        prefix += os.write(w, b"p" * 4096)
                    except BlockingIOError:
                        break
                os.set_blocking(w, True)
                streams = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
                streams[destination] = w
                with subprocess.Popen([str(WORLD), "network", "exec", "--policy", str(self.policy),
                        "--workdir", str(self.dir), "--timeout", "10s", "--", str(PROBE), "burst", destination],
                        stdin=subprocess.DEVNULL, **streams) as process:
                    os.close(w)
                    w = None
                    time.sleep(2)
                    received = bytearray()
                    while True:
                        self.assertTrue(select.select([r], [], [], 12)[0], "output drain timed out")
                        chunk = os.read(r, 65536)
                        if not chunk:
                            break
                        received.extend(chunk)
                    self.assertEqual(process.wait(timeout=5), 0)
                    self.assertEqual(received, b"p" * prefix + b"x" * 16384)
            finally:
                os.close(r)
                if w is not None:
                    os.close(w)

    @unittest.skipUnless(SANDBOX, "requires macOS Seatbelt or Linux namespaces")
    def test_https_connect(self):
        config = self.dir / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n")
        cert, key = self.dir / "ca.pem", self.dir / "key.pem"
        result = run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                     "-config", config, "-keyout", key, "-out", cert)
        self.assertEqual(result.returncode, 0, result.stderr)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                # Framed body: OpenSSL 3 curl rejects EOF without close_notify.
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"tls-ok")
            def log_message(self, *args):
                pass
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self.policy.write_text(json.dumps({"network_id":"tls","allow":[{"host":"127.0.0.1","port":server.server_port}]}))
                result = self.network("/usr/bin/curl", "-fsS", "--cacert", cert, f"https://127.0.0.1:{server.server_port}")
                self.assertEqual((result.returncode, result.stdout), (0, "tls-ok"), result.stderr)
            finally:
                server.shutdown()
                thread.join()


@unittest.skipUnless(sys.platform == "darwin" and os.getenv("WORLD_SILO_INTEGRATION") == "1",
                     "requires explicit macOS privileged loopback setup")
class Silo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="world-silo-test-")
        cls.root = pathlib.Path(cls.temp.name)
        cls.state = cls.root / "state"
        cls.worlds = {}
        for name in ["A", "B"]:
            work = cls.root / name
            work.mkdir()
            result = run(WORLD, "workspace", "--state-dir", cls.state, "create", name, "--workdir", work)
            if result.returncode:
                raise AssertionError(result.stderr)
            info = json.loads(result.stdout)
            # CI runner has passwordless sudo. Never alter sudoers or /etc/hosts.
            subprocess.run(["sudo", "-n", "/sbin/ifconfig", "lo0", "alias", info["ip"], "netmask", "255.0.0.0"], check=True, timeout=10)
            cls.worlds[name] = info

    @classmethod
    def tearDownClass(cls):
        for world in cls.worlds.values():
            shutil.rmtree(pathlib.Path.home() / ".world/tmp" / world["ip"], ignore_errors=True)
            subprocess.run(["sudo", "-n", "/sbin/ifconfig", "lo0", "-alias", world["ip"]], check=True, timeout=10)
        cls.temp.cleanup()

    def command(self, world, *args):
        return [WORLD, "exec", world, "--state-dir", self.state, "--timeout", "30s", "--", PROBE, *args]

    def test_same_port_localhost_and_lifecycle(self):
        for host in ["127.0.0.1", "0.0.0.0", "[::1]", "[::]"]:
            with self.subTest(host=host), serving(self.command("A", "serve", f"{host}:0", "A")) as (a, port):
                with serving(self.command("B", "serve", f"{host}:{port}", "B")):
                    localhost = "[::1]" if host.startswith("[") else "127.0.0.1"
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        futures = {name:pool.submit(run, *self.command(name, "get", f"{localhost}:{port}")) for name in ["A", "B"]}
                        for name, future in futures.items():
                            result = future.result()
                            self.assertEqual((result.returncode, result.stdout), (0, name), result.stderr)
                    result = run(*self.command("A", "child", "get", f"{localhost}:{port}"))
                    self.assertEqual((result.returncode, result.stdout), (0, "A"), result.stderr)
                    other = self.worlds["B"]["ip"]
                    self.assertEqual(run(*self.command("A", "get", f"{other}:{port}")).returncode, 77)
                    a.terminate()
                    a.wait(timeout=5)
                    result = run(*self.command("B", "get", f"{localhost}:{port}"))
                    self.assertEqual((result.returncode, result.stdout), (0, "B"), result.stderr)

    def test_path_skips_non_executable_candidates(self):
        with tempfile.TemporaryDirectory() as root:
            first, second = pathlib.Path(root) / "first", pathlib.Path(root) / "second"
            first.mkdir()
            second.mkdir()
            (first / "probe").write_text("not executable")
            (second / "probe").symlink_to(PROBE)
            env = dict(os.environ, PATH=f"{first}:{second}")
            command = self.command("A", "fd", "999")
            command[-3] = "probe"
            result = run(*command, env=env)
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)
            result = run(*self.command("A", "launch", "probe", "fd", "999"), env=env)
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

    def test_main_relative_path_uses_world_workdir(self):
        work = pathlib.Path(self.worlds["A"]["workdir"])
        local = work / "workdir-probe"
        local.symlink_to(PROBE)
        self.addCleanup(local.unlink)
        with tempfile.TemporaryDirectory(dir=work) as bindir, tempfile.TemporaryDirectory() as caller:
            bindir = pathlib.Path(bindir)
            (bindir / "workdir-probe").symlink_to(PROBE)
            caller = pathlib.Path(caller)
            (caller / "workdir-probe").symlink_to("/bin/echo")
            (caller / bindir.name).mkdir()
            (caller / bindir.name / "workdir-probe").symlink_to("/bin/echo")
            for path in ["", ":", f"./{bindir.name}"]:
                command = self.command("A", "fd", "999")
                command[-3] = "workdir-probe"
                result = run(*command, env=dict(os.environ, PATH=path), cwd=caller)
                self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

    def test_main_alias_preserves_arg0(self):
        work = pathlib.Path(self.worlds["A"]["workdir"])
        with tempfile.TemporaryDirectory(dir=work) as bindir:
            bindir = pathlib.Path(bindir)
            alias = bindir / "python3"
            alias.symlink_to(PROBE)
            for requested in [str(alias), "python3", f"./{bindir.name}/python3"]:
                command = self.command("A", "caller-argument")
                command[-2] = requested
                result = run(*command, env=dict(os.environ, PATH=str(bindir)))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), [requested, "caller-argument"])

    def test_main_executable_below_temp_uses_workspace_root(self):
        n = f"wt-{uuid.uuid4().hex[:8]}"
        root = pathlib.Path.home() / ".world/tmp" / self.worlds["A"]["ip"]
        # An exec must have run at least once for the workspace root to exist.
        result = run(*self.command("A", "fd", "999"))
        self.assertEqual(result.returncode, 0, result.stderr)

        private_dir = root / "tmp" / n
        private_dir.mkdir(parents=True)
        (private_dir / "probe").symlink_to(PROBE)
        # The probe echoes argv as JSON only under an interpreter-like name.
        (private_dir / "python3").symlink_to(PROBE)
        self.addCleanup(shutil.rmtree, private_dir, ignore_errors=True)

        # A decoy at the same name on the host, so a bug that left host paths
        # unmapped would run /bin/echo instead of failing loudly.
        host_dir = pathlib.Path("/tmp") / n
        host_dir.mkdir()
        (host_dir / "probe").symlink_to("/bin/echo")
        self.addCleanup(shutil.rmtree, host_dir, ignore_errors=True)

        for requested in [f"/tmp/{n}/probe", f"/private/tmp/{n}/probe"]:
            command = self.command("A", "fd", "999")
            command[-3] = requested
            result = run(*command)
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

        command = self.command("A", "fd", "999")
        command[-3] = "probe"
        result = run(*command, env=dict(os.environ, PATH=f"/tmp/{n}"))
        self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

        requested = f"/tmp/{n}/python3"
        command = self.command("A", "caller-argument")
        command[-2] = requested
        result = run(*command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [requested, "caller-argument"])

        # World B's own root has no such entry point below its temp root.
        command = self.command("B", "fd", "999")
        command[-3] = f"/tmp/{n}/probe"
        result = run(*command)
        self.assertNotEqual(result.returncode, 0)

    def test_main_privileged_mode_is_rejected(self):
        program = self.root / "privileged"
        program.write_bytes(PROBE.read_bytes())
        self.addCleanup(program.unlink)
        for mode in [0o4755, 0o2755]:
            program.chmod(mode)
            command = self.command("A", "fd", "999")
            command[-3] = program
            result = run(*command)
            self.assertEqual(result.returncode, 125, result.stderr)
            self.assertIn("privileged executable unsupported", result.stderr)

    def test_temp_is_private_per_workspace(self):
        path = f"/tmp/wt-{uuid.uuid4().hex[:8]}/service"
        with serving(self.command("A", "temp-hold", path)):
            with serving(self.command("B", "temp-hold", path)):
                for name, world in self.worlds.items():
                    root = pathlib.Path.home() / ".world/tmp" / world["ip"]
                    self.assertTrue((root / path.removeprefix("/")).with_suffix(".sock").exists(), name)
        self.assertFalse(os.path.lexists(os.path.dirname(path)))
        result = run(*self.command("A", "temp-suite", f"wt-{uuid.uuid4().hex[:8]}"))
        self.assertEqual(result.returncode, 0, result.stderr)
        tmpdir = json.loads(result.stdout)["tmpdir"]
        self.assertEqual(tmpdir, str(pathlib.Path.home().resolve() / ".world/tmp" / self.worlds["A"]["ip"] / "tmp") + "/")

    def test_udp_disconnect_uses_kernel_semantics(self):
        baseline = run(PROBE, "udp-disconnect", "127.0.0.1:12345")
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        result = run(*self.command("A", "udp-disconnect", "127.0.0.1:12345"))
        self.assertEqual((result.returncode, result.stdout), (0, baseline.stdout), result.stderr)

    def test_udp(self):
        with serving(self.command("A", "udp-serve", "127.0.0.1:0", "A")) as (_, port):
            with serving(self.command("B", "udp-serve", f"127.0.0.1:{port}", "B")):
                for name in ["A", "B"]:
                    result = run(*self.command(name, "udp-get", f"127.0.0.1:{port}"))
                    self.assertEqual((result.returncode, result.stdout), (0, name), result.stderr)

    def test_no_host_fallback(self):
        with serving([PROBE, "serve", "127.0.0.1:0", "HOST"]) as (_, port):
            for name in ["A", "B"]:
                result = run(*self.command(name, "get", f"127.0.0.1:{port}"))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("HOST", result.stdout)

    def test_sip_refused(self):
        command = self.command("A")
        command[-1:] = ["/bin/echo", "never"]
        result = run(*command)
        self.assertEqual(result.returncode, 125)
        self.assertNotIn("never", result.stdout)


@unittest.skipUnless(LINUX, "Linux World namespaces")
class LinuxWorkspace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="world-silo-test-")
        cls.root = pathlib.Path(cls.temp.name)
        cls.state = cls.root / "state"
        for name in ["A", "B"]:
            work = cls.root / name
            work.mkdir()
            for action in [["create", name, "--workdir", work], ["setup", name]]:
                result = run(WORLD, "workspace", "--state-dir", cls.state, *action)
                if result.returncode:
                    cls.tearDownClass()
                    raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        for name in ["A", "B"]:
            run(WORLD, "workspace", "--state-dir", cls.state, "teardown", name)
        cls.temp.cleanup()

    def command(self, world, *args):
        return [WORLD, "exec", world, "--state-dir", self.state, "--timeout", "30s", "--", PROBE, *args]

    def test_same_port_localhost_and_lifecycle(self):
        for host in ["127.0.0.1", "0.0.0.0", "[::1]", "[::]"]:
            with self.subTest(host=host), serving(self.command("A", "serve", f"{host}:0", "A")) as (a, port):
                with serving(self.command("B", "serve", f"{host}:{port}", "B")):
                    localhost = "[::1]" if host.startswith("[") else "127.0.0.1"
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        futures = {name:pool.submit(run, *self.command(name, "get", f"{localhost}:{port}")) for name in ["A", "B"]}
                        for name, future in futures.items():
                            result = future.result()
                            self.assertEqual((result.returncode, result.stdout), (0, name), result.stderr)
                    result = run(*self.command("A", "child", "get", f"{localhost}:{port}"))
                    self.assertEqual((result.returncode, result.stdout), (0, "A"), result.stderr)
                    # Scripts and system binaries need no special handling.
                    result = run(*self.command("B")[:-1], "/bin/sh", "-c", f'exec "$0" get {localhost}:{port}', PROBE)
                    self.assertEqual((result.returncode, result.stdout), (0, "B"), result.stderr)
                    self.assertNotIn(run(PROBE, "get", f"{localhost}:{port}").stdout, ["A", "B"])
                    a.terminate()
                    a.wait(timeout=5)
                    result = run(*self.command("B", "get", f"{localhost}:{port}"))
                    self.assertEqual((result.returncode, result.stdout), (0, "B"), result.stderr)

    def test_udp(self):
        with serving(self.command("A", "udp-serve", "127.0.0.1:0", "A")) as (_, port):
            with serving(self.command("B", "udp-serve", f"127.0.0.1:{port}", "B")):
                for name in ["A", "B"]:
                    result = run(*self.command(name, "udp-get", f"127.0.0.1:{port}"))
                    self.assertEqual((result.returncode, result.stdout), (0, name), result.stderr)

    def test_no_host_fallback(self):
        with serving([PROBE, "serve", "127.0.0.1:0", "HOST"]) as (_, port):
            for name in ["A", "B"]:
                result = run(*self.command(name, "get", f"127.0.0.1:{port}"))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("HOST", result.stdout)

    def test_privileged_ports_and_descriptors(self):
        with serving(self.command("A", "serve", "127.0.0.1:80", "A80")):
            result = run(*self.command("A", "get", "127.0.0.1:80"))
            self.assertEqual((result.returncode, result.stdout), (0, "A80"), result.stderr)
        first, second = socket.socketpair()
        with first as sock, second:
            result = run(*self.command("A", "fd", sock.fileno()), pass_fds=(sock.fileno(),))
            self.assertEqual((result.returncode, result.stdout), (0, "descriptor-closed"), result.stderr)

    @staticmethod
    def holders():
        pids = set()
        for entry in pathlib.Path("/proc").iterdir():
            try:
                if entry.name.isdigit() and (entry / "comm").read_text().strip() == "world-holder":
                    pids.add(int(entry.name))
            except OSError:
                pass
        return pids

    def test_holder_is_single_threaded_and_never_orphaned(self):
        pid = json.loads((self.state / "holders.json").read_text())["A"]["pid"]
        self.assertEqual(len(os.listdir(f"/proc/{pid}/task")), 1)
        state = self.root / "readonly-state"
        work = self.root / "D"
        work.mkdir()
        workspace = [WORLD, "workspace", "--state-dir", state]
        self.assertEqual(run(*workspace, "create", "D", "--workdir", work).returncode, 0)
        state.chmod(0o555)
        self.addCleanup(state.chmod, 0o755)
        before = self.holders()
        result = run(*workspace, "setup", "D")
        self.assertEqual(result.returncode, 125, result.stderr)
        time.sleep(0.3)
        self.assertEqual(self.holders() - before, set())

    def test_setup_with_ignored_sigchld(self):
        # SIG_IGN survives exec, as for an embedding process that ignores
        # SIGCHLD: the intermediate child is auto-reaped (ECHILD on wait).
        work = self.root / "F"
        work.mkdir()
        workspace = [str(WORLD), "workspace", "--state-dir", str(self.state)]
        self.assertEqual(run(*workspace, "create", "F", "--workdir", work).returncode, 0)
        self.addCleanup(run, *workspace, "teardown", "F")
        before = self.holders()
        result = run("/bin/sh", "-c", 'trap "" CHLD; exec "$@"', "sh", *workspace, "setup", "F")
        self.assertEqual(result.returncode, 0, result.stderr)
        pid = json.loads((self.state / "holders.json").read_text())["F"]["pid"]
        self.assertEqual(self.holders() - before, {pid})
        self.assertEqual(run(*self.command("F", "fd", "999")).returncode, 0)

    def test_socket_stdin_is_refused(self):
        first, second = socket.socketpair()
        with first as sock, second:
            result = run(*self.command("A", "fd", "999"), stdin=sock.fileno())
        self.assertEqual(result.returncode, 125)
        self.assertIn("socket stdin", result.stderr)

    def test_exit_status_with_ignored_sigchld(self):
        command = [str(x) for x in self.command("A", "fd", "999")]
        command[-3:] = ["/bin/sh", "-c", "exit 3"]
        result = run("/bin/sh", "-c", 'trap "" CHLD; exec "$@"', "sh", *command)
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_stale_holder_is_replaced_and_forgotten(self):
        work = self.root / "E"
        work.mkdir()
        workspace = [WORLD, "workspace", "--state-dir", self.state]
        self.assertEqual(run(*workspace, "create", "E", "--workdir", work).returncode, 0)
        self.addCleanup(run, *workspace, "teardown", "E")
        for _ in range(2):
            self.assertEqual(run(*workspace, "setup", "E").returncode, 0)
            pid = json.loads((self.state / "holders.json").read_text())["E"]["pid"]
            os.kill(pid, 9)
            for _ in range(50):
                if not os.path.exists(f"/proc/{pid}"):
                    break
                time.sleep(0.1)
        # A dead holder is replaced by setup; teardown forgets a dead one.
        self.assertEqual(run(*workspace, "setup", "E").returncode, 0)
        self.assertEqual(run(*self.command("E", "fd", "999")).returncode, 0)
        pid = json.loads((self.state / "holders.json").read_text())["E"]["pid"]
        os.kill(pid, 9)
        time.sleep(0.3)
        self.assertEqual(run(*workspace, "teardown", "E").returncode, 0)
        self.assertNotIn("E", json.loads((self.state / "holders.json").read_text()))

    def test_escaped_descendants_are_killed(self):
        work = self.root / "A"
        command = [WORLD, "exec", "A", "--state-dir", self.state, "--", "/bin/sh", "-c",
                   'setsid /bin/sh -c "sleep 2; echo escaped > marker" </dev/null >/dev/null 2>&1 &']
        self.assertEqual(run(*command).returncode, 0)
        time.sleep(3)
        self.assertFalse((work / "marker").exists())

    def test_setup_idempotent_and_teardown(self):
        work = self.root / "C"
        work.mkdir()
        workspace = [WORLD, "workspace", "--state-dir", self.state]
        self.assertEqual(run(*workspace, "create", "C", "--workdir", work).returncode, 0)
        self.addCleanup(run, *workspace, "teardown", "C")
        result = run(*self.command("C", "fd", "999"))
        self.assertEqual(result.returncode, 125)
        self.assertIn("workspace setup", result.stderr)
        for _ in range(2):
            self.assertEqual(run(*workspace, "setup", "C").returncode, 0)
        holders = json.loads((self.state / "holders.json").read_text())
        with serving(self.command("C", "serve", "127.0.0.1:0", "C")) as (_, port):
            result = run(*self.command("C", "get", f"127.0.0.1:{port}"))
            self.assertEqual((result.returncode, result.stdout), (0, "C"), result.stderr)
            self.assertEqual(json.loads((self.state / "holders.json").read_text()), holders)
        self.assertEqual(run(*workspace, "teardown", "C").returncode, 0)
        with self.assertRaises(ProcessLookupError):
            for _ in range(50):
                os.kill(holders["C"]["pid"], 0)
                time.sleep(0.1)
        self.assertEqual(run(*self.command("C", "fd", "999")).returncode, 125)


if __name__ == "__main__":
    unittest.main()
