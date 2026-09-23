"""Real native-process checks. Silo tests require configured macOS loopback aliases.

cargo build --workspace && cargo build --workspace --examples
python3 -m unittest discover -s tests -v
WORLD_SILO_INTEGRATION=1 python3 -m unittest discover -s tests -v
"""
import concurrent.futures
import contextlib
import http.server
import json
import os
import pathlib
import select
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORLD = ROOT / "target/debug/world"
PROBE = ROOT / "target/debug/examples/socket_probe"


def run(*args, **kwargs):
    return subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=15, **kwargs)


@contextlib.contextmanager
def serving(args):
    process = subprocess.Popen([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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

    def network(self, *command, timeout="5s", **kwargs):
        return run(WORLD, "network", "exec", "--policy", self.policy,
                   "--workdir", self.dir, "--timeout", timeout, "--", *command, **kwargs)

    def test_invalid_policy_and_platform(self):
        self.policy.write_text('{"network_id":"test","typo":true}')
        self.assertEqual(self.network("/bin/echo", "never").returncode, 125)
        if sys.platform != "darwin":
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

    @unittest.skipUnless(sys.platform == "darwin", "Seatbelt requires macOS")
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

    @unittest.skipUnless(sys.platform == "darwin", "Seatbelt requires macOS")
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
            self.assertEqual(result.returncode, 77, result.stderr)
        self.assertNotEqual(self.network("/bin/launchctl", "list").returncode, 0)

    @unittest.skipUnless(sys.platform == "darwin", "Seatbelt requires macOS")
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
                self.assertEqual(self.network(PROBE, "dial", f"127.0.0.1:{port}").returncode, 77)
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
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack))
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
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack),
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
                   SILO_IP="127.77.254.254", WORLD_SILO_ACTIVE="1", WORLD_SILO_ACK=str(ack), PATH=str(self.dir))
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

    @unittest.skipUnless(sys.platform == "darwin", "Seatbelt requires macOS")
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
                        "--workdir", str(self.dir), "--timeout", "10s", "--", str(PROBE), "burst", destination], **streams) as process:
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

    @unittest.skipUnless(sys.platform == "darwin", "Seatbelt requires macOS")
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
            result = run(WORLD, "silo", "--state-dir", cls.state, "create", "--world", name, "--workdir", work)
            if result.returncode:
                raise AssertionError(result.stderr)
            info = json.loads(result.stdout)
            # CI runner has passwordless sudo. Never alter sudoers or /etc/hosts.
            subprocess.run(["sudo", "-n", "/sbin/ifconfig", "lo0", "alias", info["ip"], "netmask", "255.0.0.0"], check=True, timeout=10)
            cls.worlds[name] = info

    @classmethod
    def tearDownClass(cls):
        for world in cls.worlds.values():
            subprocess.run(["sudo", "-n", "/sbin/ifconfig", "lo0", "-alias", world["ip"]], check=True, timeout=10)
        cls.temp.cleanup()

    def command(self, world, *args):
        return [WORLD, "silo", "--state-dir", self.state, "exec", "--world", world, "--timeout", "30s", "--", PROBE, *args]

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


if __name__ == "__main__":
    unittest.main()
