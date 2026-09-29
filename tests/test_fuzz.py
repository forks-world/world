"""Layer-2 differential fuzz: random filesystem operation sequences executed
against both `world_fsmodel::Model` and the real filesystem (through the macOS
silo shim, or Linux's bind-mounted /tmp), compared op by op and by final tree.
See docs/testing.md and crates/world-cli/examples/fuzz_driver/.

    cargo build --workspace --examples
    python3 -m unittest tests.test_fuzz -v
    WORLD_FUZZ_BUDGET=120 python3 -m unittest tests.test_fuzz -v
    WORLD_SILO_INTEGRATION=1 python3 -m unittest tests.test_fuzz -v

Knobs: WORLD_FUZZ_BUDGET (seconds, default 10), WORLD_FUZZ_SEED, WORLD_FUZZ_OPS
(default 40), WORLD_FUZZ_ARTIFACTS (default target/fuzz-artifacts).
"""

import json
import os
import pathlib
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_runtime import ROOT, WORLD  # noqa: E402

FUZZ_DRIVER = ROOT / "target/debug/examples/fuzz_driver"
MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
CORPUS = pathlib.Path(__file__).resolve().parent / "fuzz-corpus"
DEFAULT_SEEDS = [1, 2, 3, 4, 5, 6, 7, 8]
RUN_TIMEOUT = 30


def artifacts_dir():
    return pathlib.Path(os.environ.get("WORLD_FUZZ_ARTIFACTS") or ROOT / "target/fuzz-artifacts")


def budget():
    return float(os.environ.get("WORLD_FUZZ_BUDGET", "10"))


def ops_count():
    return int(os.environ.get("WORLD_FUZZ_OPS", "40"))


def seed_sequence():
    """WORLD_FUZZ_SEED (if set) or the fixed default seeds first, then random
    seeds for as long as the caller's deadline allows."""
    if os.environ.get("WORLD_FUZZ_SEED"):
        yield int(os.environ["WORLD_FUZZ_SEED"])
    else:
        yield from DEFAULT_SEEDS
    rng = random.Random()
    while True:
        yield rng.randint(1, 2**31 - 1)


def fresh_run_id():
    return "fz-" + uuid.uuid4().hex


def run_timeout(args, timeout, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=timeout, **kwargs)


def shim_env(root, ack, **extra):
    """Copied from test_runtime.CLI.shim_env (as test_stress.py does): the
    macOS silo-bind injection recipe, without importing a TestCase."""
    return dict(
        os.environ,
        DYLD_INSERT_LIBRARIES=str(ROOT / "target/debug/libworld_silo_bind.dylib"),
        SILO_IP="127.77.254.254",
        WORLD_SILO_ACTIVE="1",
        WORLD_SILO_ACK=str(ack),
        WORLD_TMP=str(root),
        **extra,
    )


def short_dir(prefix):
    """Short temp dir under $HOME (never /tmp): redirected socket paths embed
    it and sun_path is 104 bytes."""
    return tempfile.TemporaryDirectory(prefix=prefix, dir=str(pathlib.Path.home()))


def assert_owned(path, *roots):
    """Refuse to touch `path` unless its parent really lives inside one of the
    test-owned `roots` (same discipline as test_stress.assert_owned; only the
    parent is realpath'd so a symlink at `path` is never followed)."""
    path = str(path)
    parent = os.path.realpath(os.path.dirname(path) or ".")
    resolved = os.path.join(parent, os.path.basename(path))
    for root in roots:
        rroot = os.path.realpath(str(root))
        if resolved == rroot or resolved.startswith(rroot + os.sep):
            return
    raise AssertionError(
        f"refusing to touch {path!r} (resolved {resolved!r}): not under any of {[str(r) for r in roots]!r}"
    )


def owned_rmtree(path, *roots):
    assert_owned(path, *roots)
    shutil.rmtree(path, ignore_errors=True)


def kind_of(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return {"symlink": {"target": os.readlink(path)}}
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISSOCK(st.st_mode):
        return "socket"
    return {"file": {"len": st.st_size}}


def physical_tree(root):
    """Same JSON shape as `Model::tree_json`: sorted [{"path","kind"}]."""
    entries = []

    def walk(directory, prefix):
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            rel = f"{prefix}/{name}" if prefix else name
            kind = kind_of(full)
            entries.append({"path": rel, "kind": kind})
            if kind == "dir":
                walk(full, rel)

    root = str(root)
    if os.path.isdir(root) and not os.path.islink(root):
        walk(root, "")
    entries.sort(key=lambda e: e["path"])
    return entries


def canon_target(target, roots):
    """Spelling-insensitive form of an absolute symlink target: physical
    workspace roots map back to /tmp and /var/tmp, `..` is collapsed, and
    /private/{tmp,var} is folded (the shim reports host names, and the model
    keeps whatever text was written)."""
    for physical, virtual in roots:
        if target == physical or target.startswith(physical + "/"):
            target = virtual + target[len(physical):]
    target = os.path.normpath(target)
    for private in ("/private/tmp", "/private/var/tmp"):
        if target == private or target.startswith(private + "/"):
            target = target[len("/private"):]
    return target


def normalize_tree(entries, roots):
    out = []
    for e in entries:
        kind = e["kind"]
        if isinstance(kind, dict) and "symlink" in kind and kind["symlink"]["target"].startswith("/"):
            kind = {"symlink": {"target": canon_target(kind["symlink"]["target"], roots)}}
        out.append({"path": e["path"], "kind": kind})
    return out


def env_prefix(env):
    keys = ["DYLD_INSERT_LIBRARIES", "SILO_IP", "WORLD_SILO_ACTIVE", "WORLD_SILO_ACK", "WORLD_TMP"]
    return " ".join(f"{k}={env[k]}" for k in keys if env.get(k))


def report_failure(env, profile, seed, run_id, ops_file, result, phase, replay_prefix=None):
    """Save ops file, a minimized version, stdout/stderr under
    WORLD_FUZZ_ARTIFACTS; return a message with a copy-pasteable replay."""
    out = artifacts_dir()
    out.mkdir(parents=True, exist_ok=True)
    tag = f"{phase}-seed{seed}-{int(time.time())}"
    saved = out / f"{tag}.ops"
    if pathlib.Path(ops_file).exists():
        shutil.copy(ops_file, saved)
    minimized = out / f"{tag}.min.ops"
    ok_min = False
    if saved.exists() and replay_prefix is None:
        try:
            mr = run_timeout(
                [FUZZ_DRIVER, "minimize", saved, "--out", minimized, "--timeout", "15"], 180, env=env
            )
            ok_min = mr.returncode == 0 and minimized.exists()
        except subprocess.TimeoutExpired:
            pass
    (out / f"{tag}.stdout.txt").write_text(result.stdout)
    (out / f"{tag}.stderr.txt").write_text(result.stderr)
    target = minimized if ok_min else saved
    if replay_prefix is None:
        replay = f"{env_prefix(env)} {FUZZ_DRIVER} replay {target}"
    else:
        replay = f"{replay_prefix} replay {target}"
    return (
        f"{phase}: seed={seed} profile={profile} run_id={run_id} rc={result.returncode}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}\n"
        f"artifacts: {saved}{' ' + str(minimized) if ok_min else ''}\nreplay: {replay}"
    )


def run_args(profile, seed, run_id, ops_file):
    return [
        "run", "--profile", profile, "--seed", str(seed), "--ops", str(ops_count()),
        "--run-id", run_id, "--keep", "--out", ops_file,
    ]


class GuardProbes(unittest.TestCase):
    """The driver's own safety rules, exercised end to end."""

    def test_bad_run_ids_are_rejected(self):
        for bad in ["not-a-run-id", "fz-short", "fz-ABCDEF0123", "fz-0123456g", "../fz-01234567", ""]:
            with self.subTest(run_id=bad):
                r = run_timeout(
                    [FUZZ_DRIVER, "run", "--profile", "mac", "--seed", "1", "--ops", "1", "--run-id", bad], 10
                )
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertEqual(r.stdout, "")
                self.assertIn("invalid run id", r.stderr)

    def test_op_with_parent_outside_the_sandbox_is_refused_before_any_syscall(self):
        rid = fresh_run_id()
        victim = f"should-never-exist-{rid}"
        text = (
            f"# profile mac\n# seed 1\n# run-id {rid}\n# allow-escaping-links 0\n"
            f"mkdir /tmp/{rid} 755\nmkdir /var/tmp/{rid} 755\nchdir /tmp/{rid}\n"
            # Deliberately malicious: its parent is the shared host tmp root,
            # not this run's sandbox (`guarded_parent` in exec.rs must refuse).
            f"mkdir /tmp/{victim} 755\n"
            f"symlink x /tmp/{victim}-link\n"
        )
        with tempfile.TemporaryDirectory() as scratch:
            ops = pathlib.Path(scratch) / "evil.ops"
            ops.write_text(text)
            try:
                r = run_timeout([FUZZ_DRIVER, "replay", ops, "--run-id", rid], 20)
            finally:
                # The abort happens before the run's own cleanup: remove the
                # two sandbox roots (exact, freshly-random single components).
                for base in ["/private/tmp", "/tmp", "/private/var/tmp", "/var/tmp"]:
                    p = os.path.join(base, rid)
                    if os.path.basename(p) == rid and rid.startswith("fz-") and len(rid) == 35:
                        shutil.rmtree(p, ignore_errors=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("outside the sandbox", r.stderr)
        for base in ["/private/tmp", "/tmp", "/private/var/tmp", "/var/tmp"]:
            self.assertFalse(os.path.lexists(os.path.join(base, victim)), base)
            self.assertFalse(os.path.lexists(os.path.join(base, victim + "-link")), base)


@unittest.skipUnless(MACOS, "the silo shim is macOS-only")
class ShimFuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = short_dir(".wt-fuzz-")
        cls.root = pathlib.Path(cls.home.name) / "w"
        for sub in ["tmp", "var/tmp"]:
            (cls.root / sub).mkdir(parents=True)
        cls.ack = pathlib.Path(cls.home.name) / "ack"
        cls.ack.touch()
        cls.env = shim_env(cls.root, cls.ack)
        cls.sentinel = pathlib.Path(f"/private/tmp/fz-sentinel-{uuid.uuid4().hex[:8]}")
        cls.sentinel.mkdir()
        (cls.sentinel / "file").write_text("sentinel")
        cls.tmp_before = cls.host_fz("/private/tmp")
        cls.var_before = cls.host_fz("/private/var/tmp")

    @staticmethod
    def host_fz(base):
        try:
            return {n for n in os.listdir(base) if n.startswith("fz-")}
        except FileNotFoundError:
            return set()

    @classmethod
    def tearDownClass(cls):
        leaked_tmp = cls.host_fz("/private/tmp") - cls.tmp_before - {cls.sentinel.name}
        leaked_var = cls.host_fz("/private/var/tmp") - cls.var_before
        try:
            sentinel_ok = (cls.sentinel / "file").read_text() == "sentinel"
        except OSError:
            sentinel_ok = False
        owned_rmtree(cls.sentinel, cls.sentinel)
        cls.home.cleanup()
        if leaked_tmp or leaked_var or not sentinel_ok:
            raise AssertionError(
                f"host temp dirs were touched: new /private/tmp/fz-*={sorted(leaked_tmp)} "
                f"new /private/var/tmp/fz-*={sorted(leaked_var)} sentinel_ok={sentinel_ok}"
            )

    def cleanup_run(self, run_id):
        owned_rmtree(self.root / "tmp" / run_id, self.root)
        owned_rmtree(self.root / "var/tmp" / run_id, self.root)

    def check_tree(self, run_id, data):
        roots = [(str(self.root / "tmp"), "/tmp"), (str(self.root / "var/tmp"), "/var/tmp")]
        self.assertEqual(
            normalize_tree(physical_tree(self.root / "tmp" / run_id), roots),
            normalize_tree(data["model_tree"], roots),
            run_id,
        )

    def test_shim_matches_model_across_seeds(self):
        deadline = time.monotonic() + budget()
        seeds = seed_sequence()
        tried = 0
        with tempfile.TemporaryDirectory() as scratch:
            while time.monotonic() < deadline:
                seed = next(seeds)
                tried += 1
                run_id = fresh_run_id()
                ops_file = pathlib.Path(scratch) / f"{run_id}.ops"
                try:
                    result = run_timeout([FUZZ_DRIVER, *run_args("mac", seed, run_id, ops_file)], RUN_TIMEOUT, env=self.env)
                except subprocess.TimeoutExpired as e:
                    self.fail(f"fuzz_driver (seed={seed}) timed out: {e}")
                try:
                    if result.returncode != 0:
                        self.fail(report_failure(self.env, "mac", seed, run_id, ops_file, result, "shim"))
                    data = json.loads(result.stdout)
                    self.assertEqual(data["result"], "pass")
                    # The shim wrote its injection acknowledgement, so this
                    # run really went through the redirection.
                    self.assertEqual(self.ack.read_text(), "world-silo-v1")
                    self.check_tree(run_id, data)
                finally:
                    self.cleanup_run(run_id)
        self.assertGreater(tried, 0)

    def test_corpus_replay(self):
        files = sorted(CORPUS.glob("*.ops"))
        if not files:
            self.skipTest("no corpus files")
        for ops_file in files:
            with self.subTest(file=ops_file.name):
                run_id = fresh_run_id()
                try:
                    result = run_timeout([FUZZ_DRIVER, "replay", ops_file, "--run-id", run_id, "--keep"], RUN_TIMEOUT, env=self.env)
                    if ops_file.name.startswith("known-"):
                        # A documented, referenced product finding: replay is
                        # expected to keep diverging until it is fixed.
                        self.assertEqual(result.returncode, 1, f"{ops_file.name}: rc={result.returncode} {result.stderr}")
                        continue
                    self.assertEqual(result.returncode, 0, f"{ops_file.name}: {result.stdout} {result.stderr}")
                    self.check_tree(run_id, json.loads(result.stdout))
                finally:
                    self.cleanup_run(run_id)


class ExecFuzzMixin:
    """Shared loop for the two `world exec` based classes."""

    profile = None
    world_name = "F"

    def command(self, *args):
        return [WORLD, "exec", self.world_name, "--state-dir", self.state, "--timeout", "60s", "--", FUZZ_DRIVER, *args]

    def temp_root(self):
        raise NotImplementedError

    def fuzz_loop(self, phase):
        deadline = time.monotonic() + budget()
        seeds = seed_sequence()
        troot = self.temp_root()
        tried = 0
        # The driver writes its op log from inside the workspace, where /tmp
        # is private, so the scratch dir must live outside host /tmp.
        (ROOT / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="world-fuzz-ops-", dir=ROOT / "target") as scratch:
            while time.monotonic() < deadline:
                seed = next(seeds)
                tried += 1
                run_id = fresh_run_id()
                ops_file = pathlib.Path(scratch) / f"{run_id}.ops"
                try:
                    result = run_timeout(self.command(*run_args(self.profile, seed, run_id, ops_file)), RUN_TIMEOUT + 60)
                except subprocess.TimeoutExpired as e:
                    self.fail(f"fuzz_driver via world exec (seed={seed}) timed out: {e}")
                try:
                    if result.returncode != 0:
                        prefix = " ".join(str(x) for x in self.command())
                        self.fail(report_failure({}, self.profile, seed, run_id, ops_file, result, phase, replay_prefix=prefix))
                    data = json.loads(result.stdout)
                    self.assertEqual(data["result"], "pass")
                    roots = [(str(troot / "tmp"), "/tmp"), (str(troot / "var/tmp"), "/var/tmp")]
                    self.assertEqual(
                        normalize_tree(physical_tree(troot / "tmp" / run_id), roots),
                        normalize_tree(data["model_tree"], roots),
                        run_id,
                    )
                finally:
                    owned_rmtree(troot / "tmp" / run_id, troot)
                    owned_rmtree(troot / "var/tmp" / run_id, troot)
        self.assertGreater(tried, 0)


@unittest.skipUnless(LINUX, "Linux World namespaces")
class LinuxFuzz(ExecFuzzMixin, unittest.TestCase):
    profile = "linux"

    @classmethod
    def setUpClass(cls):
        # Workspaces refuse workdirs under /tmp and record their private /tmp
        # under HOME: keep both inside the build tree (LinuxWorkspace pattern).
        (ROOT / "target").mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="world-fuzz-test-", dir=ROOT / "target")
        cls.root = pathlib.Path(cls.temp.name)
        cls.state = cls.root / "state"
        cls.home = os.environ.get("HOME")
        os.environ["HOME"] = str(cls.root / "home")
        (cls.root / "home").mkdir()
        work = cls.root / "F"
        work.mkdir()
        try:
            for action in [["create", "F", "--workdir", work], ["setup", "F"]]:
                result = run_timeout([WORLD, "workspace", "--state-dir", cls.state, *action], 30)
                if result.returncode:
                    raise AssertionError(result.stderr)
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            run_timeout([WORLD, "workspace", "--state-dir", cls.state, "teardown", "F"], 30)
        finally:
            if cls.home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = cls.home
            cls.temp.cleanup()

    def temp_root(self):
        result = run_timeout([WORLD, "workspace", "--state-dir", self.state, "show", "F"], 15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return pathlib.Path(json.loads(result.stdout)["temp_root"])

    def test_linux_matches_model_across_seeds(self):
        self.fuzz_loop("linux")


@unittest.skipUnless(MACOS and os.environ.get("WORLD_SILO_INTEGRATION") == "1", "requires WORLD_SILO_INTEGRATION=1 (real loopback alias)")
class PrivilegedExecFuzz(ExecFuzzMixin, unittest.TestCase):
    profile = "mac"

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="world-fuzz-silo-")
        cls.root = pathlib.Path(cls.temp.name)
        cls.state = cls.root / "state"
        work = cls.root / "F"
        work.mkdir()
        result = run_timeout([WORLD, "workspace", "--state-dir", cls.state, "create", "F", "--workdir", work], 15)
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError(result.stderr)
        cls.info = json.loads(result.stdout)
        # CI runner has passwordless sudo. Never alter sudoers or /etc/hosts.
        subprocess.run(
            ["sudo", "-n", "/sbin/ifconfig", "lo0", "alias", cls.info["ip"], "netmask", "255.0.0.0"],
            check=True, timeout=10, stdin=subprocess.DEVNULL,
        )

    @classmethod
    def tearDownClass(cls):
        try:
            shutil.rmtree(pathlib.Path(cls.info["temp_root"]), ignore_errors=True)
        finally:
            try:
                subprocess.run(
                    ["sudo", "-n", "/sbin/ifconfig", "lo0", "-alias", cls.info["ip"]],
                    check=True, timeout=10, stdin=subprocess.DEVNULL,
                )
            finally:
                cls.temp.cleanup()

    def temp_root(self):
        return pathlib.Path(self.info["temp_root"])

    def test_exec_matches_model_across_seeds(self):
        self.fuzz_loop("exec")


if __name__ == "__main__":
    unittest.main()
