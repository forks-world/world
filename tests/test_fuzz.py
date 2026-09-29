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
    """WORLD_FUZZ_SEED (if set) or the fixed default seeds first, then more
    seeds for as long as the caller's deadline allows. The follow-on stream
    is derived from WORLD_FUZZ_SEED (nightly: the run id) or from a fixed
    value, so PR runs are deterministic and every run is reproducible."""
    base = os.environ.get("WORLD_FUZZ_SEED")
    if base:
        yield int(base)
    else:
        yield from DEFAULT_SEEDS
    rng = random.Random(int(base) if base else 0)
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


def check_trees(phys_root, run_id, data):
    """Compare the physical `/tmp/<run>` and `/var/tmp/<run>` trees under a
    workspace's physical root with the model's trees from the driver's JSON
    (`model_tree`, and `model_var_tree` when present). Raises
    AssertionError naming the root that differs."""
    phys_root = pathlib.Path(phys_root)
    roots = [(str(phys_root / "tmp"), "/tmp"), (str(phys_root / "var/tmp"), "/var/tmp")]
    pairs = [("tmp", "model_tree")]
    if "model_var_tree" in data:
        pairs.append(("var/tmp", "model_var_tree"))
    for sub, key in pairs:
        real = normalize_tree(physical_tree(phys_root / sub / run_id), roots)
        model = normalize_tree(data[key], roots)
        if real != model:
            raise AssertionError(f"/{sub}/{run_id} tree differs: physical={real!r} model={model!r}")


def escape_op_path(path):
    """The `.ops` text escaping: %XX for anything outside [A-Za-z0-9._/-]."""
    out = []
    for b in os.fsencode(str(path)):
        c = chr(b)
        out.append(c if (c.isascii() and (c.isalnum() or c in "._/-")) else f"%{b:02x}")
    return "".join(out)


class HostTempGuard:
    """Shared by every class that runs the driver: a sentinel dir plus a
    before/after listing of the *host* temp dirs, so a run that escaped its
    redirection (created host `fz-*` entries or touched the sentinel) fails
    the class instead of silently polluting the machine."""

    host_bases = ("/private/tmp", "/private/var/tmp") if MACOS else ("/tmp", "/var/tmp")

    @staticmethod
    def host_fz(base):
        try:
            return {n for n in os.listdir(base) if n.startswith("fz-")}
        except FileNotFoundError:
            return set()

    @classmethod
    def guard_start(cls):
        cls.guard_sentinel = pathlib.Path(cls.host_bases[0]) / f"fz-sentinel-{uuid.uuid4().hex[:8]}"
        cls.guard_sentinel.mkdir()
        (cls.guard_sentinel / "file").write_text("sentinel")
        cls.guard_before = {b: cls.host_fz(b) for b in cls.host_bases}

    @classmethod
    def guard_finish(cls):
        """Clean up and report; call last in tearDownClass. Tolerates a
        guard_start that never ran."""
        sentinel = getattr(cls, "guard_sentinel", None)
        if sentinel is None:
            return
        cls.guard_sentinel = None
        leaked = {}
        for base in cls.host_bases:
            new = cls.host_fz(base) - cls.guard_before.get(base, set())
            new.discard(sentinel.name)
            if new:
                leaked[base] = sorted(new)
        try:
            sentinel_ok = (sentinel / "file").read_text() == "sentinel"
        except OSError:
            sentinel_ok = False
        owned_rmtree(sentinel, sentinel)
        if leaked or not sentinel_ok:
            raise AssertionError(f"host temp dirs were touched: new fz-* entries={leaked} sentinel_ok={sentinel_ok}")


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

    @staticmethod
    def remove_roots(rid):
        """Remove the two sandbox roots of a run (exact, freshly-random single
        components) after an abort that skipped the run's own cleanup."""
        for base in ["/private/tmp", "/tmp", "/private/var/tmp", "/var/tmp"]:
            p = os.path.join(base, rid)
            if os.path.basename(p) == rid and rid.startswith("fz-") and len(rid) == 35:
                shutil.rmtree(p, ignore_errors=True)

    def test_opens_that_could_write_outside_the_sandbox_are_refused(self):
        """Every mutating open form aimed (directly, through a dirfd, or via
        a symlink in the final component) at a host file is refused before
        the syscall: the victim is never truncated, written or created."""
        with tempfile.TemporaryDirectory() as scratch:
            victim = pathlib.Path(scratch) / "victim"
            victim.write_text("precious")
            os.utime(victim, (1_000_000_000, 1_000_000_000))
            before = (victim.read_bytes(), victim.stat().st_mtime_ns)
            new = pathlib.Path(scratch) / "new"
            v = escape_op_path(victim)
            vrel = escape_op_path(str(victim).lstrip("/"))
            n = escape_op_path(new)

            def cases(rid):
                return {
                    "write-trunc": [f"open {v} 001100", "write 3 x"],
                    "write-only": [f"open {v} 000100"],
                    "dirfd-openat": ["opendir /", f"openat 3 {vrel} 001100"],
                    "symlink-to-file": [f"symlink {v} /tmp/{rid}/l", f"open /tmp/{rid}/l 001100"],
                    "dangling-symlink-create": [f"symlink {n} /tmp/{rid}/d", f"open /tmp/{rid}/d 100100"],
                }

            for name in cases("fz-00000000"):
                with self.subTest(case=name):
                    rid = fresh_run_id()
                    text = (
                        f"# profile mac\n# seed 1\n# run-id {rid}\n# allow-escaping-links 0\n"
                        f"mkdir /tmp/{rid} 755\nmkdir /var/tmp/{rid} 755\nchdir /tmp/{rid}\n"
                        + "".join(line + "\n" for line in cases(rid)[name])
                    )
                    ops = pathlib.Path(scratch) / f"{name}.ops"
                    ops.write_text(text)
                    try:
                        r = run_timeout([FUZZ_DRIVER, "replay", ops, "--run-id", rid], 20)
                    finally:
                        self.remove_roots(rid)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertIn("outside the sandbox", r.stderr)
                    self.assertEqual((victim.read_bytes(), victim.stat().st_mtime_ns), before)
                    self.assertFalse(os.path.lexists(new))

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
                # The abort happens before the run's own cleanup.
                self.remove_roots(rid)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("outside the sandbox", r.stderr)
        for base in ["/private/tmp", "/tmp", "/private/var/tmp", "/var/tmp"]:
            self.assertFalse(os.path.lexists(os.path.join(base, victim)), base)
            self.assertFalse(os.path.lexists(os.path.join(base, victim + "-link")), base)


class CheckTrees(unittest.TestCase):
    """`check_trees` compares *both* sandbox roots (pure, no driver)."""

    def test_var_tmp_tree_is_compared(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            rid = "fz-00000000"
            (root / "tmp" / rid).mkdir(parents=True)
            (root / "var/tmp" / rid).mkdir(parents=True)
            data = {"model_tree": [], "model_var_tree": []}
            check_trees(root, rid, data)
            (root / "var/tmp" / rid / "extra").write_text("x")
            with self.assertRaises(AssertionError):
                check_trees(root, rid, data)
            # An old driver without `model_var_tree` still compares /tmp only.
            check_trees(root, rid, {"model_tree": []})
            (root / "tmp" / rid / "extra").write_text("x")
            with self.assertRaises(AssertionError):
                check_trees(root, rid, {"model_tree": []})


@unittest.skipUnless(MACOS, "the silo shim is macOS-only")
class ShimFuzz(HostTempGuard, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = short_dir(".wt-fuzz-")
        cls.root = pathlib.Path(cls.home.name) / "w"
        for sub in ["tmp", "var/tmp"]:
            (cls.root / sub).mkdir(parents=True)
        cls.ack = pathlib.Path(cls.home.name) / "ack"
        cls.ack.touch()
        cls.env = shim_env(cls.root, cls.ack)
        cls.guard_start()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.home.cleanup()
        finally:
            cls.guard_finish()

    def cleanup_run(self, run_id):
        owned_rmtree(self.root / "tmp" / run_id, self.root)
        owned_rmtree(self.root / "var/tmp" / run_id, self.root)

    def check_tree(self, run_id, data):
        check_trees(self.root, run_id, data)

    def test_var_tmp_mismatch_is_detected(self):
        """A stray physical file under /var/tmp/<run> must fail the tree
        comparison even though /tmp/<run> still agrees."""
        ops_file = CORPUS / "seed-var-tmp.ops"
        run_id = fresh_run_id()
        try:
            result = run_timeout([FUZZ_DRIVER, "replay", ops_file, "--run-id", run_id, "--keep"], RUN_TIMEOUT, env=self.env)
            self.assertEqual(result.returncode, 0, f"{result.stdout} {result.stderr}")
            data = json.loads(result.stdout)
            self.assertIn("model_var_tree", data)
            self.assertTrue(data["model_var_tree"], "the corpus file must populate /var/tmp")
            self.check_tree(run_id, data)
            (self.root / "var/tmp" / run_id / "stray").write_text("x")
            with self.assertRaises(AssertionError):
                self.check_tree(run_id, data)
        finally:
            self.cleanup_run(run_id)

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


class ExecFuzzMixin(HostTempGuard):
    """Shared loop for the two `world exec` based classes (also carries the
    host-temp leak/sentinel guard: call `guard_start()` first in setUpClass
    and `guard_finish()` last in tearDownClass)."""

    profile = None
    world_name = "F"
    child_env = None  # environment for the world/driver children (None: inherit)

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
                    result = run_timeout(self.command(*run_args(self.profile, seed, run_id, ops_file)), RUN_TIMEOUT + 60, env=self.child_env)
                except subprocess.TimeoutExpired as e:
                    self.fail(f"fuzz_driver via world exec (seed={seed}) timed out: {e}")
                try:
                    if result.returncode != 0:
                        prefix = " ".join(str(x) for x in self.command())
                        self.fail(report_failure({}, self.profile, seed, run_id, ops_file, result, phase, replay_prefix=prefix))
                    data = json.loads(result.stdout)
                    self.assertEqual(data["result"], "pass")
                    check_trees(troot, run_id, data)
                finally:
                    owned_rmtree(troot / "tmp" / run_id, troot)
                    owned_rmtree(troot / "var/tmp" / run_id, troot)
        self.assertGreater(tried, 0)


@unittest.skipUnless(LINUX, "Linux World namespaces")
class LinuxFuzz(ExecFuzzMixin, unittest.TestCase):
    profile = "linux"

    @classmethod
    def setUpClass(cls):
        cls.guard_start()
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
            try:
                cls.temp.cleanup()
            finally:
                cls.guard_finish()

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
        cls.guard_start()
        cls.temp = tempfile.TemporaryDirectory(prefix="world-fuzz-silo-")
        cls.root = pathlib.Path(cls.temp.name)
        cls.state = cls.root / "state"
        # A dedicated HOME (short, under the real HOME, never /tmp): the
        # workspace's temp root (~/.world/tmp/<ip>) must land in a
        # test-owned dir, never under the real developer/CI HOME.
        cls.home_dir = short_dir(".wt-fuzz-silo-")
        cls.home = pathlib.Path(cls.home_dir.name)
        cls.child_env = dict(os.environ, HOME=str(cls.home))
        work = cls.root / "F"
        work.mkdir()
        result = run_timeout(
            [WORLD, "workspace", "--state-dir", cls.state, "create", "F", "--workdir", work], 15, env=cls.child_env
        )
        if result.returncode:
            cls.temp.cleanup()
            cls.home_dir.cleanup()
            cls.guard_finish()
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
            owned_rmtree(pathlib.Path(cls.info["temp_root"]), cls.home)
        finally:
            try:
                subprocess.run(
                    ["sudo", "-n", "/sbin/ifconfig", "lo0", "-alias", cls.info["ip"]],
                    check=True, timeout=10, stdin=subprocess.DEVNULL,
                )
            finally:
                try:
                    cls.temp.cleanup()
                    cls.home_dir.cleanup()
                finally:
                    cls.guard_finish()

    def temp_root(self):
        return pathlib.Path(self.info["temp_root"])

    def test_exec_matches_model_across_seeds(self):
        self.fuzz_loop("exec")


if __name__ == "__main__":
    unittest.main()
