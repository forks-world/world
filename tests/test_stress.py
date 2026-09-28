"""Stress/concurrency tests for the workspace registry, temp-root hardening,
and the macOS silo shim's threaded storms.

Tiers:
  default (no env)     -- smoke: fixed seeds, small counts, ~20s total.
  WORLD_STRESS=1        -- full tier (bigger counts/durations).
  WORLD_STRESS_SCALE=N  -- multiplies full-tier iteration/duration counts.

    cargo build --workspace --examples
    python3 -m unittest tests.test_stress -v
    WORLD_STRESS=1 python3 -m unittest tests.test_stress -v
"""

import concurrent.futures
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

# Importable both as `tests.test_stress` (sibling `test_runtime` not on
# sys.path) and via `unittest discover -s tests` (this file's own directory
# is sys.path[0], so a bare `test_runtime` already resolves): make sure the
# directory this file actually lives in is always on sys.path first.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_runtime import PROBE, ROOT, WORLD  # noqa: E402

STRESS_PROBE = ROOT / "target/debug/examples/stress_probe"
MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
STRESS = bool(os.environ.get("WORLD_STRESS"))
SCALE = max(1, int(os.environ.get("WORLD_STRESS_SCALE", "1")))
ARTIFACTS = ROOT / "target/fuzz-artifacts"


def n(smoke, full):
    """Smoke-tier count, or the (scaled) full-tier count under WORLD_STRESS."""
    return full * SCALE if STRESS else smoke


def run_timeout(args, timeout, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(
        [str(x) for x in args], capture_output=True, text=True, timeout=timeout, **kwargs
    )


def run_with_sample(args, timeout, name, **kwargs):
    """Like `run_timeout`, but on a macOS timeout captures `sample <pid> 1`
    into target/fuzz-artifacts/ before failing, so a real hang leaves a
    diagnosable trace instead of a bare TimeoutExpired.
    """
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    proc = subprocess.Popen(
        [str(x) for x in args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kwargs,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        sampled = None
        sample_bin = "/usr/bin/sample"
        if MACOS and os.path.exists(sample_bin):
            ARTIFACTS.mkdir(parents=True, exist_ok=True)
            sampled = ARTIFACTS / f"{name}-{proc.pid}-{int(time.time())}.txt"
            try:
                with open(sampled, "w") as out:
                    subprocess.run(
                        [sample_bin, str(proc.pid), "1"],
                        stdout=out,
                        stderr=subprocess.STDOUT,
                        timeout=15,
                    )
            except Exception:
                pass
        proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        raise AssertionError(
            f"{name} timed out after {timeout}s"
            + (f" (sample saved to {sampled})" if sampled else "")
            + f"; stdout={stdout!r} stderr={stderr!r}"
        )
    return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)


def shim_env(root, ack, **extra):
    """Copied from test_runtime.CLI.shim_env: the macOS silo-bind injection
    recipe, standalone so this module never imports a TestCase."""
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
    """A short-named temp dir under $HOME (never under /tmp): required for
    HOME/workdir on macOS, since world refuses either under a host temp dir,
    and kept short because redirected socket paths embed it (sun_path is 104
    bytes)."""
    return tempfile.TemporaryDirectory(prefix=prefix, dir=str(pathlib.Path.home()))


def write_json(path, obj):
    path.write_text(json.dumps(obj))


def assert_owned(path, *roots):
    """Refuse to touch `path` unless it is genuinely inside one of `roots`
    (each a test-owned temp dir: a short_dir `.wt-*` HOME, a tempfile.
    TemporaryDirectory, or a WORLD_TMP root). Every rmtree/remove/rename/
    move in this file calls this first on every path it touches, so a bug
    (or an unexpected race outcome) handing a destructive call a wider path
    than intended fails loudly instead of deleting something real.

    Only the path's *parent* is realpath'd: if `path` itself is currently a
    symlink (as it is mid-race in TempRootSymlinkRace), this checks where
    the symlink itself lives, never where it points -- removing a symlink
    never follows it, and this check must not either.
    """
    path = str(path)
    parent = os.path.realpath(os.path.dirname(path) or ".")
    resolved = os.path.join(parent, os.path.basename(path))
    for root in roots:
        rroot = os.path.realpath(str(root))
        if resolved == rroot or resolved.startswith(rroot + os.sep):
            return
    raise AssertionError(
        f"refusing to touch {path!r} (resolved {resolved!r}): "
        f"not under any of {[str(r) for r in roots]!r}"
    )


def owned_remove(path, *roots):
    assert_owned(path, *roots)
    os.remove(path)


def owned_rmtree(path, *roots):
    assert_owned(path, *roots)
    shutil.rmtree(path, ignore_errors=True)


def owned_rename(src, dst, *roots):
    assert_owned(src, *roots)
    assert_owned(dst, *roots)
    os.rename(src, dst)


def owned_move(src, dst, *roots):
    assert_owned(src, *roots)
    assert_owned(dst, *roots)
    shutil.move(str(src), str(dst))


def old_dir(home):
    return home / ".local/share/world/silo"


def new_dir(home):
    return home / ".local/share/world/workspaces"


# ---------------------------------------------------------------------------
# 1. registry concurrent create


@unittest.skipUnless(MACOS or LINUX, "workspace localhost isolation requires macOS or Linux")
class RegistryConcurrentCreate(unittest.TestCase):
    def test_registry_concurrent_create(self):
        procs = n(8, 32)
        ids = ["A", "B", "C", "D", "E", "F"]
        rng = random.Random(20240921)
        n_states = rng.choice([1, 2, 3])

        with short_dir(".wt-reg-home-") as home_dir:
            home = pathlib.Path(home_dir)
            workdirs = {}
            for id_ in ids:
                d = home / f"work-{id_}"
                d.mkdir()
                workdirs[id_] = d
            state_dirs = [home / f"state{i}" for i in range(n_states)]
            env = dict(os.environ, HOME=str(home))

            tasks = []
            for _ in range(procs):
                id_ = rng.choice(ids)
                state = rng.choice(state_dirs)
                # Mostly the id's own workdir (the common case), occasionally
                # another id's, to exercise the documented "belongs to
                # another workdir" rejection under real concurrency.
                workdir = (
                    workdirs[id_] if rng.random() < 0.8 else rng.choice(list(workdirs.values()))
                )
                tasks.append((id_, state, workdir))

            def create(task):
                id_, state, workdir = task
                return run_timeout(
                    [WORLD, "workspace", "--state-dir", state, "create", id_, "--workdir", workdir],
                    timeout=30,
                    env=env,
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, procs)) as pool:
                results = list(pool.map(create, tasks))

            for result in results:
                if result.returncode != 0:
                    self.assertIn("belongs to another workdir", result.stderr, result.stderr)

            all_temp_roots = []
            for state in state_dirs:
                reg_path = state / "registry.json"
                if not reg_path.exists():
                    continue
                registry = json.loads(reg_path.read_text())
                registry_id = json.loads((state / "registry-id").read_text())

                ips = [w["ip"] for w in registry.values()]
                self.assertEqual(
                    len(ips), len(set(ips)), f"duplicate ip within a registry at {state}"
                )
                for id_, world in registry.items():
                    self.assertEqual(world["id"], id_)
                    self.assertIn("temp_root", world, world)
                    root = pathlib.Path(world["temp_root"])
                    all_temp_roots.append(world["temp_root"])
                    marker = root / "owner"
                    self.assertTrue(marker.exists(), marker)
                    expected_owner = f"{registry_id}\n{id_}\n".encode()
                    self.assertEqual(marker.read_bytes(), expected_owner)

            self.assertEqual(
                len(all_temp_roots),
                len(set(all_temp_roots)),
                "a temp root was shared across distinct registries",
            )


# ---------------------------------------------------------------------------
# 2. legacy registry fill under concurrent show


@unittest.skipUnless(MACOS or LINUX, "workspace localhost isolation requires macOS or Linux")
class LegacyFillConcurrentShow(unittest.TestCase):
    def test_legacy_fill_concurrent_show(self):
        concurrency = n(6, 16)
        with short_dir(".wt-legacy-show-") as home_dir, tempfile.TemporaryDirectory() as state_dir:
            home = pathlib.Path(home_dir)
            state = pathlib.Path(state_dir)
            work = home / "work"
            work.mkdir()
            state.mkdir(exist_ok=True)
            write_json(
                state / "registry.json",
                {"L": {"id": "L", "ip": "127.77.0.9", "workdir": str(work)}},
            )
            env = dict(os.environ, HOME=str(home))

            def show(_):
                return run_timeout(
                    [WORLD, "workspace", "--state-dir", state, "show", "L"], timeout=20, env=env
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                results = list(pool.map(show, range(concurrency)))

            for result in results:
                self.assertEqual(result.returncode, 0, result.stderr)
            temp_roots = {json.loads(r.stdout)["temp_root"] for r in results}
            self.assertEqual(len(temp_roots), 1, temp_roots)

            registry = json.loads((state / "registry.json").read_text())
            self.assertEqual(registry["L"]["temp_root"], next(iter(temp_roots)))


# ---------------------------------------------------------------------------
# 3. default-state-dir migration crash states


@unittest.skipUnless(MACOS or LINUX, "workspace localhost isolation requires macOS or Linux")
class MigrationCrashStates(unittest.TestCase):
    def _seed(self, home, id_, work):
        old = old_dir(home)
        old.mkdir(parents=True)
        write_json(old / "registry.json", {id_: {"id": id_, "ip": "127.77.0.9", "workdir": str(work)}})
        write_json(old / "holders.json", {})
        write_json(old / "registry-id", "a" * 32)
        return old

    def test_migration_crash_states(self):
        concurrency = n(4, 16)
        id_ = "L"
        # Every intermediate state a SIGKILL could leave, derived from
        # default_state_dir_in's rename order (registry-id, then
        # registry.json, then holders.json -- see crates/world-runtime/src/
        # silo.rs), plus the "new already has its own registry" case where
        # nothing should move at all.
        scenarios = [
            "nothing_moved",
            "id_moved",
            "id_and_registry_moved",
            "fully_migrated",
            "new_has_different_registry",
        ]
        for scenario in scenarios:
            with self.subTest(scenario=scenario), short_dir(".wt-migrate-") as home_dir:
                home = pathlib.Path(home_dir)
                work = home / "work"
                work.mkdir()
                old = self._seed(home, id_, work)
                new = new_dir(home)

                if scenario == "nothing_moved":
                    pass
                elif scenario == "id_moved":
                    new.mkdir(parents=True)
                    owned_move(old / "registry-id", new / "registry-id", home)
                elif scenario == "id_and_registry_moved":
                    new.mkdir(parents=True)
                    owned_move(old / "registry-id", new / "registry-id", home)
                    owned_move(old / "registry.json", new / "registry.json", home)
                elif scenario == "fully_migrated":
                    new.mkdir(parents=True)
                    owned_move(old / "registry-id", new / "registry-id", home)
                    owned_move(old / "registry.json", new / "registry.json", home)
                    owned_move(old / "holders.json", new / "holders.json", home)
                elif scenario == "new_has_different_registry":
                    new.mkdir(parents=True)
                    other = home / "other-work"
                    other.mkdir()
                    write_json(
                        new / "registry.json",
                        {"M": {"id": "M", "ip": "127.77.0.1", "workdir": str(other)}},
                    )

                old_registry_before = (
                    (old / "registry.json").read_bytes() if (old / "registry.json").exists() else None
                )
                old_holders_before = (
                    (old / "holders.json").read_bytes() if (old / "holders.json").exists() else None
                )
                env = dict(os.environ, HOME=str(home))

                def show(_):
                    return run_timeout([WORLD, "workspace", "show", id_], timeout=20, env=env)

                with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                    results = list(pool.map(show, range(concurrency)))

                if scenario == "new_has_different_registry":
                    for r in results:
                        self.assertNotEqual(r.returncode, 0)
                        self.assertIn("unknown workspace", r.stderr, r.stderr)
                    # Nothing should have moved: `new` already had its own
                    # (unrelated) registry, so the legacy one is left alone.
                    self.assertEqual((old / "registry.json").read_bytes(), old_registry_before)
                    self.assertEqual((old / "holders.json").read_bytes(), old_holders_before)
                    self.assertTrue((old / "registry-id").exists())
                    self.assertFalse((new / "holders.json").exists())
                    new_registry = json.loads((new / "registry.json").read_text())
                    self.assertIn("M", new_registry)
                    continue

                for r in results:
                    self.assertEqual(r.returncode, 0, r.stderr)
                temp_roots = {json.loads(r.stdout)["temp_root"] for r in results}
                self.assertEqual(len(temp_roots), 1, temp_roots)

                # Exactly one registry, at the new location; id and contents
                # preserved; holders moved alongside it.
                self.assertFalse((old / "registry.json").exists())
                self.assertFalse((old / "registry-id").exists())
                self.assertFalse((old / "holders.json").exists())
                registry = json.loads((new / "registry.json").read_text())
                self.assertEqual(set(registry), {id_})
                self.assertEqual(registry[id_]["workdir"], str(work))
                self.assertEqual(registry[id_]["temp_root"], next(iter(temp_roots)))
                self.assertTrue((new / "holders.json").exists())
                self.assertEqual(json.loads((new / "holders.json").read_text()), {})

        if not STRESS:
            return
        # Full tier: repeatedly SIGKILL a first-time `show` mid-migration and
        # confirm the very next run always recovers to a correct, single
        # registry -- regardless of exactly when the kill landed.
        rng = random.Random(4242)
        for _ in range(50 * SCALE):
            with short_dir(".wt-migrate-kill-") as home_dir:
                home = pathlib.Path(home_dir)
                work = home / "work"
                work.mkdir()
                self._seed(home, id_, work)
                env = dict(os.environ, HOME=str(home))
                proc = subprocess.Popen(
                    [str(WORLD), "workspace", "show", id_],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                try:
                    time.sleep(rng.uniform(0, 0.02))
                finally:
                    proc.kill()
                    try:
                        proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate(timeout=5)

                result = run_timeout([WORLD, "workspace", "show", id_], timeout=20, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                info = json.loads(result.stdout)
                self.assertEqual(info["id"], id_)
                self.assertEqual(info["workdir"], str(work))
                registry = json.loads((new_dir(home) / "registry.json").read_text())
                self.assertEqual(set(registry), {id_})


# ---------------------------------------------------------------------------
# 4. temp-root symlink race


@unittest.skipUnless(
    MACOS, "temp-root re-hardening without privilege is exercised via world exec's alias check, macOS-only"
)
class TempRootSymlinkRace(unittest.TestCase):
    def test_temp_root_symlink_race(self):
        race_seconds = n(2, 8)
        exec_workers = n(3, 10)

        with short_dir(".wt-symlink-race-") as home_dir:
            home = pathlib.Path(home_dir)
            work = home / "work"
            work.mkdir()
            state = home / "state"
            env = dict(os.environ, HOME=str(home))

            result = run_timeout(
                [WORLD, "workspace", "--state-dir", state, "create", "R", "--workdir", work],
                timeout=20,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            root = pathlib.Path(json.loads(result.stdout)["temp_root"])
            # The attacker below renames/symlinks/rmtrees under `root`: prove
            # it is genuinely inside our own throwaway HOME before trusting
            # it with anything destructive (see `assert_owned`).
            assert_owned(root, home)
            self.assertTrue((root / "tmp").is_dir())

            decoy = home / "decoy"
            decoy.mkdir()
            os.chmod(decoy, 0o755)
            sentinel = decoy / "sentinel"
            sentinel.write_text("decoy-untouched")

            stop = threading.Event()
            failures = []
            lock = threading.Lock()

            def attacker():
                # Concurrent `world exec` runs can re-materialize a component
                # (via temp_root_in's mkdirat) in the exact window it is
                # swapped out, so every step here tolerates the name already
                # being in an unexpected state: a stale backup from a prior
                # cycle, a symlink left by a previous failed attempt, or
                # `real` reappearing as a fresh real directory before it is
                # restored. An OSError from that race is expected noise and
                # swallowed; an AssertionError from `owned_*` (a path that
                # somehow is not under `home`) is never expected and is
                # fatal -- it stops the whole race immediately rather than
                # being swallowed like ordinary race noise. Every
                # remove/rmtree/rename below goes through the `owned_*`
                # helpers, which never follow a symlink to decide whether the
                # *name itself* is owned (removing a symlink never follows
                # it either).
                components = ("tmp", "var", "var/tmp")

                def cleanup(real, backup):
                    try:
                        if real.is_symlink():
                            owned_remove(real, home)
                        if backup.exists() and real.exists() and not real.is_symlink():
                            owned_rmtree(real, home)
                        if backup.exists() and not real.exists():
                            owned_rename(backup, real, home)
                    except OSError:
                        pass
                    except AssertionError as e:
                        with lock:
                            failures.append(f"attacker safety check failed (cleanup): {e}")
                        stop.set()

                while not stop.is_set():
                    for name in components:
                        real = root / name
                        backup = root / f".backup-{name.replace('/', '_')}"
                        try:
                            if backup.is_symlink():
                                owned_remove(backup, home)
                            elif backup.exists():
                                owned_rmtree(backup, home)
                            if real.is_symlink():
                                owned_remove(real, home)
                            if not real.is_dir():
                                continue  # not built (yet) by a racing create/exec
                            owned_rename(real, backup, home)
                            os.symlink(decoy, real)
                            time.sleep(0.002)
                        except OSError:
                            pass
                        except AssertionError as e:
                            with lock:
                                failures.append(f"attacker safety check failed: {e}")
                            stop.set()
                            return
                        finally:
                            cleanup(real, backup)

            def exec_worker():
                while not stop.is_set():
                    try:
                        run_with_sample(
                            [
                                WORLD,
                                "exec",
                                "R",
                                "--state-dir",
                                state,
                                "--timeout",
                                "5s",
                                "--",
                                STRESS_PROBE,
                                "report",
                                "race",
                            ],
                            timeout=15,
                            name="symlink-race-exec",
                            env=env,
                        )
                    except AssertionError as e:
                        with lock:
                            failures.append(str(e))
                    # Anything else (alias-not-configured, a transient
                    # symlink error from the mid-swap window) is expected
                    # race noise; only a hang is a real bug here.

            def create_worker():
                while not stop.is_set():
                    run_timeout(
                        [WORLD, "workspace", "--state-dir", state, "create", "R", "--workdir", work],
                        timeout=15,
                        env=env,
                    )

            threads = (
                [threading.Thread(target=attacker)]
                + [threading.Thread(target=exec_worker) for _ in range(exec_workers)]
                + [threading.Thread(target=create_worker)]
            )
            for t in threads:
                t.start()
            try:
                time.sleep(race_seconds)
            finally:
                # Always stop and join every thread, even if something above
                # raised: no test may leave a background thread (and the
                # subprocesses it keeps spawning) running past its own body.
                stop.set()
                for t in threads:
                    t.join(timeout=30)

            self.assertEqual(failures, [], failures)

            # Post-race invariants only (interleaving-dependent behavior
            # during the race itself is not asserted on).
            self.assertEqual(os.stat(decoy).st_mode & 0o777, 0o755)
            self.assertEqual(sentinel.read_text(), "decoy-untouched")
            for name in ("tmp", "var", "var/tmp"):
                p = root / name
                self.assertFalse(p.is_symlink(), p)
                self.assertTrue(p.is_dir(), p)

            # One more, non-racing run must succeed past temp-root
            # (re)hardening cleanly -- failing only at the (expected,
            # never-configured) alias check, never on a symlink complaint.
            result = run_with_sample(
                [
                    WORLD,
                    "exec",
                    "R",
                    "--state-dir",
                    state,
                    "--timeout",
                    "5s",
                    "--",
                    STRESS_PROBE,
                    "report",
                    "final",
                ],
                timeout=15,
                name="symlink-race-final",
                env=env,
            )
            self.assertEqual(result.returncode, 125, result.stderr)
            self.assertIn("loopback alias is not configured", result.stderr)
            self.assertNotIn("symlink", result.stderr)

            self.assertEqual(os.stat(root / "tmp").st_mode & 0o7777, 0o1777)
            self.assertEqual(os.stat(root / "var").st_mode & 0o7777, 0o700)
            self.assertEqual(os.stat(root / "var/tmp").st_mode & 0o7777, 0o1777)


# ---------------------------------------------------------------------------
# 5. macOS shim storms
#
# These intentionally never run under `sandbox-exec`: empirically (see
# `SandboxExecConfinement.test_sandbox_exec_strips_dyld_insert_libraries`
# below), sandbox-exec strips DYLD_INSERT_LIBRARIES from its child's
# environment -- it treats the target like a shell, the same SIP-adjacent
# hardening that keeps an injected library out of /bin/sh. Wrapping a storm
# in sandbox-exec would therefore silently run it *unshimmed*, writing
# straight at the real host /tmp/R instead of the redirected one -- worse,
# not better. These tests rely instead on stress_probe's own `--dir`
# allowlist (`check_dir_allowed` in stress_probe/main.rs) plus the shim's
# WORLD_TMP redirection itself.


@unittest.skipUnless(MACOS, "native silo shim requires macOS")
class ShimStorms(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="world-stress-shim-")
        self.addCleanup(self.temp.cleanup)
        self.dir = pathlib.Path(self.temp.name)
        self.short = short_dir(".wt-stress-shim-")
        self.addCleanup(self.short.cleanup)
        self.world_tmp = pathlib.Path(self.short.name) / "w"
        (self.world_tmp / "tmp").mkdir(parents=True)
        (self.world_tmp / "var/tmp").mkdir(parents=True)
        self.ack = self.dir / "ack"
        self.ack.touch()

    def env(self, **extra):
        return shim_env(self.world_tmp, self.ack, **extra)

    def physical(self, virtual_path):
        return self.world_tmp / pathlib.Path(virtual_path).relative_to("/")

    def assert_probe_ok(self, result, name):
        self.assertEqual(result.returncode, 0, f"{name}: {result.stdout} {result.stderr}")
        summary = json.loads(result.stdout)
        self.assertEqual(summary["violations"], [], summary["violations"])
        for path in summary["expected_files"]:
            self.assertTrue(self.physical(path).exists(), f"missing physical file: {path}")
        self.assertFalse(os.path.lexists("/tmp/R"), "host /tmp/R must not exist")

    def with_gmalloc(self, env):
        lib = "/usr/lib/libgmalloc.dylib"
        if not os.path.exists(lib):
            return None
        merged = dict(env)
        merged["DYLD_INSERT_LIBRARIES"] = f"{lib}:{env['DYLD_INSERT_LIBRARIES']}"
        merged["MALLOC_STRICT_SIZE"] = "1"
        return merged

    def test_shim_storm(self):
        threads, iters = n(2, 6), n(5, 60)
        result = run_with_sample(
            [STRESS_PROBE, "storm", "--threads", threads, "--iters", iters, "--seed", "123", "--dir", "/tmp/R"],
            timeout=60,
            name="shim-storm",
            env=self.env(),
        )
        self.assert_probe_ok(result, "storm")
        if STRESS:
            gm_env = self.with_gmalloc(self.env())
            if gm_env is not None:
                result = run_with_sample(
                    [STRESS_PROBE, "storm", "--threads", "2", "--iters", "5", "--seed", "7", "--dir", "/tmp/R"],
                    timeout=90,
                    name="shim-storm-gmalloc",
                    env=gm_env,
                )
                self.assert_probe_ok(result, "storm-gmalloc")

    def test_shim_spawn_storm(self):
        threads, iters = n(2, 4), n(3, 20)
        result = run_with_sample(
            [STRESS_PROBE, "spawn-storm", "--threads", threads, "--iters", iters, "--dir", "/tmp/R"],
            timeout=90,
            name="shim-spawn-storm",
            env=self.env(),
        )
        self.assert_probe_ok(result, "spawn-storm")
        if STRESS:
            gm_env = self.with_gmalloc(self.env())
            if gm_env is not None:
                result = run_with_sample(
                    [STRESS_PROBE, "spawn-storm", "--threads", "2", "--iters", "3", "--dir", "/tmp/R"],
                    timeout=120,
                    name="shim-spawn-storm-gmalloc",
                    env=gm_env,
                )
                self.assert_probe_ok(result, "spawn-storm-gmalloc")

    def test_shim_fork_exec_storm(self):
        threads, iters = n(2, 6), n(3, 20)
        result = run_with_sample(
            [STRESS_PROBE, "fork-exec-storm", "--threads", threads, "--iters", iters, "--dir", "/tmp/R"],
            timeout=90,
            name="shim-fork-exec-storm",
            env=self.env(),
        )
        self.assert_probe_ok(result, "fork-exec-storm")
        if STRESS:
            gm_env = self.with_gmalloc(self.env())
            if gm_env is not None:
                result = run_with_sample(
                    [STRESS_PROBE, "fork-exec-storm", "--threads", "2", "--iters", "3", "--dir", "/tmp/R"],
                    timeout=120,
                    name="shim-fork-exec-storm-gmalloc",
                    env=gm_env,
                )
                self.assert_probe_ok(result, "fork-exec-storm-gmalloc")


# ---------------------------------------------------------------------------
# 5b. sandbox-exec confinement: validates, in isolation, the profile shape a
# future non-shimmed native-op probe could use as an OS-enforced backstop.
# Never wraps stress_probe itself (see the note above ShimStorms for why).


@unittest.skipUnless(MACOS and os.path.exists("/usr/bin/sandbox-exec"), "sandbox-exec is macOS-only")
class SandboxExecConfinement(unittest.TestCase):
    def setUp(self):
        # Deliberately NOT the default system temp dir: on macOS that is
        # under /private/var/folders, which the profile below allows
        # unconditionally (matching the coordinator's template), so both
        # "allowed" and "denied" would pass trivially if placed there. A
        # short_dir under $HOME is outside every clause but the explicit
        # allowed-subpath one, so denial is actually exercised.
        self.scratch = short_dir(".wt-sandbox-")
        self.addCleanup(self.scratch.cleanup)
        self.allowed = pathlib.Path(self.scratch.name) / "allowed"
        self.denied = pathlib.Path(self.scratch.name) / "denied"
        self.allowed.mkdir()
        self.denied.mkdir()

    def profile(self, *allowed_subpaths):
        clauses = " ".join(f'(subpath "{p}")' for p in allowed_subpaths)
        return (
            "(version 1)(allow default)"
            f"(deny file-write* (require-not (require-any {clauses} "
            '(subpath "/private/var/folders") (subpath "/dev"))))'
        )

    def test_sandbox_exec_strips_dyld_insert_libraries(self):
        # Documents (and pins, so a future OS change can't silently change
        # the safety story here) why the shim storms above never run under
        # sandbox-exec: it never even sees the shim's injection env.
        result = run_timeout(
            ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/env"],
            timeout=15,
            env=dict(os.environ, DYLD_INSERT_LIBRARIES="/tmp/does-not-matter.dylib"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("DYLD_INSERT_LIBRARIES", result.stdout)

    def test_sandbox_exec_confines_writes_to_the_allowed_subpath(self):
        profile = self.profile(str(self.allowed))

        ok = run_timeout(
            ["/usr/bin/sandbox-exec", "-p", profile, "/usr/bin/touch", str(self.allowed / "f")],
            timeout=15,
        )
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertTrue((self.allowed / "f").exists())

        denied = run_timeout(
            ["/usr/bin/sandbox-exec", "-p", profile, "/usr/bin/touch", str(self.denied / "f")],
            timeout=15,
        )
        self.assertNotEqual(denied.returncode, 0)
        self.assertFalse((self.denied / "f").exists())


# ---------------------------------------------------------------------------
# 6. Linux holder setup/teardown/exec race (cannot be run on this machine;
# written to be correct by inspection of crates/world-runtime/src/linux.rs
# and the LinuxWorkspace tests in tests/test_runtime.py).


@unittest.skipUnless(LINUX, "Linux World namespaces")
class LinuxHolderRace(unittest.TestCase):
    def test_holder_setup_teardown_exec_race(self):
        (ROOT / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="world-stress-linux-", dir=ROOT / "target") as tmp:
            root = pathlib.Path(tmp)
            state = root / "state"
            home = root / "home"
            home.mkdir()
            env = dict(os.environ, HOME=str(home))

            ids = [f"W{i}" for i in range(n(2, 6))]
            workdirs = {}
            for id_ in ids:
                w = root / id_
                w.mkdir()
                workdirs[id_] = w
                result = run_timeout(
                    [WORLD, "workspace", "--state-dir", state, "create", id_, "--workdir", w],
                    timeout=30,
                    env=env,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            stop = threading.Event()
            hangs = []
            lock = threading.Lock()

            def loop(id_):
                deadline = time.time() + n(3, 10)
                while time.time() < deadline and not stop.is_set():
                    for action in (["setup", id_], ["teardown", id_]):
                        try:
                            run_timeout(
                                [WORLD, "workspace", "--state-dir", state, *action],
                                timeout=30,
                                env=env,
                            )
                        except subprocess.TimeoutExpired as e:
                            with lock:
                                hangs.append((id_, action, str(e)))
                    try:
                        run_timeout(
                            [WORLD, "exec", id_, "--state-dir", state, "--timeout", "5s", "--", "/bin/true"],
                            timeout=30,
                            env=env,
                        )
                    except subprocess.TimeoutExpired as e:
                        with lock:
                            hangs.append((id_, "exec", str(e)))

            threads = [threading.Thread(target=loop, args=(id_,)) for id_ in ids]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=n(3, 10) + 60)
            stop.set()

            self.assertEqual(hangs, [], hangs)

            # A clean setup+exec+teardown must work for every workspace
            # afterwards.
            for id_ in ids:
                r = run_timeout(
                    [WORLD, "workspace", "--state-dir", state, "setup", id_], timeout=30, env=env
                )
                self.assertEqual(r.returncode, 0, r.stderr)
                r = run_timeout(
                    [WORLD, "exec", id_, "--state-dir", state, "--timeout", "10s", "--", "/bin/true"],
                    timeout=30,
                    env=env,
                )
                self.assertEqual(r.returncode, 0, r.stderr)
                r = run_timeout(
                    [WORLD, "workspace", "--state-dir", state, "teardown", id_], timeout=30, env=env
                )
                self.assertEqual(r.returncode, 0, r.stderr)

            # No orphan holders: every recorded pid must have actually
            # exited (see Holder::verify in linux.rs for what a live one
            # looks like; here we only need to know it's gone).
            holders_path = state / "holders.json"
            if holders_path.exists():
                holders = json.loads(holders_path.read_text())
                for id_, holder in holders.items():
                    pid = holder["pid"]
                    self.assertFalse(
                        pathlib.Path(f"/proc/{pid}").exists(),
                        f"orphan holder for {id_}: pid {pid} still alive",
                    )


# ---------------------------------------------------------------------------
# 7. macOS privileged network soak (requires WORLD_SILO_INTEGRATION=1 and the
# full tier; local/CI-unprivileged runs skip this).


@unittest.skipUnless(
    MACOS and os.environ.get("WORLD_SILO_INTEGRATION") == "1" and STRESS,
    "privileged (sudo -n ifconfig) and full-tier only",
)
class NetworkSoak(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="world-stress-soak-")
        cls.root = pathlib.Path(cls.temp.name)
        cls.state = cls.root / "state"
        # A dedicated HOME under our own scratch root: workspace temp roots
        # (~/.world/tmp/<ip>) must never land under the real developer/CI
        # HOME (see `assert_owned` in tearDownClass, and the same rule every
        # other test in this file follows via `short_dir`).
        cls.home_dir = tempfile.TemporaryDirectory(prefix=".wt-soak-", dir=str(pathlib.Path.home()))
        cls.home = pathlib.Path(cls.home_dir.name)
        cls.env = dict(os.environ, HOME=str(cls.home))
        cls.worlds = {}
        for i in range(8):
            name = f"S{i}"
            work = cls.root / name
            work.mkdir()
            result = run_timeout(
                [WORLD, "workspace", "--state-dir", cls.state, "create", name, "--workdir", work],
                timeout=30,
                env=cls.env,
            )
            if result.returncode:
                raise AssertionError(result.stderr)
            info = json.loads(result.stdout)
            subprocess.run(
                ["sudo", "-n", "/sbin/ifconfig", "lo0", "alias", info["ip"], "netmask", "255.0.0.0"],
                check=True,
                timeout=10,
            )
            cls.worlds[name] = info

    @classmethod
    def tearDownClass(cls):
        for world in getattr(cls, "worlds", {}).values():
            owned_rmtree(pathlib.Path(world["temp_root"]), cls.home)
            subprocess.run(
                ["sudo", "-n", "/sbin/ifconfig", "lo0", "-alias", world["ip"]], check=True, timeout=10
            )
        cls.temp.cleanup()
        cls.home_dir.cleanup()

    def command(self, world, *args):
        return [WORLD, "exec", world, "--state-dir", self.state, "--timeout", "90s", "--", PROBE, *args]

    def test_network_soak(self):
        duration = 60 * SCALE
        names = list(self.worlds)
        stop_at = time.time() + duration
        errors = []
        lock = threading.Lock()
        servers = {}

        def stop_servers():
            for proc, _ in servers.values():
                proc.terminate()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=5)

        try:
            for name in names:
                proc = subprocess.Popen(
                    [str(x) for x in self.command(name, "serve", "127.0.0.1:0", name)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=self.env,
                )
                line = proc.stdout.readline()
                self.assertTrue(line.startswith("READY"), (name, line))
                servers[name] = (proc, int(line.split()[1]))

            def client_loop(name):
                while time.time() < stop_at:
                    for other, (_, port) in servers.items():
                        result = run_timeout(
                            self.command(name, "get", f"127.0.0.1:{port}"), timeout=15, env=self.env
                        )
                        ok = result.returncode == 0 and result.stdout == other
                        expected_ok = other == name
                        if ok != expected_ok:
                            with lock:
                                errors.append(
                                    f"{name}->{other}: rc={result.returncode} out={result.stdout!r}"
                                )

            threads = [threading.Thread(target=client_loop, args=(name,)) for name in names]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=duration + 60)
        finally:
            # No test may leave a background process running, whether it
            # passed, failed, or raised.
            stop_servers()

        self.assertEqual(errors, [], errors[:20])


if __name__ == "__main__":
    unittest.main()
