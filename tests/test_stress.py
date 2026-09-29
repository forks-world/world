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
import ipaddress
import json
import os
import pathlib
import queue
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

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


def check_alias_ip(ip):
    """Only ever touch addresses inside the 127.77.0.0/16 range the workspace
    allocator hands out; in particular never 127.0.0.1."""
    addr = ipaddress.ip_address(ip)
    if addr not in ipaddress.ip_network("127.77.0.0/16"):
        raise AssertionError(f"refusing to manage loopback alias {ip}: outside 127.77.0.0/16")
    return str(addr)


def alias_present(ip):
    """True when `ip` is bindable on this host (the same test the shim's
    `alias_ready` uses)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((ip, 0))
        except OSError:
            return False
    return True


def remove_alias(ip):
    """Tolerant, verifying removal: a no-op when the alias is absent (a failed
    or timed-out add), otherwise `-alias` and a check that it is really gone."""
    ip = check_alias_ip(ip)
    if not alias_present(ip):
        return
    result = subprocess.run(
        ["sudo", "-n", "/sbin/ifconfig", "lo0", "-alias", ip],
        capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
    )
    if alias_present(ip):
        raise AssertionError(f"loopback alias {ip} is still present after removal: {result.stderr}")


def add_alias(ip):
    """Register the removal BEFORE adding (unittest runs class cleanups even
    when setUpClass raises), and refuse an address that is already aliased:
    the allocator skips those, so it belongs to someone else."""
    ip = check_alias_ip(ip)
    if alias_present(ip):
        raise AssertionError(f"loopback alias {ip} is already present; not taking it over")
    return ip


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


def run_workers(workers, join_timeout, stop=None, run_for=None):
    """Run `workers` (a list of (name, fn)) on daemon threads and join them
    ALL against one overall deadline. Any exception (including
    subprocess.TimeoutExpired) escaping a worker is recorded instead of
    silently ending the thread. With `run_for` (and a `stop` Event) the
    workers are left to loop for that long and then told to stop. Returns
    (errors, alive): the recorded exception strings and the names of threads
    still running after `stop` was set and the deadline passed. Callers must
    assert both are empty, `alive` first (a stuck thread makes every later
    invariant meaningless).
    """
    errors = []
    lock = threading.Lock()

    def wrap(name, fn):
        def body():
            try:
                fn()
            except BaseException as e:  # noqa: BLE001 - record, never swallow
                with lock:
                    errors.append(f"{name}: {type(e).__name__}: {e}")

        return body

    threads = [threading.Thread(target=wrap(name, fn), name=name, daemon=True) for name, fn in workers]
    for t in threads:
        t.start()
    try:
        if run_for is not None:
            time.sleep(run_for)
    finally:
        # Always stop and join, even if the sleep above was interrupted: no
        # test may leave a background thread (and the subprocesses it keeps
        # spawning) running past its own body.
        if run_for is not None and stop is not None:
            stop.set()
        end = time.monotonic() + join_timeout
        for t in threads:
            t.join(max(0.0, end - time.monotonic()))
        if stop is not None:
            stop.set()
    return errors, [t.name for t in threads if t.is_alive()]


def read_ready_line(proc, timeout=30):
    """First stdout line of `proc`, bounded. A plain readline can block
    forever (a hung or silent server, or a partial line), and select on a
    text pipe can still block on a partial line, so the read happens on a
    helper thread and the wait is a bounded queue get. Raises AssertionError
    on timeout; the caller owns killing `proc` (the helper thread then sees
    EOF and exits).
    """
    q = queue.Queue()
    reader = threading.Thread(
        target=lambda: q.put(proc.stdout.readline()), name=f"ready-reader-{proc.pid}", daemon=True
    )
    reader.start()
    try:
        return q.get(timeout=timeout)
    except queue.Empty:
        raise AssertionError(f"no readiness line from pid {proc.pid} within {timeout}s") from None


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

            # One exec_worker iteration can take run_with_sample's 15 s
            # timeout + 15 s sample + 10 s reap; a create_worker iteration
            # 15 s. Join every worker against one deadline that covers that.
            workers = (
                [("attacker", attacker)]
                + [(f"exec-{i}", exec_worker) for i in range(exec_workers)]
                + [("create", create_worker)]
            )
            errors, alive = run_workers(workers, join_timeout=60, stop=stop, run_for=race_seconds)
            self.assertEqual(alive, [], f"race workers still running: {alive}")
            self.assertEqual(errors, [], errors)

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
# These intentionally never run under `sandbox-exec`: how it treats
# DYLD_INSERT_LIBRARIES depends on the host's SIP configuration (locally it
# strips the variable, so the child would run *unshimmed* against the real
# host /tmp/R; on CI runners dyld instead tries to load the library into
# sandbox-exec itself). Either way the storm would not reliably run through
# the shim, which is worse, not better. These tests rely instead on stress_probe's own `--dir`
# allowlist plus `verify_redirected` (see `guard_dir` in stress_probe/main.rs:
# it refuses unless `/tmp` provably is WORLD_TMP/tmp, so a storm that is not
# really shimmed fails closed) and the shim's WORLD_TMP redirection itself.


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

    def assert_fork_exec_summary(self, result, threads, iters):
        """Every fork ran (ops == threads*iters) and every file holds its own
        marker: even iterations exec'd `stress_probe touch` (so the exec'd
        image ran its own verify_redirected under the shim), odd ones wrote
        it from the forked child."""
        summary = json.loads(result.stdout)
        self.assertEqual(summary["ops"], threads * iters, summary)
        self.assertEqual(len(summary["expected_files"]), threads * iters)
        for t in range(threads):
            for i in range(iters):
                path = self.physical(f"/tmp/R/{t}/{i}")
                self.assertEqual(path.read_text(), f"fe-t{t}-i{i}", str(path))

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
        self.assert_fork_exec_summary(result, threads, iters)
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
                self.assert_fork_exec_summary(result, 2, 3)

    def test_fork_exec_storm_timeout_reaps_children(self):
        """A hung child (test-only STRESS_PROBE_HANG: exec `pause <marker>`)
        past the deadline makes the probe kill and reap every child before it
        exits 3: nothing is left running under the marker."""
        marker = f"stress-hang-{uuid.uuid4().hex}"
        result = run_with_sample(
            [STRESS_PROBE, "fork-exec-storm", "--threads", "2", "--iters", "2",
             "--dir", "/tmp/R", "--deadline-ms", "500"],
            timeout=60,
            name="shim-fork-exec-storm-timeout",
            env=self.env(STRESS_PROBE_HANG=marker),
        )
        ps = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True).stdout
        strays = [line.split(None, 1) for line in ps.splitlines() if marker in line]
        for pid, _ in strays:
            # Only ever by exact pid, and only for a process that carries our
            # unique marker.
            try:
                os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass
        self.assertEqual(result.returncode, 3, f"{result.stdout} {result.stderr}")
        summary = json.loads(result.stdout)
        self.assertTrue(summary["timeout"], summary)
        self.assertEqual(summary["unreaped"], [], summary)
        self.assertTrue(summary["pids"], summary)
        self.assertEqual(strays, [], f"children survived the timeout: {strays}")


# ---------------------------------------------------------------------------
# 5a. stress_probe refuses to run unredirected (fail-closed)


@unittest.skipUnless(MACOS or LINUX, "stress_probe runs on macOS and Linux")
class StressProbeRefusesUnredirected(unittest.TestCase):
    """Run natively (no shim, no namespace), so `/tmp` is the shared host
    temp dir and `verify_redirected` must refuse before creating anything.
    The positive case is every ShimStorms test (macOS) and the Linux
    harness."""

    def setUp(self):
        self.target = f"/tmp/sp-{uuid.uuid4().hex}"
        self.addCleanup(self.cleanup_target)
        self.scratch = short_dir(".wt-sp-refuse-")
        self.addCleanup(self.scratch.cleanup)
        # A real, owned physical-root-shaped dir with a `tmp` inside: the
        # only thing wrong with it is that nothing redirects /tmp to it.
        self.owned = pathlib.Path(self.scratch.name) / "w"
        (self.owned / "tmp").mkdir(parents=True)

    def cleanup_target(self):
        # Remove ONLY the exact unique path this test chose; anything else
        # (including a different /tmp/sp-* entry) is never touched.
        if os.path.lexists(self.target):
            assert self.target.startswith("/tmp/sp-") and "/" not in self.target[len("/tmp/") :]
            assert_owned(self.target, "/tmp")
            if os.path.isdir(self.target) and not os.path.islink(self.target):
                shutil.rmtree(self.target, ignore_errors=True)
            else:
                os.remove(self.target)

    def clean_env(self, **extra):
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("WORLD_TMP", "STRESS_PROBE_PHYSICAL_ROOT", "STRESS_PROBE_EXTRA_ROOT", "DYLD_INSERT_LIBRARIES")
        }
        env.update(extra)
        return env

    def assert_refused(self, args, env, label):
        result = run_timeout([STRESS_PROBE, *args], timeout=30, env=env)
        try:
            self.assertEqual(result.returncode, 2, f"{label}: {result.stdout} {result.stderr}")
            self.assertIn("not running redirected", result.stderr, label)
            self.assertFalse(os.path.lexists(self.target), f"{label}: created {self.target}")
        finally:
            # Fail closed even for the assertion above: never leave a
            # created path behind for the next case to trip over.
            self.cleanup_target()

    def test_refuses_without_redirection(self):
        modes = {
            "storm": ["storm", "--threads", "1", "--iters", "1", "--dir", self.target],
            "spawn-storm": ["spawn-storm", "--threads", "2", "--iters", "1", "--dir", self.target],
            "fork-exec-storm": ["fork-exec-storm", "--threads", "1", "--iters", "1", "--dir", self.target],
            "touch": ["touch", f"{self.target}/x", "marker"],
        }
        cases = {
            "no env": self.clean_env(),
            "WORLD_TMP set, no injection": self.clean_env(WORLD_TMP=str(self.owned)),
            "PHYSICAL_ROOT set, no injection": self.clean_env(STRESS_PROBE_PHYSICAL_ROOT=str(self.owned)),
            "WORLD_TMP=/private": self.clean_env(WORLD_TMP="/private"),
            "WORLD_TMP=/": self.clean_env(WORLD_TMP="/"),
            "WORLD_TMP=/private/tmp": self.clean_env(WORLD_TMP="/private/tmp"),
            "WORLD_TMP=/tmp": self.clean_env(WORLD_TMP="/tmp"),
            "WORLD_TMP relative": self.clean_env(WORLD_TMP="w"),
            "WORLD_TMP with ..": self.clean_env(WORLD_TMP=f"{self.owned}/../w"),
            "WORLD_TMP nonexistent": self.clean_env(WORLD_TMP=f"{self.owned}/missing"),
        }
        for mode, args in modes.items():
            for case, env in cases.items():
                with self.subTest(mode=mode, case=case):
                    self.assert_refused(args, env, f"{mode}/{case}")

    def test_dotdot_dir_is_still_rejected(self):
        result = run_timeout(
            [STRESS_PROBE, "storm", "--dir", f"{self.target}/../x"], timeout=30, env=self.clean_env()
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("..", result.stderr)
        self.assertFalse(os.path.lexists(self.target))


@unittest.skipUnless(MACOS, "native silo shim requires macOS")
class StressProbeRefusesSymlinkedDir(unittest.TestCase):
    """A symlink already planted below the redirected /tmp (R -> victim, or
    R/0 -> victim) must make every stress_probe mode refuse with rc 2 and
    leave the victim (outside the private tree) untouched: `open_validated`
    walks --dir fd-relative with O_NOFOLLOW."""

    def setUp(self):
        self.short = short_dir(".wt-stress-symdir-")
        self.addCleanup(self.short.cleanup)
        self.base = pathlib.Path(self.short.name)
        self.world_tmp = self.base / "w"
        (self.world_tmp / "tmp").mkdir(parents=True)
        (self.world_tmp / "var/tmp").mkdir(parents=True)
        self.ack = self.base / "ack"
        self.ack.touch()
        self.victim_holder = short_dir(".wt-stress-victim-")
        self.addCleanup(self.victim_holder.cleanup)
        self.victim = pathlib.Path(self.victim_holder.name) / "victim"
        self.victim.mkdir()
        (self.victim / "sentinel").write_text("keep me")
        self.planted = []
        self.addCleanup(self.remove_planted)
        self.host_target = f"/private/tmp/sp-{uuid.uuid4().hex}"

    def remove_planted(self):
        # Only ever unlink the exact symlinks (never follow them).
        for link in reversed(self.planted):
            if os.path.islink(link):
                owned_remove(link, self.world_tmp)
        self.planted.clear()
        r = self.world_tmp / "tmp/R"
        if r.is_dir() and not r.is_symlink():
            assert_owned(r, self.world_tmp)
            shutil.rmtree(r, ignore_errors=True)

    def plant(self, link, target):
        assert_owned(link, self.world_tmp)
        os.symlink(str(target), str(link))
        self.planted.append(link)

    def snapshot(self):
        return {
            name: (self.victim / name).read_bytes() if (self.victim / name).is_file() else None
            for name in sorted(os.listdir(self.victim))
        }

    def modes(self):
        return {
            "storm": ["storm", "--threads", "1", "--iters", "1", "--dir", "/tmp/R"],
            "spawn-storm": ["spawn-storm", "--threads", "2", "--iters", "1", "--dir", "/tmp/R"],
            "fork-exec-storm": ["fork-exec-storm", "--threads", "1", "--iters", "1", "--dir", "/tmp/R"],
            "touch": ["touch", "/tmp/R/0/x", "m"],
        }

    def check_refused(self, label):
        before = self.snapshot()
        env = shim_env(self.world_tmp, self.ack)
        for mode, args in self.modes().items():
            with self.subTest(case=label, mode=mode):
                result = run_timeout([STRESS_PROBE, *args], timeout=60, env=env)
                self.assertEqual(result.returncode, 2, f"{result.stdout} {result.stderr}")
                self.assertIn("not a real directory inside the private tree", result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual((self.victim / "sentinel").read_text(), "keep me")
                self.assertFalse(os.path.lexists(self.host_target))
                self.assertFalse(os.path.lexists("/tmp/R"))

    def test_symlinked_dir_is_refused(self):
        phys_r = self.world_tmp / "tmp/R"
        self.plant(phys_r, self.victim)
        self.check_refused("R -> victim")
        self.remove_planted()

    def test_symlinked_thread_dir_is_refused(self):
        phys_r = self.world_tmp / "tmp/R"
        phys_r.mkdir()
        self.plant(phys_r / "0", self.victim)
        self.check_refused("R/0 -> victim")
        self.remove_planted()

    def test_symlink_to_host_tmp_is_refused(self):
        self.plant(self.world_tmp / "tmp/R", self.host_target)
        self.check_refused("R -> /private/tmp/<uuid>")
        self.remove_planted()


# ---------------------------------------------------------------------------
# 5a'. unit tests for this file's own bounded-concurrency helpers (no
# privileges, no world binary).


class WorkerHelpers(unittest.TestCase):
    def test_run_workers_records_exceptions(self):
        def timing_out():
            raise subprocess.TimeoutExpired(["x"], 15)

        def boom():
            raise KeyError("k")

        errors, alive = run_workers([("a", timing_out), ("b", boom), ("c", lambda: None)], join_timeout=10)
        self.assertEqual(alive, [])
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(any(e.startswith("a: TimeoutExpired") for e in errors), errors)
        self.assertTrue(any(e.startswith("b: KeyError") for e in errors), errors)

    def test_run_workers_reports_workers_that_outlive_their_budget(self):
        release = threading.Event()
        stop = threading.Event()
        # A worker that ignores `stop` and sleeps past the budget.
        errors, alive = run_workers([("slow", lambda: release.wait(30))], join_timeout=0.3, stop=stop)
        try:
            self.assertEqual(alive, ["slow"])
            self.assertEqual(errors, [])
            self.assertTrue(stop.is_set())
        finally:
            release.set()
            for t in threading.enumerate():
                if t.name == "slow":
                    t.join(5)
        self.assertEqual([t.name for t in threading.enumerate() if t.name == "slow"], [])

    def test_run_workers_run_for_sets_stop_and_joins(self):
        stop = threading.Event()
        errors, alive = run_workers(
            [("loop", lambda: stop.wait(30))], join_timeout=10, stop=stop, run_for=0.2
        )
        self.assertEqual((errors, alive), ([], []))

    def test_read_ready_line_is_bounded_and_leaves_nothing_behind(self):
        proc = subprocess.Popen(
            ["sleep", "60"], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True
        )
        start = time.monotonic()
        try:
            with self.assertRaises(AssertionError):
                read_ready_line(proc, timeout=1)
            self.assertLess(time.monotonic() - start, 30)
        finally:
            proc.kill()
            proc.wait(timeout=10)
            proc.stdout.close()
        for t in threading.enumerate():
            if t.name == f"ready-reader-{proc.pid}":
                t.join(10)
        self.assertEqual(
            [t.name for t in threading.enumerate() if t.name == f"ready-reader-{proc.pid}"], []
        )
        self.assertIsNotNone(proc.poll())

    def test_read_ready_line_returns_a_line(self):
        proc = subprocess.Popen(
            ["echo", "READY 1"], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True
        )
        try:
            self.assertEqual(read_ready_line(proc, timeout=10), "READY 1\n")
        finally:
            proc.kill()
            proc.wait(timeout=10)
            proc.stdout.close()


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

            loop_seconds = n(3, 10)

            def loop(id_):
                deadline = time.time() + loop_seconds

                def live():
                    # Checked before EVERY action, not just the top of the
                    # loop: one pass is three commands of up to 30 s each.
                    return not stop.is_set() and time.time() < deadline

                while live():
                    for action in (["setup", id_], ["teardown", id_]):
                        if not live():
                            return
                        try:
                            run_timeout(
                                [WORLD, "workspace", "--state-dir", state, *action],
                                timeout=30,
                                env=env,
                            )
                        except Exception as e:  # noqa: BLE001 - any failure is recorded
                            with lock:
                                hangs.append((id_, action, f"{type(e).__name__}: {e}"))
                    if not live():
                        return
                    try:
                        run_timeout(
                            [WORLD, "exec", id_, "--state-dir", state, "--timeout", "5s", "--", "/bin/true"],
                            timeout=30,
                            env=env,
                        )
                    except Exception as e:  # noqa: BLE001
                        with lock:
                            hangs.append((id_, "exec", f"{type(e).__name__}: {e}"))

            # One overall deadline for every worker: the loop budget, plus
            # the three 30 s commands of a final in-flight pass, plus slack.
            errors, alive = run_workers(
                [(f"holder-{id_}", lambda id_=id_: loop(id_)) for id_ in ids],
                join_timeout=loop_seconds + 3 * 30 + 30,
                stop=stop,
            )
            # Stuck workers first: recovery checks below are meaningless
            # while a worker still races them.
            self.assertEqual(alive, [], f"holder-race workers still running: {alive}")
            self.assertEqual(errors, [], errors)
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
        # Everything is registered with addClassCleanup the moment it exists:
        # unittest runs those (LIFO) even when setUpClass itself raises, so a
        # failed create/ifconfig cannot leak aliases, temp roots or dirs.
        cls.temp = tempfile.TemporaryDirectory(prefix="world-stress-soak-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = pathlib.Path(cls.temp.name)
        cls.state = cls.root / "state"
        # A dedicated HOME under our own scratch root: workspace temp roots
        # (~/.world/tmp/<ip>) must never land under the real developer/CI
        # HOME (see `assert_owned` in `owned_rmtree`, and the same rule every
        # other test in this file follows via `short_dir`).
        cls.home_dir = tempfile.TemporaryDirectory(prefix=".wt-soak-", dir=str(pathlib.Path.home()))
        cls.addClassCleanup(cls.home_dir.cleanup)
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
            # assert_owned (inside owned_rmtree) keeps this under the
            # dedicated HOME.
            cls.addClassCleanup(owned_rmtree, pathlib.Path(info["temp_root"]), cls.home)
            # Validate the address, refuse one already aliased, and register
            # the (tolerant, verifying) removal BEFORE adding.
            ip = add_alias(info["ip"])
            cls.addClassCleanup(remove_alias, ip)
            subprocess.run(
                ["sudo", "-n", "/sbin/ifconfig", "lo0", "alias", ip, "netmask", "255.0.0.0"],
                check=True,
                timeout=10,
                stdin=subprocess.DEVNULL,
            )
            cls.worlds[name] = info

    def command(self, world, *args):
        return [WORLD, "exec", world, "--state-dir", self.state, "--timeout", "90s", "--", PROBE, *args]

    def test_network_soak(self):
        duration = 60 * SCALE
        names = list(self.worlds)
        stop = threading.Event()
        errors = []
        requests = {name: 0 for name in names}
        lock = threading.Lock()
        servers = {}
        logs = []

        def stop_servers():
            for proc, _ in servers.values():
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            for log in logs:
                log.close()

        try:
            for name in names:
                # stderr goes to a file, never an undrained PIPE: a chatty
                # server would otherwise fill the pipe and hang.
                log = open(self.root / f"server-{name}.log", "wb")
                logs.append(log)
                proc = subprocess.Popen(
                    [str(x) for x in self.command(name, "serve", "127.0.0.1:0", name)],
                    stdout=subprocess.PIPE,
                    stderr=log,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    env=self.env,
                )
                # Registered before the readiness read so a hang or failure
                # there still gets this process killed by stop_servers.
                servers[name] = (proc, None)
                line = read_ready_line(proc, timeout=30)
                self.assertTrue(line.startswith("READY"), (name, line))
                servers[name] = (proc, int(line.split()[1]))

            # Readiness waits must not use up the soak time.
            stop_at = time.time() + duration

            def client_loop(name):
                while time.time() < stop_at and not stop.is_set():
                    for other, (_, port) in servers.items():
                        # Checked before each call: one pass is up to 8 x 15 s.
                        if time.time() >= stop_at or stop.is_set():
                            return
                        result = run_timeout(
                            self.command(name, "get", f"127.0.0.1:{port}"), timeout=15, env=self.env
                        )
                        with lock:
                            requests[name] += 1
                        ok = result.returncode == 0 and result.stdout == other
                        expected_ok = other == name
                        if ok != expected_ok:
                            with lock:
                                errors.append(
                                    f"{name}->{other}: rc={result.returncode} out={result.stdout!r}"
                                )

            # A timed-out client call is recorded by run_workers (it would
            # otherwise silently end that worker and shrink the soak).
            worker_errors, alive = run_workers(
                [(f"soak-{name}", lambda name=name: client_loop(name)) for name in names],
                join_timeout=duration + 8 * 15 + 30,
                stop=stop,
            )
        finally:
            # No test may leave a background process running, whether it
            # passed, failed, or raised.
            stop_servers()

        self.assertEqual(alive, [], f"soak clients still running: {alive}")
        self.assertEqual(worker_errors, [], worker_errors[:20])
        self.assertEqual(errors, [], errors[:20])
        idle = [n for n, c in requests.items() if c == 0]
        self.assertEqual(idle, [], f"soak clients made no request: {requests}")


if __name__ == "__main__":
    unittest.main()
