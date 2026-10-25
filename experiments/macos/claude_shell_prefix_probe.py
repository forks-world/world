"""Offline launcher-contract probe; not a Silo/network compatibility test.

Run with python3 experiments/macos/claude_shell_prefix_probe.py.
Requires macOS, clang and Claude Code. Leaves evidence in a new temporary
directory. Does not modify user settings or request model inference.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile


PREFIX = r'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char *path = getenv("WORLD_PREFIX_LOG");
    if (!path) return 125;
    FILE *f = fopen(path, "a");
    if (!f) return 125;
    fprintf(f, "argc=%d\n", argc);
    if (argc == 2) fprintf(f, "command=%s\n", argv[1]);
    fclose(f);
    if (argc != 2 || getenv("WORLD_PREFIX_REFUSE")) return 125;
    execl("/bin/sh", "sh", "-c", argv[1], (char *)0);
    return 125;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claude", default=shutil.which("claude"))
    args = parser.parse_args()
    if sys.platform != "darwin" or not args.claude:
        parser.error("requires macOS and --claude or claude on PATH")
    claude = str(Path(args.claude).resolve())
    root = Path(tempfile.mkdtemp(prefix="world-prefix-probe-")).resolve()
    print(f"Evidence: {root}", flush=True)
    for name in ("home", "config", "project"):
        (root / name).mkdir()
    (root / "prefix.c").write_text(PREFIX)
    subprocess.run(
        ["/usr/bin/clang", str(root / "prefix.c"), "-o", str(root / "prefix")],
        check=True, timeout=30,
    )
    settings = {"hooks": {"SessionStart": [{"matcher": "startup", "hooks": [
        {"type": "command", "command": "printf HOOK_OK > hook-result"}
    ]}]}}
    (root / "settings.json").write_text(json.dumps(settings))
    env = {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(root / "home"), "TMPDIR": str(root),
        "CLAUDE_CONFIG_DIR": str(root / "config"), "TERM": "dumb",
        "CLAUDE_CODE_SHELL_PREFIX": str(root / "prefix"),
        "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    }
    results = []
    marker = root / "project/hook-result"
    for mode in ("execute", "refuse"):
        if marker.exists():
            marker.unlink()
        log = root / f"{mode}.log"
        case_env = dict(env, WORLD_PREFIX_LOG=str(log))
        if mode == "refuse":
            case_env["WORLD_PREFIX_REFUSE"] = "1"
        proc = subprocess.Popen(
            [claude, "--init-only", "--setting-sources", "", "--settings",
             str(root / "settings.json"), "--no-session-persistence"],
            cwd=root / "project", env=case_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        timed_out = False
        try:
            out, err = proc.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            out, err = proc.communicate()
        result = {
            "mode": mode, "exit": proc.returncode, "timeout": timed_out,
            "wrapper_called": log.exists(),
            "wrapper_log": log.read_text() if log.exists() else "",
            "hook_result": marker.read_text() if marker.exists() else None,
            "stdout": out, "stderr": err,
        }
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    (root / "results.json").write_text(json.dumps(results, indent=2))
    passed = (
        all(r["wrapper_called"] and not r["timeout"] for r in results)
        and results[0]["hook_result"] == "HOOK_OK"
        and results[1]["hook_result"] is None
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
