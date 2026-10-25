"""Single-VM Apple container smoke probe (not a World backend acceptance test).

Requires an already running `container system` and a cached Alpine 3.22 image.
Run: python3 experiments/macos/linux_vm_probe.py
Uses one CPU and 256 MiB, no host mounts or published ports. Removes only its
own container on exit; leaves the pre-existing container service running.
Raw timings, output and host memory snapshots are saved to a temporary folder.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    root = Path(tempfile.mkdtemp(prefix="world-vm-probe-"))
    name = f"world-vm-probe-{os.getpid()}"
    records = []
    print(f"Evidence: {root}", flush=True)

    def run(label, argv, check=True, timeout=120):
        start = time.monotonic()
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            item = dict(label=label, argv=argv, seconds=time.monotonic() - start,
                        returncode=p.returncode, stdout=p.stdout, stderr=p.stderr)
        except subprocess.TimeoutExpired as e:
            item = dict(label=label, argv=argv, seconds=time.monotonic() - start,
                        error=str(e))
            raise
        finally:
            if 'item' in locals():
                records.append(item)
                (root / "results.json").write_text(json.dumps(records, indent=2))
        print(f"{label}: rc={p.returncode}, {item['seconds']:.3f}s", flush=True)
        if check and p.returncode:
            raise RuntimeError(f"{label}: {p.stderr or p.stdout}")
        return p.stdout

    def snapshot(label):
        run(label + "-pressure", ["memory_pressure"])
        run(label + "-swap", ["sysctl", "vm.swapusage"])
        out = run(label + "-processes", ["ps", "-axo", "pid,rss,%cpu,comm"])
        for line in out.splitlines():
            if any(s in line for s in ("container-runtime-linux", "container-apiserver",
                                      "container-network", "machine-apiserver",
                                      "container-core-images", "Virtualization.VirtualMachine")):
                pid = line.split()[0]
                run(label + "-footprint-" + pid, ["vmmap", "-summary", pid], check=False)

    run("version", ["container", "--version"])
    run("image", ["container", "image", "inspect", "docker.io/library/alpine:3.22"])
    snapshot("before")
    try:
        run("first-start-cached-image", ["container", "run", "-d", "--name", name,
            "--cpus", "1", "--memory", "256M", "docker.io/library/alpine:3.22",
            "sleep", "3600"])
        run("inspect", ["container", "inspect", name])
        run("guest", ["container", "exec", name, "sh", "-ec",
            "uname -a; cat /proc/meminfo; cat /proc/self/status; "
            "cat /proc/filesystems; ls /proc/self/ns; mount"])
        # HTTP daemon must survive the exec invocation that starts it.
        run("start-service", ["container", "exec", name, "sh", "-ec",
            "mkdir -p /tmp/world-probe; printf WORLD_VM_OK > /tmp/world-probe/index.html; "
            "printf '%s\\n' '#!/bin/sh' 'read -r request' "
            "\"printf 'HTTP/1.0 200 OK\\\\r\\\\nContent-Length: 11\\\\r\\\\n\\\\r\\\\nWORLD_VM_OK'\" "
            "> /tmp/world-probe/respond; chmod +x /tmp/world-probe/respond; "
            "nohup nc -lk -s 127.0.0.1 -p 8080 -e /tmp/world-probe/respond "
            "</dev/null >/tmp/world-probe/service.log 2>&1 &"])
        time.sleep(0.2)
        for i in range(3):
            out = run(f"separate-exec-http-{i}", ["container", "exec", name,
                "wget", "-qO-", "http://127.0.0.1:8080"])
            if out != "WORLD_VM_OK":
                raise RuntimeError(f"Unexpected HTTP response: {out!r}")
        run("guest-host-path-absent", ["container", "exec", name, "sh", "-ec",
            "test ! -e /Users/hurricane; echo HOST_HOME_NOT_MOUNTED"])
        run("namespace-capability", ["container", "exec", name, "sh", "-c",
            "unshare -Urnm sh -c 'echo NAMESPACE_OK; ip link'"], check=False)
        run("stats", ["container", "stats", "--no-stream", "--format", "json", name])
        time.sleep(3)
        snapshot("running")
        run("stop", ["container", "stop", "--time", "1", name])
        run("restart", ["container", "start", name])
        out = run("restart-file", ["container", "exec", name,
            "cat", "/tmp/world-probe/index.html"])
        if out != "WORLD_VM_OK":
            raise RuntimeError("Writable layer did not survive restart")
        # Files persist; process state is not restored by a restart.
        run("restart-service-absent", ["container", "exec", name, "sh", "-ec",
            "if wget -T 2 -qO- http://127.0.0.1:8080; then exit 1; fi"])
    finally:
        run("cleanup-stop", ["container", "stop", "--time", "1", name], check=False)
        run("cleanup-delete", ["container", "delete", name], check=False)
        snapshot("after")
    print(f"PASS. Raw evidence: {root / 'results.json'}", flush=True)


if __name__ == "__main__":
    main()
