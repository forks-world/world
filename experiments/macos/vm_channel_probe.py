"""Provider transport probes run inside the smoke test's disposable VM."""

import os
import select
import subprocess
import time


DETACHED_SERVER = """
import socket
server = socket.socket()
server.bind(('127.0.0.1', 18765))
server.listen(1)
server.settimeout(20)
conn, _ = server.accept()
with conn:
    conn.settimeout(5)
    conn.sendall(b'detached')
"""

DETACHED_CLIENT = """
import socket, time
for attempt in range(40):
    try:
        with socket.create_connection(('127.0.0.1', 18765), timeout=1) as conn:
            assert conn.makefile('rb').read() == b'detached'
        break
    except ConnectionRefusedError:
        time.sleep(0.1)
else:
    raise RuntimeError('detached guest did not become reachable')
"""

ECHO = """
import os, sys
sys.stdout.buffer.write(b'R')
sys.stdout.buffer.flush()
while data := os.read(0, 65536):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
"""

HALF_CLOSE = """
import socket, sys, threading

with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    with socket.create_connection(listener.getsockname()) as bridge:
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(5)
            bridge.settimeout(5)
            def reply():
                request = peer.makefile('rb').read()
                peer.sendall(request[::-1])
                peer.shutdown(socket.SHUT_WR)

            worker = threading.Thread(target=reply)
            worker.start()
            bridge.sendall(sys.stdin.buffer.read())
            bridge.shutdown(socket.SHUT_WR)
            sys.stdout.buffer.write(bridge.makefile('rb').read())
            worker.join()
"""


def run(instance, record):
    def guest(*args):
        return ['container', 'exec', *args, instance, 'python3', '-I', '-c']

    record('detached-start', guest('--detach') + [DETACHED_SERVER])
    # This is a fresh provider CLI process after the launching CLI exited.
    record('detached-client', guest() + [DETACHED_CLIENT])

    payload = bytes(range(256)) * (32 * 1024)
    start = time.monotonic()
    with subprocess.Popen(
        guest('-i') + [ECHO], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=0,
    ) as proc:
        try:
            assert select.select([proc.stdout], [], [], 10)[0], 'echo readiness timed out'
            assert proc.stdout.read(1) == b'R', 'echo readiness marker missing'
            os.set_blocking(proc.stdin.fileno(), False)
            sent = 0
            deadline = time.monotonic() + 15
            # Deliberately withhold stdout reads and look for upstream backpressure.
            while sent < len(payload):
                assert time.monotonic() < deadline, 'filling the channel timed out'
                if not select.select([], [proc.stdin], [], 1)[1]:
                    break
                try:
                    sent += os.write(proc.stdin.fileno(), payload[sent:sent + 65536])
                except BlockingIOError:
                    continue
            os.set_blocking(proc.stdin.fileno(), True)
            output, error = proc.communicate(payload[sent:] if sent < len(payload) else b'', timeout=30)
            assert proc.returncode == 0, error
            assert output == payload, f'binary echo mismatch: {len(output)} bytes'
            record('binary-backpressure', None, details={
                'seconds': time.monotonic() - start,
                'payload_bytes': len(payload),
                'bytes_before_drain': sent,
                'writer_stalled': 0 < sent < len(payload),
            })
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    sample = bytes(range(256)) * 128 + b'\x00\x01'
    result = record('tcp-half-close', guest('-i') + [HALF_CLOSE], input=sample)
    assert result.stdout == sample[::-1], 'reply after stdin EOF or TCP FIN was truncated'
