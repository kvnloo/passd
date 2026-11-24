#!/opt/passd/bin/python -I
"""Deliver a single fresh unlock line from a privileged stdin pipe."""
import argparse
import errno
import fcntl
import os
import subprocess
import sys
import time
from pathlib import Path

from passd.client import PassdSession


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker-only", action="store_true", help="leave the gateway stopped")
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.stdin.isatty():
        print("passd-unlock requires root and piped stdin", file=sys.stderr)
        return 2
    line = sys.stdin.buffer.readline(4097)
    if len(line) < 2 or len(line) > 4096 or not line.endswith(b"\n"):
        print("passd-unlock requires one nonempty newline-terminated line (at most 4096 bytes)", file=sys.stderr)
        return 2
    runtime = Path("/run/passd-unlock")
    try:
        with (runtime / "lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.broker_only:
                subprocess.run(["systemctl", "stop", "passd-gateway.service"], check=True, timeout=10)
            subprocess.run(["systemctl", "start", "passd.service"], check=True, timeout=10)
            deadline = time.monotonic() + 10
            while True:
                try:
                    fd = os.open(runtime / "input", os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                    break
                except OSError as exc:
                    if exc.errno != errno.ENXIO or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
            client = PassdSession(Path("/run/passd/passd.sock"), remote="")
            while time.monotonic() < deadline:
                try:
                    with client:
                        assert client.sock is not None
                        client.sock.settimeout(1)
                        ready = client.call("health")["ok"]
                    if ready:
                        if not args.broker_only:
                            subprocess.run(["systemctl", "start", "passd-gateway.service"], check=True, timeout=10)
                        return 0
                except OSError:
                    time.sleep(0.05)
    except Exception:
        pass
    print("passd unlock did not complete; check passd.service status", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
