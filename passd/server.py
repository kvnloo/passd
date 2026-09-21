from __future__ import annotations

import json
import os
import signal
import socketserver
import threading
from pathlib import Path

from .errors import PassdError

MAX_REQUEST = 2 * 1024 * 1024


class PassdHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # Multiple newline-delimited requests may share one Unix socket. CLI use
        # remains one-shot; SDK/agent callers can amortize connect/syscall cost.
        while True:
            raw = self.rfile.readline(MAX_REQUEST + 1)
            if not raw:
                return
            if len(raw) > MAX_REQUEST:
                self._send({"ok": False, "error": {"code": "request_too_large", "message": "request exceeds 2 MiB"}})
                return
            try:
                request = json.loads(raw.decode("utf-8"))
                result = self.server.service.handle(request)
                self._send({"ok": True, "result": result})
            except PassdError as exc:
                self._send({"ok": False, "error": {"code": exc.code, "message": str(exc)}})
            except Exception as exc:
                self._send({"ok": False, "error": {"code": "internal_error", "message": str(exc)}})

    def _send(self, value):
        self.wfile.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
        self.wfile.flush()


class PassdUnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, socket_path: Path, service):
        self.socket_path = socket_path
        self.service = service
        if socket_path.exists():
            socket_path.unlink()
        socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        super().__init__(str(socket_path), PassdHandler)
        os.chmod(socket_path, 0o600)

    def server_close(self):
        super().server_close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass


def serve(socket_path: Path, service):
    server = PassdUnixServer(socket_path, service)
    stop = threading.Event()

    def handle_signal(signum, frame):
        if not stop.is_set():
            stop.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    old_int = signal.signal(signal.SIGINT, handle_signal)
    old_term = signal.signal(signal.SIGTERM, handle_signal)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        server.server_close()
        service.close()
