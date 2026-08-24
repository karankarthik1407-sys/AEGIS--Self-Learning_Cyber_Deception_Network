from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from .config import SETTINGS
from .server import handler_factory
from .service import AegisService


class ResidentControlPlane:
    """Owns the endpoint runtime, loopback API, and orderly shutdown path."""

    def __init__(
        self,
        host: str,
        port: int,
        database_path: Path,
        telemetry_interval_seconds: int = 30,
        static_root: Path = SETTINGS.static_path,
        session_token: str | None = None,
    ):
        self.service = AegisService(
            database_path,
            telemetry_interval_seconds=telemetry_interval_seconds,
        )
        self.server = ThreadingHTTPServer(
            (host, port),
            handler_factory(self.service, static_root, session_token=session_token),
        )
        self._stop_lock = threading.Lock()
        self._stop_requested = False

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def run(self) -> None:
        self.service.start_background_services()
        try:
            self.server.serve_forever(poll_interval=0.25)
        finally:
            self.service.stop_background_services()
            self.server.server_close()

    def request_stop(self) -> bool:
        with self._stop_lock:
            if self._stop_requested:
                return False
            self._stop_requested = True
        self.server.shutdown()
        return True
