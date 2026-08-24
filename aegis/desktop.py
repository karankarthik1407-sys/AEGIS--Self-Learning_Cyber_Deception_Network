from __future__ import annotations

import argparse
import ctypes
import importlib
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from urllib.error import URLError
from urllib.request import Request, urlopen

from .config import SETTINGS
from .runtime import ResidentControlPlane
from .version import PRODUCT_VERSION


DEFAULT_SERVICE_URL = "http://127.0.0.1:8765"


def probe_aegis(url: str, timeout: float = 0.75) -> dict | None:
    """Return a validated AEGIS health document from a candidate endpoint."""

    try:
        request = Request(f"{url.rstrip('/')}/api/health", method="GET")
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("product") != "AEGIS" or payload.get("status") != "healthy":
        return None
    return payload


class EmbeddedDesktopRuntime:
    """Window-owned local runtime used when the resident service is unavailable."""

    def __init__(
        self,
        data_root: Path,
        port: int = 0,
        telemetry_interval_seconds: int = 30,
        static_root: Path = SETTINGS.static_path,
    ):
        self.data_root = Path(data_root).resolve()
        self.data_root.mkdir(parents=True, exist_ok=True)
        self._previous_desktop_mode = os.environ.get("AEGIS_DESKTOP_MODE")
        os.environ["AEGIS_DESKTOP_MODE"] = "1"
        self.session_token = secrets.token_urlsafe(32)
        self.runtime = ResidentControlPlane(
            "127.0.0.1",
            port,
            self.data_root / "aegis.db",
            telemetry_interval_seconds=telemetry_interval_seconds,
            static_root=static_root,
            session_token=self.session_token,
        )
        self.thread: threading.Thread | None = None
        self.failure: BaseException | None = None

    @property
    def url(self) -> str:
        host, port = self.runtime.address
        return f"http://{host}:{port}"

    def start(self, timeout_seconds: float = 8.0) -> str:
        if self.thread is not None:
            return self.url

        def runner() -> None:
            try:
                self.runtime.run()
            except BaseException as error:  # retained for the main-thread readiness check
                self.failure = error

        self.thread = threading.Thread(target=runner, name="aegis-desktop-runtime", daemon=True)
        self.thread.start()
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self.failure is not None:
                raise RuntimeError("AEGIS embedded runtime failed to start") from self.failure
            health = probe_aegis(self.url, timeout=0.35)
            if health and health.get("release") == PRODUCT_VERSION:
                return self.url
            time.sleep(0.05)
        self.stop()
        raise TimeoutError("AEGIS embedded runtime did not become healthy")

    def stop(self) -> None:
        thread = self.thread
        if thread is None:
            return
        self.runtime.request_stop()
        thread.join(timeout=5)
        self.thread = None
        if self._previous_desktop_mode is None:
            os.environ.pop("AEGIS_DESKTOP_MODE", None)
        else:
            os.environ["AEGIS_DESKTOP_MODE"] = self._previous_desktop_mode


@dataclass
class DesktopSession:
    url: str
    mode: str
    embedded: EmbeddedDesktopRuntime | None = None

    @classmethod
    def open(
        cls,
        data_root: Path,
        service_url: str = DEFAULT_SERVICE_URL,
        force_standalone: bool = False,
        port: int = 0,
        telemetry_interval_seconds: int = 30,
        static_root: Path = SETTINGS.static_path,
    ) -> "DesktopSession":
        if not force_standalone:
            health = probe_aegis(service_url)
            if health and health.get("release") == PRODUCT_VERSION:
                return cls(service_url.rstrip("/"), "resident-service")
        embedded = EmbeddedDesktopRuntime(
            data_root,
            port=port,
            telemetry_interval_seconds=telemetry_interval_seconds,
            static_root=static_root,
        )
        return cls(embedded.start(), "embedded-desktop", embedded)

    def close(self, *_args: object) -> None:
        if self.embedded is not None:
            self.embedded.stop()


def run_headless_check(data_root: Path, static_root: Path = SETTINGS.static_path) -> dict:
    session = DesktopSession.open(
        data_root,
        force_standalone=True,
        telemetry_interval_seconds=3600,
        static_root=static_root,
    )
    try:
        health = probe_aegis(session.url, timeout=2)
        if not health:
            raise RuntimeError("desktop health check failed")
        return {
            "status": "healthy",
            "release": health["release"],
            "mode": session.mode,
            "loopback": session.url.startswith("http://127.0.0.1:"),
        }
    finally:
        session.close()


def _load_webview() -> ModuleType:
    try:
        return importlib.import_module("webview")
    except ImportError as error:
        raise RuntimeError(
            "The desktop renderer is not installed. Install AEGIS with the desktop extra."
        ) from error


def _show_fatal(message: str) -> None:
    if os.name == "nt":
        ctypes.windll.user32.MessageBoxW(0, message, "AEGIS could not start", 0x10)  # type: ignore[attr-defined]
    else:
        print(message, file=sys.stderr)


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launch the AEGIS desktop control plane")
    parser.add_argument("--data-root", type=Path, default=SETTINGS.desktop_data_root)
    parser.add_argument("--service-url", default=DEFAULT_SERVICE_URL)
    parser.add_argument("--standalone", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--telemetry-interval", type=int, default=30)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--headless-check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    if args.headless_check:
        result = run_headless_check(args.data_root)
        if sys.stdout is not None:
            print(json.dumps(result, sort_keys=True))
        return 0

    session: DesktopSession | None = None
    try:
        session = DesktopSession.open(
            args.data_root,
            service_url=args.service_url,
            force_standalone=args.standalone,
            port=args.port,
            telemetry_interval_seconds=args.telemetry_interval,
        )
        webview = _load_webview()
        webview.settings["ALLOW_DOWNLOADS"] = False
        webview.settings["ALLOW_FILE_URLS"] = False
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False
        webview.settings["OPEN_DEVTOOLS_IN_DEBUG"] = bool(args.debug)
        webview.settings["REMOTE_DEBUGGING_PORT"] = None
        window = webview.create_window(
            "AEGIS — Autonomous Deception Intelligence",
            session.url,
            width=1500,
            height=940,
            min_size=(1100, 700),
            resizable=True,
            maximized=True,
            background_color="#030506",
            text_select=True,
            zoomable=False,
            draggable=False,
        )
        window.events.closed += session.close
        webview.start(
            gui="edgechromium" if os.name == "nt" else None,
            debug=bool(args.debug),
            private_mode=True,
            user_agent=f"AEGIS-Desktop/{PRODUCT_VERSION}",
        )
        return 0
    except Exception as error:
        _show_fatal(str(error))
        return 1
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    raise SystemExit(main())
