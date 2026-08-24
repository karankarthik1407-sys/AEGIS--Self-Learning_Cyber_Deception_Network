from __future__ import annotations

import argparse
import ctypes
import os
import threading
from pathlib import Path
from typing import Any

from ctypes import wintypes

from .config import SETTINGS
from .runtime import ResidentControlPlane


SERVICE_NAME = "AEGISNode"
SERVICE_DISPLAY_NAME = "AEGIS Resident Security Node"

SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004
SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004
SERVICE_ACCEPT_PRESHUTDOWN = 0x00000100
SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_SHUTDOWN = 0x00000005
SERVICE_CONTROL_PRESHUTDOWN = 0x0000000F
ERROR_SUCCESS = 0

CALLBACK = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
ServiceMainCallback = CALLBACK(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
HandlerExCallback = CALLBACK(
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
)


class ServiceStatus(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class ServiceTableEntry(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpServiceProc", ServiceMainCallback),
    ]


class WindowsServiceHost:
    def __init__(
        self,
        host: str,
        port: int,
        database_path: Path,
        telemetry_interval_seconds: int,
        session_token_file: Path | None = None,
    ):
        self.host = host
        self.port = port
        self.database_path = database_path
        self.telemetry_interval_seconds = telemetry_interval_seconds
        self.session_token_file = session_token_file
        self.runtime: ResidentControlPlane | None = None
        self.status_handle: Any = None
        self.checkpoint = 0
        self._service_main_callback = ServiceMainCallback(self._service_main)
        self._handler_callback = HandlerExCallback(self._control_handler)

    @staticmethod
    def _advapi32() -> Any:
        if os.name != "nt":
            raise RuntimeError("The AEGIS Windows Service host can only run on Windows.")
        library = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        library.RegisterServiceCtrlHandlerExW.argtypes = [
            wintypes.LPCWSTR,
            HandlerExCallback,
            wintypes.LPVOID,
        ]
        library.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
        library.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(ServiceStatus)]
        library.SetServiceStatus.restype = wintypes.BOOL
        library.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(ServiceTableEntry)]
        library.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
        return library

    def _session_token(self) -> str | None:
        if self.session_token_file is None:
            return None
        token = self.session_token_file.read_text(encoding="ascii").strip()
        if len(token) < 32 or len(token) > 256 or not token.isascii():
            raise ValueError("AEGIS service session token is invalid")
        return token

    def dispatch(self) -> None:
        advapi32 = self._advapi32()
        table = (ServiceTableEntry * 2)()
        table[0].lpServiceName = SERVICE_NAME
        table[0].lpServiceProc = self._service_main_callback
        table[1].lpServiceName = None
        table[1].lpServiceProc = ServiceMainCallback()
        if not advapi32.StartServiceCtrlDispatcherW(table):
            error = ctypes.get_last_error()
            raise OSError(error, "StartServiceCtrlDispatcherW failed")

    def _report(
        self,
        state: int,
        controls: int = 0,
        wait_hint_ms: int = 0,
        win32_exit_code: int = ERROR_SUCCESS,
    ) -> None:
        if not self.status_handle:
            return
        pending = state in (SERVICE_START_PENDING, SERVICE_STOP_PENDING)
        self.checkpoint = self.checkpoint + 1 if pending else 0
        status = ServiceStatus(
            SERVICE_WIN32_OWN_PROCESS,
            state,
            controls,
            win32_exit_code,
            0,
            self.checkpoint,
            wait_hint_ms,
        )
        if not self._advapi32().SetServiceStatus(self.status_handle, ctypes.byref(status)):
            error = ctypes.get_last_error()
            raise OSError(error, "SetServiceStatus failed")

    def _service_main(self, _argc: int, _argv: Any) -> None:
        advapi32 = self._advapi32()
        self.status_handle = advapi32.RegisterServiceCtrlHandlerExW(
            SERVICE_NAME,
            self._handler_callback,
            None,
        )
        if not self.status_handle:
            return
        self._report(SERVICE_START_PENDING, wait_hint_ms=20_000)
        exit_code = ERROR_SUCCESS
        try:
            os.environ["AEGIS_SERVICE_MODE"] = "1"
            self.runtime = ResidentControlPlane(
                self.host,
                self.port,
                self.database_path,
                self.telemetry_interval_seconds,
                session_token=self._session_token(),
            )
            controls = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN
            self._report(SERVICE_RUNNING, controls=controls)
            self.runtime.run()
        except Exception:
            exit_code = 1
        finally:
            self._report(SERVICE_STOPPED, win32_exit_code=exit_code)

    def _control_handler(
        self,
        control: int,
        _event_type: int,
        _event_data: Any,
        _context: Any,
    ) -> int:
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_PRESHUTDOWN):
            self._report(SERVICE_STOP_PENDING, wait_hint_ms=20_000)
            if self.runtime is not None:
                threading.Thread(
                    target=self.runtime.request_stop,
                    name="aegis-service-stop",
                    daemon=True,
                ).start()
        return ERROR_SUCCESS


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Host AEGIS as a Windows Service")
    parser.add_argument("--host", default=SETTINGS.host)
    parser.add_argument("--port", type=int, default=SETTINGS.port)
    parser.add_argument("--database", type=Path, default=SETTINGS.database_path)
    parser.add_argument("--telemetry-interval", type=int, default=30)
    parser.add_argument("--session-token-file", type=Path)
    parser.add_argument(
        "--console",
        action="store_true",
        help="Run the resident host in the current terminal for diagnostics.",
    )
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    if args.console:
        host = WindowsServiceHost(
            args.host,
            args.port,
            args.database,
            args.telemetry_interval,
            args.session_token_file,
        )
        runtime = ResidentControlPlane(
            args.host,
            args.port,
            args.database,
            args.telemetry_interval,
            session_token=host._session_token(),
        )
        address = runtime.address
        print(f"AEGIS resident diagnostic host: http://{address[0]}:{address[1]}")
        try:
            runtime.run()
        except KeyboardInterrupt:
            pass
        return
    WindowsServiceHost(
        args.host,
        args.port,
        args.database,
        args.telemetry_interval,
        args.session_token_file,
    ).dispatch()


if __name__ == "__main__":
    main()
