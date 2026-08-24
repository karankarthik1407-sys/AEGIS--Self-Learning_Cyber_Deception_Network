from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    root: Path = Path(__file__).resolve().parents[1]
    host: str = "127.0.0.1"
    port: int = 8765
    product_name: str = "AEGIS"
    deployment_profile: str = "Desktop Research Edition"
    authorized_namespace: str = "aegis-range"
    max_action_memory_mb: int = 256
    max_action_cpu_cores: float = 1.0
    max_action_ttl_seconds: int = 900

    @property
    def database_path(self) -> Path:
        return self.root / "data" / "aegis.db"

    @property
    def static_path(self) -> Path:
        candidates = [
            self.root / "web",
            Path(getattr(sys, "_MEIPASS", self.root)) / "web",
            Path(sys.prefix) / "share" / "aegis" / "web",
        ]
        for candidate in candidates:
            if candidate.is_dir():
                return candidate
        return candidates[0]

    @property
    def desktop_data_root(self) -> Path:
        override = os.environ.get("AEGIS_DATA_ROOT")
        if override:
            return Path(override).expanduser().resolve()
        if os.name == "nt":
            local_app_data = os.environ.get("LOCALAPPDATA")
            base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
            return base / "AEGIS"
        xdg_data = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg_data) if xdg_data else Path.home() / ".local" / "share"
        return base / "aegis"


SETTINGS = Settings()
