"""Настройки запуска из cleaner.toml. Всё остальное хранится в базе и меняется в интерфейсе."""
from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    host: str = "127.0.0.1"
    port: int = 5464
    tls_cert: str = ""
    tls_key: str = ""
    data_dir: Path = Path("data")
    max_text_chars: int = 500_000
    utc_offset_hours: int = 3

    @property
    def db_path(self) -> Path:
        return self.data_dir / "cleaner.db"


def load(path: Path) -> Config:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    server, paths, limits, ui = (raw.get(name, {}) for name in ("server", "paths", "limits", "ui"))
    defaults = Config()
    return Config(
        host=str(server.get("host", defaults.host)),
        port=int(server.get("port", defaults.port)),
        tls_cert=str(server.get("tls_cert", "")),
        tls_key=str(server.get("tls_key", "")),
        data_dir=Path(paths.get("data_dir", defaults.data_dir)),
        max_text_chars=int(limits.get("max_text_chars", defaults.max_text_chars)),
        utc_offset_hours=int(ui.get("utc_offset_hours", defaults.utc_offset_hours)),
    )


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_transport(config: Config) -> None:
    """SEC-8: не на петлевом адресе служба работает только по TLS."""
    if not _loopback(config.host) and not (config.tls_cert and config.tls_key):
        raise ValueError(f"адрес {config.host} не петлевой: нужны tls_cert и tls_key")
