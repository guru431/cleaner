"""Отпечаток установленного кода: по нему видно, какая версия стоит на сервере. Доставка — git archive, git там нет,
поэтому отпечаток — sha256 исходников всего пакета, как у паспорта качества (eval.runner.code_fingerprint, там — только
ядра). Дата — самого нового файла: git archive ставит файлам время коммита, установщик его сохраняет."""
from __future__ import annotations

import functools
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Build:
    digest: str            # sha256 исходников, переводы строк приведены к LF
    date: str              # ГГГГ-ММ-ДД самого нового файла, UTC

    @property
    def short(self) -> str:
        return self.digest[:12]

    def line(self) -> str:
        return f"Код: {self.short} от {self.date} (sha256 исходников {self.digest})"


def fingerprint(root: Path = PACKAGE) -> Build:
    """Все файлы пакета, кроме __pycache__, по относительному пути: на Windows и Linux отпечаток тот же."""
    files = sorted(
        (path.relative_to(root).as_posix(), path)
        for path in root.rglob("*") if path.is_file() and "__pycache__" not in path.parts
    )
    digest, newest = hashlib.sha256(), 0.0
    for name, path in files:
        digest.update(name.encode("utf-8") + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
        newest = max(newest, path.stat().st_mtime)
    return Build(digest.hexdigest(), datetime.fromtimestamp(newest, timezone.utc).date().isoformat())


@functools.cache
def current() -> Build:
    """Отпечаток кода этого процесса: считается один раз — замена файлов под работающей службой его не меняет."""
    return fingerprint()
