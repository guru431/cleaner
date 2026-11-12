"""Соединение с SQLite, схема, нумерованные миграции и транзакции."""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_SCHEMA = Path(__file__).with_name("schema.sql")          # версия 1
_MIGRATIONS = Path(__file__).with_name("migrations")       # 0002_*.sql, 0003_*.sql, …
_NUMBERED = re.compile(r"(\d{4})_[a-z0-9_]+\.sql")


def migrations(directory: Path | None = None) -> list[tuple[int, Path]]:
    """Файлы миграций по возрастанию номера. Номера идут подряд с 2: пропуск — ошибка сборки, а не тихий сбой."""
    found = []
    for path in (directory or _MIGRATIONS).glob("*.sql"):
        m = _NUMBERED.fullmatch(path.name)
        if m:
            found.append((int(m.group(1)), path))
    found.sort()
    numbers = [number for number, _ in found]
    if numbers != list(range(2, 2 + len(numbers))):
        raise RuntimeError(f"миграции должны идти подряд с 0002: {numbers}")
    return found


SCHEMA_VERSION = max((number for number, _ in migrations()), default=1)


def connect(path: Path | str) -> sqlite3.Connection:
    """Соединение без неявных транзакций: границы задаёт transaction()."""
    conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA secure_delete = ON")     # удалённое перезаписывается на диске
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _statements(script: str) -> Iterator[str]:
    """Скрипт по одному оператору: executescript сам фиксирует открытую транзакцию."""
    statement = ""
    for piece in script.split(";"):
        statement += piece + ";"
        if sqlite3.complete_statement(statement):
            yield statement
            statement = ""


def _apply(conn: sqlite3.Connection, script: str, version: int) -> None:
    """Скрипт и номер версии — одной транзакцией: сбой посередине не оставляет половину схемы.
    Версия перечитывается под замком: другой процесс мог применить этот номер, пока мы ждали."""
    with transaction(conn):
        if conn.execute("PRAGMA user_version").fetchone()[0] >= version:
            return
        for statement in _statements(script):
            conn.execute(statement)
        conn.execute(f"PRAGMA user_version = {version}")


def migrate(conn: sqlite3.Connection, directory: Path | None = None) -> None:
    """Пустая база получает схему версии 1, затем все миграции по порядку, каждую — своей транзакцией."""
    steps = migrations(directory)
    latest = max((number for number, _ in steps), default=1)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > latest:
        raise RuntimeError(f"база версии {version}, программа знает версию {latest}")
    if version == 0:
        _apply(conn, _SCHEMA.read_text(encoding="utf-8"), 1)
        version = 1
    for number, path in steps:
        if number > version:
            _apply(conn, path.read_text(encoding="utf-8"), number)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
