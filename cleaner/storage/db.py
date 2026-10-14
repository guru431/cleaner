"""Соединение с SQLite, схема и транзакции."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1
_SCHEMA = Path(__file__).with_name("schema.sql")


def connect(path: Path | str) -> sqlite3.Connection:
    """Соединение без неявных транзакций: границы задаёт transaction()."""
    conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA secure_delete = ON")     # удалённое перезаписывается на диске
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == SCHEMA_VERSION:
        return
    if version != 0:
        raise RuntimeError(f"база версии {version}, программа знает версию {SCHEMA_VERSION}")
    conn.executescript(_SCHEMA.read_text(encoding="utf-8"))
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
