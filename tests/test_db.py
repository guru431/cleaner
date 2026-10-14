import pytest

from cleaner.storage import db


def test_migrate_creates_the_schema_once(tmp_path):
    conn = db.connect(tmp_path / "cleaner.db")
    db.migrate(conn)
    db.migrate(conn)
    tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"users", "sessions", "chats", "items", "dictionary", "patterns", "policies", "settings", "audit"} <= tables
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_transaction_rolls_back_on_error(tmp_path):
    conn = db.connect(tmp_path / "cleaner.db")
    db.migrate(conn)
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            conn.execute("INSERT INTO settings(key, value) VALUES ('a', 'b')")
            raise RuntimeError("сбой посреди записи")
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0


def test_newer_schema_is_refused(tmp_path):
    conn = db.connect(tmp_path / "cleaner.db")
    conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION + 1}")
    with pytest.raises(RuntimeError):
        db.migrate(conn)
