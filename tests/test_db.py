import sqlite3
from pathlib import Path

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


def test_schema_version_is_the_last_migration():
    assert db.SCHEMA_VERSION == max(number for number, _ in db.migrations()) == 7


def test_version_2_chat_gets_no_provider(tmp_path):
    """Версия 3 (этап 3): у прежних чатов подключение не выбрано — ручной режим, как был."""
    conn = db.connect(tmp_path / "cleaner.db")
    db.migrate(conn)
    conn.execute(
        "INSERT INTO users(id, login, password_hash, role, disabled, created_at) VALUES ('u', 'ivan', 'h', 'user', 0, 't')"
    )
    conn.execute(
        "INSERT INTO chats(id, user_id, title_enc, dek_wrapped, state_enc, version, created_at, updated_at) "
        "VALUES ('c', 'u', x'00', x'00', x'00', 0, 't', 't')"
    )
    assert tuple(conn.execute("SELECT provider_id, model FROM chats").fetchone()) == (None, "")
    assert conn.execute("SELECT COUNT(*) FROM providers").fetchone()[0] == 0


def test_version_1_database_upgrades_in_place(tmp_path):
    conn = db.connect(tmp_path / "cleaner.db")
    conn.executescript(Path(db.__file__).with_name("schema.sql").read_text(encoding="utf-8"))
    conn.execute("PRAGMA user_version = 1")
    conn.execute(
        "INSERT INTO users(id, login, password_hash, role, disabled, created_at) VALUES ('u', 'ivan', 'h', 'user', 0, 't')"
    )
    conn.execute(
        "INSERT INTO chats(id, user_id, title_enc, dek_wrapped, state_enc, version, created_at, updated_at) "
        "VALUES ('c', 'u', x'00', x'00', x'00', 0, 't', 't')"
    )
    for seq, kind in ((1, "input"), (2, "answer")):
        conn.execute(
            "INSERT INTO items(id, chat_id, seq, kind, original_enc, created_at) VALUES (?, 'c', ?, ?, x'00', 't')",
            (f"i{seq}", seq, kind),
        )
    db.migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    rows = [tuple(row) for row in conn.execute(
        "SELECT kind, source, status, meta, model_spans, risk_status, risk_enc, risk_job, reviewed_at FROM items ORDER BY seq"
    )]
    assert rows == [
        ("input", "paste", "done", "{}", "[]", "", None, None, None),
        ("answer", "pasted_answer", "done", "{}", "[]", "", None, None, None),
    ]
    assert conn.execute("SELECT layers FROM chats").fetchone()[0] == "{}"
    tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "gold" in tables


def test_failed_migration_leaves_the_previous_version(tmp_path):
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0002_broken.sql").write_text(
        "ALTER TABLE items ADD COLUMN extra TEXT;\nTHIS IS NOT SQL;\n", encoding="utf-8"
    )
    conn = db.connect(tmp_path / "cleaner.db")
    with pytest.raises(sqlite3.Error):
        db.migrate(conn, migrations)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    assert "extra" not in {row["name"] for row in conn.execute("PRAGMA table_info(items)")}


def test_migration_numbers_must_follow_each_other(tmp_path):
    (tmp_path / "0003_gap.sql").write_text("SELECT 1;", encoding="utf-8")
    with pytest.raises(RuntimeError):
        db.migrations(tmp_path)
