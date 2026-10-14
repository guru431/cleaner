import uuid

import pytest

from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.storage import crypto, db
from cleaner.storage.repo import Item, Repository, StaleState


def new_chat(repo, title="Чат"):
    user = repo.create_user("ivan", "hash", "user")
    return user, repo.create_chat(user, title)


def input_item(text, sanitized):
    return Item(uuid.uuid4().hex, 0, "input", text, sanitized, [{"start": 0, "end": 1}])


def test_content_is_not_stored_in_clear(tmp_path, repo):
    """AC-1.8 на уровне хранилища: заголовок, оригинал, очищенный текст и словарь — шифртекст."""
    user, chat = new_chat(repo, "Заголовок Zx91")
    state, version = repo.load_state(chat)
    repo.commit_chat(chat, state, version, [input_item("оригинал Qq77", "очищено Ee33")])
    repo.add_dictionary("always", "Ромашка Ww55", T.ORG, ("Romashka Rr22",), "комментарий Cc11")
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))
    for secret in ("Zx91", "Qq77", "Ee33", "Ww55", "Rr22", "Cc11"):
        assert secret.encode("utf-8") not in raw and secret.encode("utf-16-le") not in raw, secret


def test_chat_round_trip(repo):
    user, chat = new_chat(repo, "Консультация")
    state, version = repo.load_state(chat)
    assert (state.chat_id, len(state.net_key), version) == (chat, 32, 0)
    first = input_item("текст", "очищено")
    repo.commit_chat(chat, state, version, [first])
    first.sanitized = "заново"
    repo.commit_chat(chat, state, version + 1, updated_items=[first])
    [stored] = repo.items(chat)
    assert (stored.seq, stored.original, stored.sanitized, stored.spans) == (1, "текст", "заново", [{"start": 0, "end": 1}])
    repo.rename_chat(chat, "Новое имя")
    assert [c.title for c in repo.chats(user)] == ["Новое имя"]


def test_commit_with_a_stale_version_is_refused(repo):
    user, chat = new_chat(repo)
    state, version = repo.load_state(chat)
    repo.commit_chat(chat, state, version)
    with pytest.raises(StaleState):
        repo.commit_chat(chat, state, version, [input_item("x", "x")])
    assert repo.items(chat) == []


def test_deleting_a_chat_removes_its_key_and_items(repo):
    user, chat = new_chat(repo)
    state, version = repo.load_state(chat)
    repo.commit_chat(chat, state, version, [input_item("текст", "очищено")])
    repo.delete_chat(chat)
    assert repo.chat(chat) is None
    assert repo.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0


def test_wrong_master_key_stops_the_start(tmp_path, repo, clock):
    conn = db.connect(tmp_path / "cleaner.db")
    with pytest.raises(crypto.CryptoError):
        Repository(conn, bytes(32), clock)


def test_settings_from_dictionary_patterns_and_policies(repo):
    repo.add_dictionary("always", "Ромашка", T.ORG, ("Romashka",))
    repo.add_dictionary("never", "Microsoft.COM ")
    kept = repo.add_pattern("инвентарный", r"INV-\d{6}", T.TERM)
    dropped = repo.add_pattern("старый", r"OLD-\d+", T.TERM)
    repo.conn.execute("UPDATE patterns SET enabled = 0 WHERE id = ?", (dropped,))
    repo.set_policy(T.CARD, Policy.BLOCK)
    settings = repo.settings()
    assert [(e.type, e.value, e.aliases) for e in settings.always] == [(T.ORG, "Ромашка", ("Romashka",))]
    assert settings.never == frozenset({"microsoft.com"})
    assert [p.name for p in settings.patterns] == ["инвентарный"]
    assert settings.policies[T.CARD] is Policy.BLOCK and settings.policies[T.SECRET] is Policy.HIDE
    assert kept


def test_import_writes_all_values_at_once(repo):
    assert repo.add_dictionary_many("always", ["srv1.corp.example", "srv2.corp.example"], T.HOST) == 2
    assert sorted((r.list, r.type, r.value) for r in repo.dictionary()) == [
        ("always", T.HOST, "srv1.corp.example"), ("always", T.HOST, "srv2.corp.example"),
    ]


def test_users_sessions_and_audit(repo, clock):
    user = repo.create_user("ivan", "hash1", "admin")
    repo.create_session("t1", user, "csrf1")
    clock.advance(minutes=5)
    repo.touch_session("t1")
    assert repo.session("t1").last_seen_at == clock.now().isoformat(timespec="seconds")
    repo.set_password(user, "hash2")
    assert repo.session("t1") is None and repo.user(user).password_hash == "hash2"
    repo.audit("login", user, details_ok=1)
    clock.advance(days=1)
    repo.audit("logout", user)
    assert [(a.event, a.details) for a in repo.audit_events("login")] == [("login", {"details_ok": 1})]
    assert [a.event for a in repo.audit_events(since="2026-10-15")] == ["logout"]
    assert [a.event for a in repo.audit_events(before="2026-10-15")] == ["login"]


def test_backup_opens_with_the_same_key(tmp_path, repo, clock):
    user, chat = new_chat(repo, "Копия")
    repo.backup(tmp_path / "copy.db")
    copy = Repository(db.connect(tmp_path / "copy.db"), bytes(range(32)), clock)
    assert [c.title for c in copy.chats(user)] == ["Копия"]
