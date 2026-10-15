import uuid
from dataclasses import replace

import pytest

from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.storage import crypto, db
from cleaner.storage.repo import CheckpointBusy, Item, Repository, StaleState


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


def test_deleted_chat_key_is_gone_from_the_wal_file(tmp_path, repo):
    """FR-1.4: служба держит соединение открытым, поэтому журнал WAL не должен хранить ключ чата."""
    user, chat = new_chat(repo)
    state, version = repo.load_state(chat)
    repo.commit_chat(chat, state, version, [input_item("текст", "очищено")])
    [wrapped] = repo.conn.execute("SELECT dek_wrapped FROM chats WHERE id = ?", (chat,)).fetchone()
    assert bytes(wrapped) in (tmp_path / "cleaner.db-wal").read_bytes()
    repo.delete_chat(chat)
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))
    assert bytes(wrapped) not in raw


def test_deleting_a_chat_does_not_hide_a_wal_that_was_not_truncated(repo, wal_reader):
    """Обзор 1В: занятая контрольная точка — копии страниц с ключом чата остались в журнале WAL."""
    user, chat = new_chat(repo)
    with pytest.raises(CheckpointBusy):
        repo.delete_chat(chat)
    assert repo.chat(chat) is None


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


def raw_database(tmp_path) -> bytes:
    return b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))


def test_queued_item_is_processed_and_its_fields_round_trip(repo):
    user, chat = new_chat(repo)
    queued = repo.add_item(chat, Item(uuid.uuid4().hex, 0, "input", "оригинал", None, source="file", status="queued"))
    assert (queued.seq, queued.status, queued.source) == (1, "queued", "file")
    repo.set_item_status(chat, queued.id, "running")
    repo.set_item_progress(chat, queued.id, "2/5")
    assert repo.item(chat, queued.id).meta == {"progress": "2/5"}
    state, version = repo.load_state(chat)
    done = replace(
        repo.item(chat, queued.id), sanitized="очищено", status="done", meta={"kind": "pdf", "layers": ["ner"]},
        model_spans=[{"start": 0, "end": 3, "type": "PERSON", "source": "ner", "score": 0.9}],
    )
    repo.commit_chat(chat, state, version, updated_items=[done])
    [stored] = repo.items(chat)
    assert (stored.status, stored.sanitized, stored.meta, stored.model_spans) == (
        "done", "очищено", {"kind": "pdf", "layers": ["ner"]}, done.model_spans,
    )
    assert repo.item(chat, "0" * 32) is None
    with pytest.raises(KeyError):
        repo.set_item_status(chat, "0" * 32, "failed", "причина")


def test_failure_reason_is_kept_and_cleared(repo):
    user, chat = new_chat(repo)
    item = repo.add_item(chat, Item(uuid.uuid4().hex, 0, "input", "текст", None, status="queued"))
    repo.set_item_status(chat, item.id, "failed", "Файл защищён паролем")
    assert repo.item(chat, item.id).meta == {"error": "Файл защищён паролем"}
    repo.set_item_status(chat, item.id, "queued")
    assert repo.item(chat, item.id).meta == {}
    repo.set_item_status(chat, item.id, "failed", "Файл защищён паролем")
    assert repo.queue_item(chat, item.id) and not repo.queue_item(chat, item.id)
    assert (repo.item(chat, item.id).status, repo.item(chat, item.id).meta) == ("queued", {})


def test_interrupted_processing_fails_at_start(repo):
    user, chat = new_chat(repo)
    repo.add_item(chat, Item("a" * 32, 0, "input", "x", None, status="running"))
    repo.add_item(chat, Item("b" * 32, 0, "input", "y", None, status="queued"))
    repo.add_item(chat, Item("c" * 32, 0, "input", "z", "z"))
    assert repo.set_item_risk_status(chat, "c" * 32, "running", ("",))
    assert repo.fail_interrupted("прервано") == 2
    assert [(i.status, i.meta.get("error"), i.risk_status) for i in repo.items(chat)] == [
        ("failed", "прервано", ""), ("failed", "прервано", ""), ("done", None, "interrupted"),
    ]


def test_extracted_text_and_risk_are_stored_encrypted(tmp_path, repo):
    user, chat = new_chat(repo)
    item = repo.add_item(chat, Item(uuid.uuid4().hex, 0, "input", "", None, source="file", status="running"))
    repo.set_item_original(chat, item.id, "извлечено Kk41", {"kind": "docx"})
    assert repo.set_item_risk_status(chat, item.id, "running", ("",))
    assert repo.set_item_risk(chat, item.id, {"guesses": [{"kind": "org", "guess": "Ромашка Gg52", "clue": ""}]})
    stored = repo.item(chat, item.id)
    assert (stored.original, stored.meta, stored.risk_status) == ("извлечено Kk41", {"kind": "docx"}, "done")
    assert repo.item_risk(chat, item.id)["guesses"][0]["guess"] == "Ромашка Gg52"
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = raw_database(tmp_path)
    for secret in ("Kk41", "Gg52"):
        assert secret.encode("utf-8") not in raw and secret.encode("utf-16-le") not in raw, secret


def test_chat_layers_follow_the_default_until_chosen(repo):
    user, chat = new_chat(repo)
    assert (repo.layer_defaults(), repo.chat_layers(chat)) == ({"ner": True, "llm": False}, {})
    repo.set_chat_layer(chat, "llm", True)
    repo.set_layer_defaults({"ner": True, "llm": False})
    assert (repo.chat_layers(chat), repo.layer_defaults()) == ({"llm": True}, {"ner": True, "llm": False})
    with pytest.raises(KeyError):
        repo.set_chat_layer("0" * 32, "ner", False)


def test_settings_are_stored_by_key(repo):
    assert repo.setting("local_llm.url") is None
    repo.set_setting("local_llm.url", "http://127.0.0.1:30000/v1")
    repo.set_setting("local_llm.url", "http://example:30000/v1")
    assert repo.setting("local_llm.url") == "http://example:30000/v1"


def test_gold_examples_are_encrypted_and_deleted(tmp_path, repo):
    user = repo.create_user("ivan", "hash", "user")
    spans = [{"start": 0, "end": 6, "type": "TERM", "entity": 0, "origin": "manual"}]
    gold_id = repo.add_gold(user, "эталон Ee61", spans)
    [row] = repo.gold()
    assert (row.id, row.user_id, row.text, row.spans) == (gold_id, user, "эталон Ee61", spans)
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    assert b"Ee61" not in raw_database(tmp_path)
    assert repo.delete_gold(gold_id) and repo.gold() == [] and not repo.delete_gold(gold_id)
