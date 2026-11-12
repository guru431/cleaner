import uuid
from dataclasses import replace
from datetime import timedelta

import pytest

from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.storage import crypto, db
from cleaner.storage.repo import CheckpointBusy, Item, LedgerEntry, Provider, Repository, StaleState
from cleaner.web import auth


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


def test_settings_apply_internal_suffixes_added_by_the_admin(repo):
    """Дополнения внутренних суффиксов действуют в любом пути, который берёт настройки из базы (cleaner eval, verify и
    другие команды), а не только в веб-службе после старта."""
    from cleaner.core.entities import hostmap

    repo.set_setting("internal_suffixes.extra", '["lcl"]')
    try:
        assert not hostmap.has_known_suffix("srv01.romashka.lcl")
        repo.settings()
        assert hostmap.has_known_suffix("srv01.romashka.lcl")
        repo.set_setting("internal_suffixes.extra", "[]")
        repo.settings()
        assert not hostmap.has_known_suffix("srv01.romashka.lcl")
    finally:
        hostmap.set_extra_suffixes(())


def test_import_writes_all_values_at_once(repo):
    assert repo.add_dictionary_many("always", ["srv1.corp.example", "srv2.corp.example"], T.HOST) == 2
    assert sorted((r.list, r.type, r.value) for r in repo.dictionary()) == [
        ("always", T.HOST, "srv1.corp.example"), ("always", T.HOST, "srv2.corp.example"),
    ]


def test_dictionary_membership_decrypts_only_needed_values(repo, clock, monkeypatch):
    first = repo.add_dictionary("always", "Ромашка", T.ORG, ("Romashka",), "комментарий")
    clock.advance(seconds=1)
    repo.add_dictionary("always", "Сосна", T.ORG)
    other = repo.add_dictionary("never", "Берёза")
    decrypt = repo._dec
    opened = []

    def tracked(key, data, aad):
        opened.append(aad)
        return decrypt(key, data, aad)

    monkeypatch.setattr(repo, "_dec", tracked)
    assert repo.in_dictionary("always", "РОМАШКА")
    assert opened == [f"dictionary.value:{first}"]
    opened.clear()
    assert not repo.in_dictionary("never", "РОМАШКА")
    assert opened == [f"dictionary.value:{other}"]
    assert not repo.in_dictionary("always", "Romashka")  # псевдоним не считается отдельной записью
    repo.delete_dictionary(first)
    assert not repo.in_dictionary("always", "РОМАШКА")


def test_users_sessions_and_audit(repo, clock):
    user = repo.create_user("ivan", "hash1", "admin")
    assert repo.create_session("t1", user, "csrf1", "hash1")
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


def test_audit_counts_without_loading_rows_and_filters_by_index(repo, clock):
    """Блок «Служба» опрашивается раз в 5 с: счётчики журнала — COUNT по индексам, без просмотра всей таблицы."""
    repo.audit("error", kind="CheckpointBusy")
    repo.audit("error", kind="Timeout")
    clock.advance(days=2)
    repo.audit("error", kind="CheckpointBusy")
    repo.audit("agent_send")
    since = "2026-10-15"
    assert repo.audit_count(since=since) == 2 and repo.audit_count("error") == 3
    assert repo.audit_count("error", kind="CheckpointBusy") == len(repo.audit_events("error", kind="CheckpointBusy")) == 2
    assert repo.audit_count("error", since=since, kind="CheckpointBusy") == 1
    for event, start in (("error", since), (None, since)):
        where, args = repo._audit_where(event, None, start, None, None)
        plan = " ".join(row[3] for row in repo.conn.execute("EXPLAIN QUERY PLAN SELECT COUNT(*) FROM audit" + where, args))
        assert "USING COVERING INDEX audit_by_" in plan, plan


def test_session_opens_only_for_the_checked_password_of_an_enabled_account(repo):
    """Аудит 21.10.2026: сессия сверяет хэш, проверенный при входе, с нынешним — в той же записи."""
    user = repo.create_user("ivan", "hash1", "user")
    assert not repo.create_session("t0", user, "csrf0", "hash0")
    repo.set_disabled(user, True)
    assert not repo.create_session("t1", user, "csrf1", "hash1")
    repo.set_disabled(user, False)
    assert repo.create_session("t2", user, "csrf2", "hash1")
    assert [repo.session(token) is not None for token in ("t0", "t1", "t2")] == [False, False, True]


def test_role_of_the_last_active_admin_stays(repo):
    """Идея «Смена роли…»: снять роль с последнего активного администратора нельзя, и когда есть отключённый. Проверка
    и запись — одним UPDATE: два администратора, снимающие роль друг с друга разом, его не обойдут."""
    boss = repo.create_user("boss", "hash", "admin")
    anna = repo.create_user("anna", "hash", "admin")
    repo.set_disabled(anna, True)
    assert not repo.set_role(boss, "user") and repo.user(boss).role == "admin"
    assert repo.set_role(anna, "user") and repo.set_role(anna, "admin")      # у отключённого — можно
    repo.set_disabled(anna, False)
    assert repo.set_role(boss, "user") and not repo.set_role(anna, "user")
    assert not repo.set_role("нет", "admin")


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
    job = repo.queue_risk(chat, "c" * 32, ("",))
    assert job and repo.set_item_risk_status(chat, "c" * 32, job, "running", ("queued",))
    assert repo.fail_interrupted("прервано") == 2
    assert [(i.status, i.meta.get("error"), i.risk_status) for i in repo.items(chat)] == [
        ("failed", "прервано", ""), ("failed", "прервано", ""), ("done", None, "interrupted"),
    ]
    assert not repo.set_item_risk_status(chat, "c" * 32, job, "running", ("interrupted",))     # задание прервано


def test_interrupted_file_without_extracted_text_asks_for_the_file_again(repo):
    """Файл не хранится: прерванный до извлечения текста разбор повторить нельзя — своя причина. Извлечённый текст
    (в meta есть kind) очищается заново, как вставленный."""
    user, chat = new_chat(repo)
    repo.add_item(chat, Item("a" * 32, 0, "input", "", None, source="file", status="running", meta={"progress": "1/5"}))
    repo.add_item(chat, Item("b" * 32, 0, "input", "", None, source="file", status="queued"))
    repo.add_item(chat, Item("c" * 32, 0, "input", "текст", None, source="file", status="running", meta={"kind": "pdf"}))
    repo.add_item(chat, Item("d" * 32, 0, "input", "текст", None, status="running"))
    assert repo.fail_interrupted("прервано", file_reason="загрузите файл") == 4
    assert [i.meta.get("error") for i in repo.items(chat)] == ["загрузите файл", "загрузите файл", "прервано", "прервано"]


def test_risk_transitions_belong_to_their_job(repo):
    """Аудит 21.10.2026: прежняя проверка, сброшенная сменой текста, не завершает новую — ни догадками, ни отказом;
    догадки о другом очищенном тексте не записываются и у своего задания."""
    user, chat = new_chat(repo)
    item = repo.add_item(chat, Item("d" * 32, 0, "input", "Проект Заря", "Проект Заря"))
    old = repo.queue_risk(chat, item.id, ("",))
    assert repo.set_item_risk_status(chat, item.id, old, "running", ("queued",))
    state, version = repo.load_state(chat)
    repo.commit_chat(chat, state, version, updated_items=[replace(item, sanitized="Проект <TERM_1>")])
    assert repo.queue_risk(chat, item.id, ("",)) is not None and repo.queue_risk(chat, item.id, ("",)) is None
    assert not repo.set_item_risk_status(chat, item.id, old, "running", ("queued",))
    [new] = [row["risk_job"] for row in repo.conn.execute("SELECT risk_job FROM items")]
    assert repo.set_item_risk_status(chat, item.id, new, "running", ("queued",))
    assert not repo.set_item_risk(chat, item.id, old, "Проект Заря", {"guesses": []})
    assert not repo.set_item_risk_status(chat, item.id, old, "failed", ("running",))
    assert not repo.set_item_risk(chat, item.id, new, "Проект Заря", {"guesses": []})
    assert repo.set_item_risk(chat, item.id, new, "Проект <TERM_1>", {"guesses": []})
    assert (repo.item(chat, item.id).risk_status, repo.item_risk(chat, item.id)) == ("done", {"guesses": []})


def test_extracted_text_and_risk_are_stored_encrypted(tmp_path, repo):
    user, chat = new_chat(repo)
    item = repo.add_item(chat, Item(uuid.uuid4().hex, 0, "input", "", None, source="file", status="running"))
    repo.set_item_original(chat, item.id, "извлечено Kk41", {"kind": "docx"})
    job = repo.queue_risk(chat, item.id, ("",))
    assert repo.set_item_risk_status(chat, item.id, job, "running", ("queued",))
    assert repo.set_item_risk(chat, item.id, job, None, {"guesses": [{"kind": "org", "guess": "Ромашка Gg52", "clue": ""}]})
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
    repo.set_setting("local_llm.url", "http://10.20.0.10:30000/v1")
    assert repo.setting("local_llm.url") == "http://10.20.0.10:30000/v1"


def test_gold_examples_are_encrypted_and_deleted(tmp_path, repo):
    user = repo.create_user("ivan", "hash", "user")
    spans = [{"start": 0, "end": 6, "type": "TERM", "entity": 0, "origin": "manual"}]
    gold_id = repo.add_gold(user, "эталон Ee61", spans)
    [row] = repo.gold()
    assert (row.id, row.user_id, row.text, row.spans) == (gold_id, user, "эталон Ee61", spans)
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    assert b"Ee61" not in raw_database(tmp_path)
    assert repo.delete_gold(gold_id) and repo.gold() == [] and not repo.delete_gold(gold_id)


def provider(name="Облако", key="sk-test-0123456789abcd", **changes) -> Provider:
    base = Provider("", name, "anthropic", "https://llm.example/anthropic", "x-api-key", key, ("m-1", "m-2"), 2048,
                    {"temperature": 0.2})
    return replace(base, **changes)


def test_provider_key_is_stored_encrypted_and_shown_by_tail(tmp_path, repo):
    """FR-8.10, AC-3.6 на уровне хранилища: ключ — шифртекст, наружу — последние четыре знака."""
    provider_id = repo.add_provider(provider())
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))
    assert b"0123456789abcd" not in raw
    stored = repo.provider(provider_id)
    assert (stored.api_key, stored.key_tail, stored.models, stored.extra_body) == (
        "sk-test-0123456789abcd", "abcd", ("m-1", "m-2"), {"temperature": 0.2},
    )
    assert "0123456789abcd" not in repr(stored)


def test_update_without_a_key_keeps_the_old_one(repo):
    provider_id = repo.add_provider(provider())
    repo.update_provider(provider(id=provider_id, name="Другое", models=("m-3",), enabled=False), None)
    stored = repo.provider(provider_id)
    assert (stored.name, stored.models, stored.enabled, stored.api_key) == ("Другое", ("m-3",), False, "sk-test-0123456789abcd")
    repo.update_provider(stored, "sk-new-key-9999")
    assert repo.provider(provider_id).key_tail == "9999"
    with pytest.raises(KeyError):
        repo.update_provider(provider(id="нет"), None)
    assert repo.delete_provider(provider_id) and not repo.delete_provider(provider_id) and repo.providers() == []


def test_api_key_is_stored_as_hash_with_encrypted_name(tmp_path, repo):
    """SEC-17 на уровне хранилища: ключ — хэшем, имя — шифртекстом."""
    user = repo.create_user("ivan", "hash", "user")
    key = "ck_KanareykaZx81QwErTy0123456789abcdefghijkl"
    repo.add_api_key(user, "Сборка отчётов", auth.token_hash(key), key[-4:])
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = raw_database(tmp_path)
    assert "Сборка отчётов".encode("utf-8") not in raw and key.encode("ascii") not in raw
    stored = repo.api_key_by_hash(auth.token_hash(key))
    assert (stored.user_id, stored.name, stored.tail, stored.disabled, stored.last_used_at) == (
        user, "Сборка отчётов", "ijkl", False, "",
    )
    assert repo.api_key_by_hash(auth.token_hash(key + "x")) is None


def test_api_keys_are_listed_by_owner_or_all_newest_first(repo, clock):
    ivan = repo.create_user("ivan", "hash", "user")
    petr = repo.create_user("petr", "hash", "user")
    first = repo.add_api_key(ivan, "первый", "h1", "aaaa")
    clock.advance(minutes=1)
    second = repo.add_api_key(petr, "второй", "h2", "bbbb")
    clock.advance(minutes=1)
    third = repo.add_api_key(ivan, "третий", "h3", "cccc")
    assert [k.id for k in repo.api_keys(ivan)] == [third, first]
    assert [k.id for k in repo.api_keys()] == [third, second, first]
    assert repo.api_key(second).name == "второй" and repo.api_key("нет") is None


def test_disabled_key_stays_but_is_marked(repo):
    user = repo.create_user("ivan", "hash", "user")
    key_id = repo.add_api_key(user, "ключ", "h1", "aaaa")
    assert repo.disable_api_key(key_id)
    assert repo.api_key(key_id).disabled and repo.api_key_by_hash("h1").disabled
    assert not repo.disable_api_key("нет")


def test_touch_records_last_use(repo, clock):
    user = repo.create_user("ivan", "hash", "user")
    key_id = repo.add_api_key(user, "ключ", "h1", "aaaa")
    assert repo.api_key(key_id).last_used_at == ""
    clock.advance(minutes=3)
    repo.touch_api_key(key_id)
    assert repo.api_key(key_id).last_used_at == clock.now().isoformat(timespec="seconds")


def test_chat_remembers_provider_and_model(repo):
    user, chat = new_chat(repo)
    assert repo.chat_provider(chat) == (None, "")
    repo.set_chat_provider(chat, "p1", "m-1")
    assert repo.chat_provider(chat) == ("p1", "m-1")
    with pytest.raises(KeyError):
        repo.set_chat_provider("нет", "p1", "m-1")


def test_gateway_key_keeps_access_models_layers_and_chat(repo):
    user = repo.create_user("ivan", "hash", "user")
    plain = repo.api_key(repo.add_api_key(user, "скрипт", "h1", "aaaa"))
    assert (plain.upstream, plain.models, plain.layers, plain.chat_id) == (None, (), {"ner": False, "llm": False}, None)
    key_id = repo.add_api_key(
        user, "агент", "h2", "bbbb", upstream="provider:p1", models=("m-1", "m-2"), layers={"ner": True, "llm": False},
    )
    chat = repo.create_chat(user, "Агент", kind="agent")
    repo.set_key_chat(key_id, chat)
    key = repo.api_key_by_hash("h2")
    assert (key.upstream, key.models, key.layers, key.chat_id) == ("provider:p1", ("m-1", "m-2"), {"ner": True, "llm": False}, chat)
    repo.delete_chat(chat)
    assert repo.api_key(key_id).chat_id is None
    repo.set_key_chat(key_id, None)


def test_agent_chat_starts_in_written_mode(repo, clock):
    user = repo.create_user("ivan", "hash", "user")
    agent = repo.create_chat(user, "Агент", kind="agent")
    plain = repo.create_chat(user, "Чат")
    assert repo.load_state(agent)[0].written and not repo.load_state(plain)[0].written
    assert (repo.chat(agent).kind, repo.chat(plain).kind) == ("agent", "chat")
    assert repo.chat(agent).created_at == clock.now().isoformat(timespec="seconds")


def gateway(repo):
    user = repo.create_user("ivan", "hash", "user")
    key_id = repo.add_api_key(user, "агент", "h1", "aaaa", upstream="provider:p1")
    return user, key_id, repo.create_chat(user, "Агент", kind="agent")


def test_conversation_is_added_once_and_touched(repo, clock):
    user, key_id, chat = gateway(repo)
    assert repo.conversation("c1") is None
    first = repo.add_conversation("c1", chat, key_id, "")
    assert (first.chat_id, first.key_id, first.session, first.requests) == (chat, key_id, "", 0)
    clock.advance(minutes=5)
    assert repo.add_conversation("c1", "другой", key_id, "s-2") == first       # уже есть — прежний
    repo.touch_conversation("c1", "s-1")
    repo.touch_conversation("c1", "s-2")
    stored = repo.conversation("c1")
    assert (stored.session, stored.requests, stored.first_seen) == ("s-1", 2, first.first_seen)
    assert stored.last_seen == clock.now().isoformat(timespec="seconds")


def entry(digest, local="агент Zx91", wire="провайдер Qq77", direction="in", conversation="c1"):
    return LedgerEntry(conversation, direction, digest, local, wire, "", {"EMAIL": 1})


def test_ledger_is_written_with_the_chat_state_and_encrypted(tmp_path, repo):
    user, key_id, chat = gateway(repo)
    repo.add_conversation("c1", chat, key_id, "")
    state, version = repo.load_state(chat)
    repo.commit_chat(chat, state, version, ledger=[entry("d1")])
    with pytest.raises(StaleState):
        repo.commit_chat(chat, state, version, ledger=[entry("d2")])
    found = repo.ledger_get(chat, "c1", "in", ["d1", "d2", "d3"])
    assert list(found) == ["d1"] and found["d1"] == entry("d1")
    assert repo.ledger_get(chat, "c1", "out", ["d1"]) == {}
    repo.add_ledger(chat, [entry("d4", direction="out", local="отдано Ee33", wire="пришло Rr22")])
    assert repo.ledger_get(chat, "c1", "out", ["d4"])["d4"].wire == "пришло Rr22"
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = raw_database(tmp_path)
    for secret in ("Zx91", "Qq77", "Ee33", "Rr22"):
        assert secret.encode("utf-8") not in raw, secret


def test_parallel_ledger_insert_keeps_the_first(repo, clock):
    """Блок, который записал параллельный запрос, остаётся первым: его вид уже ушёл провайдеру."""
    user, key_id, chat = gateway(repo)
    repo.add_conversation("c1", chat, key_id, "")
    state, version = repo.load_state(chat)
    repo.commit_chat(chat, state, version, ledger=[entry("d1", wire="первый")])
    clock.advance(minutes=1)
    repo.commit_chat(chat, state, version + 1, ledger=[entry("d1", wire="второй")])
    repo.add_ledger(chat, [entry("d1", wire="третий")])
    assert repo.ledger_get(chat, "c1", "in", ["d1"])["d1"].wire == "первый"
    clock.advance(minutes=1)
    repo.touch_ledger(chat, "c1", "in", ["d1"])
    [(stored, first_seen)] = repo.ledger_page(chat, 0, 50)
    assert stored.wire == "первый" and first_seen < clock.now().isoformat(timespec="seconds")


def test_ledger_page_lists_newest_first_across_conversations(repo, clock):
    user, key_id, chat = gateway(repo)
    for conversation in ("c1", "c2"):
        repo.add_conversation(conversation, chat, key_id, "")
    for number, conversation in enumerate(("c1", "c2", "c1")):
        clock.advance(minutes=1)
        repo.add_ledger(chat, [entry(f"d{number}", conversation=conversation)])
    page = repo.ledger_page(chat, 0, 2)
    assert [(e.conversation, e.digest) for e, _ in page] == [("c1", "d2"), ("c2", "d1")]
    assert [e.digest for e, _ in repo.ledger_page(chat, 2, 2)] == ["d0"]


def test_prune_removes_old_conversations_and_orphan_agent_chats(repo, clock):
    user, key_id, current = gateway(repo)
    repo.set_key_chat(key_id, current)
    old = repo.create_chat(user, "Агент, прежний", kind="agent")
    plain = repo.create_chat(user, "Обычный")
    repo.add_conversation("c-old", old, key_id, "")
    repo.add_conversation("c-current", current, key_id, "")
    repo.add_ledger(old, [entry("d1", conversation="c-old")])
    clock.advance(days=31)
    repo.add_conversation("c-fresh", current, key_id, "")
    assert repo.prune_agent((clock.now() - timedelta(days=30)).isoformat(timespec="seconds")) == 1
    assert repo.chat(old) is None and repo.chat(current) is not None and repo.chat(plain) is not None
    assert repo.conversation("c-old") is None and repo.conversation("c-current") is None
    assert repo.conversation("c-fresh") is not None


def test_finish_answer_writes_text_status_and_meta(repo):
    user, chat = new_chat(repo)
    item = repo.add_item(chat, Item(uuid.uuid4().hex, 0, "answer", "", None, source="api", status="running"))
    repo.finish_answer(chat, item.id, "Ответ <PERSON_1>", "partial", {"model": "m-1", "error": "обрыв"})
    stored = repo.item(chat, item.id)
    assert (stored.original, stored.status, stored.meta) == ("Ответ <PERSON_1>", "partial", {"model": "m-1", "error": "обрыв"})
    with pytest.raises(KeyError):
        repo.finish_answer(chat, "нет", "x", "done", {})
