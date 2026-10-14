"""Приёмка этапа 1 на уровне приложения: AC-1.5, AC-1.8, AC-1.10, AC-1.11 (TZ.md, раздел 11)."""
import json
import logging
import re

import pytest
from fastapi.routing import iter_route_contexts

CANARIES = ("ivanov.qa@kontora-test.ru", "10.20.30.40", "Заря-Восток", "Zx9!kLm2#Qp")
TEXT = "Пишет ivanov.qa@kontora-test.ru с 10.20.30.40 по проекту Заря-Восток, Password=Zx9!kLm2#Qp"


def raw_database(tmp_path) -> bytes:
    return b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))


def test_ac_1_5_unmask_and_manual_mask_hold_for_all_and_next_texts(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Пишет a@x.example по проекту Заря")
    first = repo.items(chat_id)[0].id
    ivan.post(f"/chats/{chat_id}/unmask", item_id=first, value="a@x.example")
    ivan.post(f"/chats/{chat_id}/mask", item_id=first, value="Заря", type="TERM")
    ivan.post(f"/chats/{chat_id}/input", text="Снова a@x.example и Заря")
    assert [i.sanitized for i in repo.items(chat_id)] == [
        "Пишет a@x.example по проекту <TERM_1>", "Снова a@x.example и <TERM_1>",
    ]


def test_ac_1_8_control_values_are_absent_from_the_file_the_logs_and_the_journal(ivan, repo, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    chat_id = ivan.chat("Заря-Восток")
    ivan.post(f"/chats/{chat_id}/input", text=TEXT)
    item_id = repo.items(chat_id)[0].id
    ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value="Заря-Восток", type="TERM")
    ivan.post(f"/chats/{chat_id}/answer", answer="Проверьте <EMAIL_1> и <TERM_1>")
    assert "ivanov.qa@kontora-test.ru</mark>" in ivan.get(f"/chats/{chat_id}").text
    ivan.get("/chats", q="Заря")
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = raw_database(tmp_path)
    journal = json.dumps([(a.event, a.details) for a in repo.audit_events(limit=1000)], ensure_ascii=False)
    for value in CANARIES:
        assert value.encode("utf-8") not in raw and value.encode("utf-16-le") not in raw, value
        assert value not in caplog.text and value not in journal, value


def test_ac_1_10_deleted_chat_is_gone_from_the_interface_and_the_file(ivan, repo, tmp_path):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text=TEXT)
    item_id = repo.items(chat_id)[0].id
    wrapped, state = repo.conn.execute("SELECT dek_wrapped, state_enc FROM chats WHERE id = ?", (chat_id,)).fetchone()
    [original] = repo.conn.execute("SELECT original_enc FROM items WHERE id = ?", (item_id,)).fetchone()
    ivan.post(f"/chats/{chat_id}/delete", confirm="yes")
    for path in (
        f"/chats/{chat_id}", f"/chats/{chat_id}/items/{item_id}",
        f"/chats/{chat_id}/entities", f"/chats/{chat_id}/items/{item_id}/download",
    ):
        assert ivan.get(path).status_code == 404, path
    with pytest.raises(KeyError):
        repo.load_state(chat_id)
    repo.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    raw = raw_database(tmp_path)
    # Обёрнутый ключ чата и шифртексты стёрты из файла (secure_delete): даже главный ключ их не вернёт.
    for blob in (bytes(wrapped), bytes(state)[:64], bytes(original)[:64]):
        assert blob not in raw


def test_ac_1_11_only_the_login_page_is_open_without_a_session(app, browser):
    anonymous = browser()
    # FastAPI 0.143 держит подключённые роутеры в app.routes целиком; маршруты с префиксами — через iter_route_contexts.
    routes = list(iter_route_contexts(app.routes))
    assert any(route.path == "/settings/audit" for route in routes)
    for route in routes:
        path = route.path or ""
        if path == "/login" or path.startswith("/static"):
            continue
        concrete = re.sub(r"\{[^}]+\}", "0" * 32, path)
        for method in sorted((route.methods or set()) - {"HEAD"}):
            response = anonymous.client.request(method, concrete)
            assert (response.status_code, response.headers.get("location")) == (303, "/login"), (method, path)


def test_ac_1_11_one_user_cannot_reach_another_users_chat(browser, repo):
    anna, boris = browser(), browser()
    anna.user("anna")
    anna.login("anna")
    boris.user("boris")
    boris.login("boris")
    chat_id = anna.chat()
    anna.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    [entity] = repo.load_state(chat_id)[0].entities.values()
    for path in (
        f"/chats/{chat_id}", f"/chats/{chat_id}/items/{item_id}",
        f"/chats/{chat_id}/entities", f"/chats/{chat_id}/items/{item_id}/download",
    ):
        assert boris.get(path).status_code == 404, path
    for path, fields in (
        (f"/chats/{chat_id}/input", {"text": "x"}),
        (f"/chats/{chat_id}/answer", {"answer": "x"}),
        (f"/chats/{chat_id}/rename", {"title": "x"}),
        (f"/chats/{chat_id}/mask", {"item_id": item_id, "value": "почта", "type": "TERM"}),
        (f"/chats/{chat_id}/unmask", {"item_id": item_id, "value": "a@x.example"}),
        (f"/chats/{chat_id}/entities/{entity.id}/unmask", {}),
        (f"/chats/{chat_id}/entities/{entity.id}/retype", {"type": "TERM"}),
        (f"/chats/{chat_id}/refresh", {}),
        (f"/chats/{chat_id}/delete", {"confirm": "yes"}),
    ):
        assert boris.post(path, **fields).status_code == 404, path
    assert "Консультация" not in boris.get("/chats").text
    assert [i.sanitized for i in repo.items(chat_id)] == ["почта <EMAIL_1>"]
