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
    raw = raw_database(tmp_path)
    # Обёрнутый ключ чата и шифртексты стёрты из файла и журнала WAL сразу при удалении, без
    # отдельной контрольной точки: даже главный ключ их не вернёт.
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
            if path.startswith("/api/"):
                # Программам — отказ JSON без ключа; после пяти отказов с адреса — пауза (план 5А).
                assert response.status_code in (401, 429), (method, path)
                assert response.json()["error"]["code"] == response.status_code, (method, path)
                continue
            assert (response.status_code, response.headers.get("location")) == (303, "/login"), (method, path)


def test_ac_1_11_one_user_cannot_reach_another_users_chat(app, browser, repo, api):
    """Каждый маршрут с чатом в адресе — из списка маршрутов приложения, так что новый проверяется сам
    (обзор плана 2+4, m-11). Чужой — администратор: маршруты только для администраторов тоже доходят до
    проверки владельца. Поля запросов верные: без проверки владельца каждый из них изменил бы чат Анны.
    Маршруты /api/v1 — ключом Бориса, тела — JSON с теми же полями (план 5А)."""
    anna, boris = browser(), browser()
    anna.user("anna")
    anna.login("anna")
    boris.user("boris", "admin")
    boris.login("boris")
    program = api("boris")
    chat_id = anna.chat()
    anna.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    [entity] = repo.load_state(chat_id)[0].entities.values()
    ids = {"chat_id": chat_id, "item_id": item_id, "entity_id": entity.id}
    fields = {
        "text": "x", "answer": "x", "title": "x", "item_id": item_id, "value": "a@x.example", "type": "TERM",
        "list": "never", "layer": "ner", "enabled": "no", "keep": entity.id, "drop": entity.id, "confirm": "yes",
        "action": "mask",
    }
    checked = set()
    for route in iter_route_contexts(app.routes):
        if "{chat_id}" not in (route.path or ""):
            continue
        path = re.sub(r"\{([^}]+)\}", lambda m: ids[m.group(1)], route.path)      # KeyError — новый вид id: дополните ids
        for method in sorted((route.methods or set()) - {"HEAD"}):
            if path.startswith("/api/"):
                if path.endswith("/files"):
                    response = program.post(path, files={"file": ("письмо.txt", "почта b@x.example".encode("utf-8"))})
                else:
                    response = program.client.request(
                        method, path, json=None if method == "GET" else fields, headers={"X-Cleaner-Key": program.key},
                    )
            elif method == "GET":
                response = boris.get(path)
            elif path.endswith("/upload"):
                response = boris.upload(path, "письмо.txt", "почта b@x.example".encode("utf-8"))
            else:
                response = boris.client.request(method, path, data={"csrf": boris.csrf, **fields})
            assert response.status_code == 404, (method, route.path)
            checked.add(route.path)
    item_routes = {f"/chats/{{chat_id}}/items/{{item_id}}/{name}" for name in ("status", "retry", "risk", "gold")}
    assert item_routes | {"/chats/{chat_id}/layers", "/chats/{chat_id}/upload", "/chats/{chat_id}/delete"} <= checked
    assert "/api/v1/chats/{chat_id}" in checked
    assert "Консультация" not in boris.get("/chats").text
    [item] = repo.items(chat_id)
    assert (item.sanitized, item.status, item.risk_status) == ("почта <EMAIL_1>", "done", "")
    assert (repo.chat(chat_id).title, repo.chat_layers(chat_id), repo.gold(), repo.dictionary()) == ("Консультация", {}, [], [])
