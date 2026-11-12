"""Чат шлюза в интерфейсе (спецификация 2026-10-28, разделы 7.3, 11, 16): журнал отправленного вместо ленты, только для
чтения; правки распознавания — на следующие запросы агента; объединение и значение для восстановления — нельзя."""
import json

import pytest

from cleaner.core.types import ChatRule
from cleaner.core.types import EntityType as T
from cleaner.service import EditRefused
from cleaner.storage.repo import Provider
from cleaner.web import auth
from tests.agent_bodies import body, model_turn
from tests.stub_provider import StubProvider

TASK = "Проверь узел srv-dc01.corp.contoso.ru, проект Заря"


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


@pytest.fixture
def gateway(ivan, repo, stub):
    """Ключ шлюза Ивана к заглушке и отправка запроса агента через маршрут; возвращает функцию отправки."""
    provider_id = repo.add_provider(Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", "sk-1", ("m-1",)))
    key = auth.new_api_key()
    user = repo.user_by_login("ivan")
    key_id = repo.add_api_key(user.id, "агент", auth.token_hash(key), key[-4:], upstream=f"provider:{provider_id}")

    def send(task: str = TASK) -> str:
        stub.script.append(model_turn("Готово"))
        response = ivan.client.post("/agent/anthropic/v1/messages", content=json.dumps(body(task)).encode(),
                                    headers={"x-api-key": key, "content-type": "application/json"})
        assert response.status_code == 200, response.text
        return repo.api_key(key_id).chat_id

    return send


def test_agent_chat_shows_the_ledger_side_by_side(ivan, gateway, stub):
    chat = gateway()
    page = ivan.get(f"/chats/{chat}").text
    assert "Журнал отправленного" in page and "агент" in page and "Разговоров: 1" in page
    assert "srv-dc01.corp.contoso.ru" in page                         # оригинал — сторона агента
    sent = stub.requests[0]["body"]["messages"][0]["content"][-1]["text"]
    fake = sent.split("узел ", 1)[1].split(",")[0]
    assert fake in page and "правки действуют на следующие запросы агента" in page
    assert 'name="text"' not in page and f'action="/chats/{chat}/input"' not in page      # ввода нет
    assert "в 0 блоках" in page


def test_agent_chat_shows_the_blocks_of_a_selected_request(ivan, gateway, repo):
    """Выбор запроса — блоки из его квитанции (10.4; квитанция сжата) и только они."""
    chat = gateway()
    gateway("Второй разговор: узел srv-db02.corp.contoso.ru")
    second, first = repo.agent_receipts(chat)                     # свежие первыми
    page = ivan.get(f"/chats/{chat}?request={first['id']}").text.split("Журнал отправленного", 1)[1]
    assert "srv-dc01.corp.contoso.ru" in page and "srv-db02" not in page
    page = ivan.get(f"/chats/{chat}?request={second['id']}").text.split("Журнал отправленного", 1)[1]
    assert "srv-db02.corp.contoso.ru" in page and "srv-dc01" not in page


def test_agent_chat_warns_about_new_request_shapes(ivan, repo, stub):
    """Риск 7: незнакомые поля и блоки (пути и type, без данных) и блоки модели вне журнала — в квитанции и на странице."""
    provider_id = repo.add_provider(Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", "sk-1", ("m-1",)))
    key = auth.new_api_key()
    key_id = repo.add_api_key(repo.user_by_login("ivan").id, "агент", auth.token_hash(key), key[-4:],
                              upstream=f"provider:{provider_id}")

    def send(request: dict) -> str:
        stub.script.append(model_turn("Готово"))
        response = ivan.client.post("/agent/anthropic/v1/messages", content=json.dumps(request).encode(),
                                    headers={"x-api-key": key, "content-type": "application/json"})
        assert response.status_code == 200, response.text
        return repo.api_key(key_id).chat_id

    chat = send(body(TASK))
    page = ivan.get(f"/chats/{chat}").text
    assert "data-agent-shapes" not in page and "data-agent-fresh" not in page
    odd = body("Второй разговор")
    odd["messages"][0]["content"].append({"type": "custom_note", "note": "секретная заметка"})
    history = [{"role": "assistant", "content": [{"type": "text", "text": f"Ответ {n}, которого модель не давала"}]}
               for n in range(3)]
    send(body("Третий разговор", *[part for turn in history for part in (turn, {"role": "user", "content": "дальше"})]))
    send(odd)
    receipts = repo.agent_receipts(chat)
    assert receipts[0]["unfamiliar"] == ["messages[].content[] type=custom_note"]
    assert (receipts[1]["model_blocks"], receipts[1]["model_fresh"]) == (3, 3)
    page = ivan.get(f"/chats/{chat}").text
    assert "data-agent-shapes" in page and "messages[].content[] type=custom_note" in page
    assert "data-agent-fresh" in page and "секретная заметка" not in page.split("Журнал отправленного")[0]


def test_agent_chat_counts_values_left_open_in_frozen_blocks(ivan, gateway, repo):
    chat = gateway()
    state, version = repo.load_state(chat)
    state.rules.append(ChatRule("mask", "Заря", T.TERM))          # «скрывать» после записи блока
    repo.commit_chat(chat, state, version)
    gateway("Новый разговор: проект Заря")                        # значение стало известным
    page = ivan.get(f"/chats/{chat}").text
    assert "в 1 блоке" in page


def test_agent_chat_counts_open_values_in_the_whole_ledger_on_request(ivan, gateway, repo, monkeypatch):
    """FR-14.8, 7.3: замороженный блок с открытым значением — начало разговора — уходит на дальние страницы; проверка
    всего журнала находит его с любой страницы и показывает только такие блоки."""
    from cleaner.web import routes_chats

    chat = gateway()
    state, version = repo.load_state(chat)
    state.rules.append(ChatRule("mask", "Заря", T.TERM))
    repo.commit_chat(chat, state, version)
    gateway("Новый разговор: проект Заря")
    monkeypatch.setattr(routes_chats, "LEDGER_PAGE", 1)
    first = ivan.get(f"/chats/{chat}").text
    assert "В показанных записях известные значения открыты в 0 блоках" in first and 'href="?open=1"' in first
    whole = ivan.get(f"/chats/{chat}", open="1").text
    assert "Во всём журнале чата известные значения открыты в 1 блоке" in whole
    assert whole.count("открыто значение</span>") == 1 and "Старше</a>" not in whole
    assert "Проверь узел srv-dc01.corp.contoso.ru, проект Заря" in whole


def test_agent_chat_refuses_input_and_send(ivan, gateway):
    chat = gateway()
    for path, fields in (
        ("input", {"text": "текст"}), ("answer", {"answer": "ответ"}), ("layers", {"layer": "ner", "enabled": "yes"}),
        ("provider", {"choice": ""}), ("send", {}), ("ask-local", {"question": "вопрос"}),
    ):
        response = ivan.post(f"/chats/{chat}/{path}", **fields)
        assert response.status_code == 400 and "только для просмотра" in response.text, path
    assert ivan.upload(f"/chats/{chat}/upload", "a.txt", b"text").status_code == 400
    assert ivan.get(f"/chats/{chat}/send").status_code == 400
    assert ivan.get(f"/chats/{chat}/manual").status_code == 400


def test_written_chat_refuses_merge_and_restore_value(ivan, gateway, repo, app):
    chat = gateway()
    state, _ = repo.load_state(chat)
    hosts = [e for e in state.entities.values() if e.type is T.HOST]
    with pytest.raises(EditRefused, match="разные написания"):
        app.state.service.merge(chat, "u", hosts[0].id, hosts[1].id)
    with pytest.raises(EditRefused, match="разные написания"):
        app.state.service.set_restore_value(chat, "u", hosts[0].id, "другое")
    page = ivan.get(f"/chats/{chat}/entities").text
    assert "/entities/merge" not in page and "/restore-value" not in page and "/unmask/preview" in page
    assert "правки действуют на следующие запросы агента" in page
    response = ivan.post(f"/chats/{chat}/entities/{hosts[0].id}/restore-value", value="другое")
    assert response.status_code == 400


def test_api_refuses_to_add_texts_to_an_agent_chat(gateway, api):
    chat = gateway()
    program = api("ivan")
    for path, payload in (("texts", {"text": "x"}), ("restore", {"text": "x"}), ("rules", {"action": "unmask", "value": "x"})):
        response = program.post(f"/api/v1/chats/{chat}/{path}", json=payload)
        assert response.status_code == 409 and "только для просмотра" in response.json()["error"]["message"], path
    assert program.client.post(f"/api/v1/chats/{chat}/files", headers={"X-Cleaner-Key": program.key},
                               files={"file": ("a.txt", b"x")}).status_code == 409
    assert chat in [c["id"] for c in program.get("/api/v1/chats").json()]
    assert program.get(f"/api/v1/chats/{chat}/entities").status_code == 200


def test_other_users_agent_chat_is_404(browser, gateway):
    chat = gateway()
    petr = browser()
    petr.user("petr")
    petr.login("petr")
    assert petr.get(f"/chats/{chat}").status_code == 404
    assert petr.get(f"/chats/{chat}/entities").status_code == 404
