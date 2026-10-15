"""Отправка в интерфейсе (FR-8.3…8.6, FR-9.4): выбор подключения, подтверждение, поток ответа, остановка."""
import re

import pytest

from cleaner.storage.repo import Item, Provider

KEY = "sk-test-0123456789abcd"


@pytest.fixture
def provider(repo):
    return repo.add_provider(Provider("", "Облако", "openai", "https://llm.example/v1", "bearer", KEY, ("m-1",), 512))


@pytest.fixture
def cloud(app, monkeypatch):
    calls = []

    def fake(ctx, connection, state, settings, *, cancel=None, outcome=None, transport=None):
        calls.append(ctx)
        yield "Ответ про "
        yield "<EMAIL_1>"

    monkeypatch.setattr(app.state.service, "cloud_send", fake)
    return calls


def chat_with_question(ivan, provider) -> str:
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Вопрос: почта a@x.example")
    assert ivan.post(f"/chats/{chat_id}/provider", choice=f"{provider}|m-1").status_code == 303
    return chat_id


def digest(page: str) -> str:
    return re.search(r'name="digest" value="([0-9a-f]{64})"', page).group(1)


def test_chat_offers_enabled_connections_and_remembers_the_choice(ivan, repo, provider):
    chat_id = ivan.chat()
    page = ivan.get(f"/chats/{chat_id}").text
    assert f'value="{provider}|m-1"' in page and "Отправить очищенный чат" not in page
    ivan.post(f"/chats/{chat_id}/provider", choice=f"{provider}|m-1")
    assert "Отправить очищенный чат" in ivan.get(f"/chats/{chat_id}").text
    assert ivan.post(f"/chats/{chat_id}/provider", choice=f"{provider}|чужая").status_code == 400
    assert ivan.post(f"/chats/{chat_id}/provider", choice="").status_code == 303
    assert repo.chat_provider(chat_id) == (None, "")


def test_confirmation_shows_what_will_be_sent_and_no_originals(ivan, provider):
    chat_id = chat_with_question(ivan, provider)
    page = ivan.get(f"/chats/{chat_id}/send").text
    assert "Вопрос: почта &lt;EMAIL_1&gt;" in page and "a@x.example" not in page
    assert "Облако — m-1" in page and digest(page)


def test_send_streams_into_the_chat_and_restores_the_answer(ivan, provider, cloud):
    chat_id = chat_with_question(ivan, provider)
    response = ivan.post(f"/chats/{chat_id}/send", digest=digest(ivan.get(f"/chats/{chat_id}/send").text))
    assert response.status_code == 303
    [ctx] = cloud
    assert "a@x.example" not in " ".join(ctx.texts())
    page = ivan.get(f"/chats/{chat_id}").text
    assert "Ответ Облако — m-1" in page and "a@x.example</mark>" in page


def test_stale_confirmation_is_refused(ivan, provider, cloud):
    chat_id = chat_with_question(ivan, provider)
    shown = digest(ivan.get(f"/chats/{chat_id}/send").text)
    ivan.post(f"/chats/{chat_id}/input", text="И ещё вопрос")
    response = ivan.post(f"/chats/{chat_id}/send", digest=shown)
    assert response.status_code == 400 and "изменился" in response.text
    assert cloud == []


def test_send_without_a_connection_says_what_to_do(ivan):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Вопрос")
    response = ivan.get(f"/chats/{chat_id}/send")
    assert response.status_code == 409 and "Выберите подключение" in response.text


def test_stream_sends_the_restored_text_then_done(ivan, app, repo, provider):
    chat_id = chat_with_question(ivan, provider)
    item_id = "a" * 32
    repo.add_item(chat_id, Item(item_id, 0, "answer", "", None, source="api", status="running"))
    live = app.state.service.live.start(item_id)
    live.append("Пишите на <EMAIL_1> ")
    live.finished = True
    with ivan.client.stream("GET", f"/chats/{chat_id}/items/{item_id}/stream") as response:
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())
    assert 'data: {"text": "Пишите на a@x.example "}' in body and body.rstrip().endswith("event: done\ndata: {}")
    assert ivan.get(f"/chats/{chat_id}/items/{'b' * 32}/stream").status_code == 404


def test_stop_reaches_a_running_answer(ivan, app, repo, provider):
    chat_id = chat_with_question(ivan, provider)
    item_id = "c" * 32
    repo.add_item(chat_id, Item(item_id, 0, "answer", "", None, source="api", status="running"))
    live = app.state.service.live.start(item_id)
    assert "Остановить" in ivan.get(f"/chats/{chat_id}").text
    assert ivan.post(f"/chats/{chat_id}/items/{item_id}/stop").status_code == 303
    assert live.cancel.is_set()
    app.state.service.live.finish(item_id)
    assert ivan.post(f"/chats/{chat_id}/items/{item_id}/stop").status_code == 404


def test_instruction_is_shown_in_the_feed_and_goes_to_the_system_part(ivan, provider):
    chat_id = chat_with_question(ivan, provider)
    assert ivan.post(f"/chats/{chat_id}/input", text="Отвечай кратко", source="instruction").status_code == 303
    assert "Инструкция для модели 2" in ivan.get(f"/chats/{chat_id}").text
    page = ivan.get(f"/chats/{chat_id}/send").text
    assert page.index("Отвечай кратко") < page.index("Вопрос: почта")
    assert ivan.post(f"/chats/{chat_id}/input", text="x", source="system").status_code == 400


def test_ask_local_answers_with_originals(ivan, engines):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Вопрос: почта a@x.example")
    engines.completer.answers = ["Локально: пишите на a@x.example"]
    assert ivan.post(f"/chats/{chat_id}/ask-local").status_code == 303
    assert engines.completer.requests[-1]["messages"][-1]["content"] == "Вопрос: почта a@x.example"
    page = ivan.get(f"/chats/{chat_id}").text
    assert "Ответ локальной модели" in page and "Локально: пишите на a@x.example" in page
