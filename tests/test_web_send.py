"""Отправка в интерфейсе (FR-8.3…8.6, FR-9.4): выбор подключения, подтверждение, поток ответа, остановка."""
import re

import pytest

from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.storage.repo import Item, Provider

KEY = "sk-test-0123456789abcd"


@pytest.fixture
def provider(repo):
    return repo.add_provider(Provider("", "Облако", "openai", "https://llm.example/v1", "bearer", KEY, ("m-1",), 512))


@pytest.fixture
def cloud(app, monkeypatch):
    calls = []

    def fake(ctx, connection, state, settings, *, cancel=None, outcome=None, transport=None, on_open=None):
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
    hint = "Без очистки: оригиналы остаются на этом сервере (локальная модель по адресу 127.0.0.1:30000)"
    assert f'<button title="{hint}">Спросить локальную модель</button>' in page


def test_ask_local_hint_names_the_remote_gateway(ivan, repo):
    """Аудит 21.10.2026: частный или доверенный адрес — уже другой сервер, и «текст не покидает сервер» было неправдой.
    Подсказка называет узел и порт, без учётных данных из адреса."""
    repo.set_setting("local_llm.url", "http://user:secret@10.0.0.5:4000/v1")
    page = ivan.get(f"/chats/{ivan.chat()}").text
    assert 'title="Без очистки: оригиналы уходят локальной модели на узел 10.0.0.5:4000"' in page
    assert "secret" not in page


def test_ask_local_is_off_while_a_local_answer_is_pending(ivan, repo):
    """Аудит 21.10.2026: пока ответ локальной модели в очереди, кнопка неактивна, а повтор формы — отказ с причиной."""
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Вопрос: почта a@x.example")
    repo.add_item(chat_id, Item("l" * 32, 0, "answer", "", None, source="local", status="queued"))
    page = ivan.get(f"/chats/{chat_id}").text
    assert re.search(r'<button disabled title="[^"]*ещё идёт[^"]*">Спросить локальную модель</button>', page)
    response = ivan.post(f"/chats/{chat_id}/ask-local")
    assert response.status_code == 400 and "ещё идёт" in response.text
    assert [i.id for i in repo.items(chat_id) if i.source == "local"] == ["l" * 32]


def three_items(ivan, provider) -> str:
    """Вопрос 1, ответ вручную 2, вопрос 3."""
    chat_id = chat_with_question(ivan, provider)
    ivan.post(f"/chats/{chat_id}/answer", answer="Ответ про <EMAIL_1>")
    ivan.post(f"/chats/{chat_id}/input", text="Второй вопрос")
    return chat_id


def test_confirmation_can_leave_items_out_and_sends_only_that_selection(ivan, provider, cloud):
    """Сокращение контекста: состав — в адресе номерами, отправка — только кнопкой с отпечатком этого состава."""
    chat_id = three_items(ivan, provider)
    full = ivan.get(f"/chats/{chat_id}/send").text
    assert all(f'name="include" value="{seq}" checked' in full for seq in (1, 2, 3))
    short = ivan.get(f"/chats/{chat_id}/send", shown="1,2,3", include=["1", "3"]).text
    assert "Исключено: Ответ модели 2" in short and 'name="exclude" value="2"' in short
    assert "соседние вопросы уйдут одним сообщением" in short
    assert 'name="include" value="2">' in short and "Ответ про" not in short
    assert ivan.post(f"/chats/{chat_id}/send", digest=digest(short)).status_code == 400    # без состава — другой запрос
    assert cloud == []
    assert ivan.post(f"/chats/{chat_id}/send", digest=digest(short), exclude="2").status_code == 303
    [ctx] = cloud
    assert [m.role for m in ctx.messages] == ["user"]


def test_leaving_out_the_last_question_keeps_the_choice_without_a_send_button(ivan, provider):
    chat_id = three_items(ivan, provider)
    page = ivan.get(f"/chats/{chat_id}/send", shown="1,2,3", include=["1", "2"]).text
    assert "Последним в запросе должен быть вопрос" in page and "Пересобрать" in page
    assert 'name="digest"' not in page


def test_manual_transfer_shows_the_whole_cleaned_dialogue_with_roles(ivan, provider):
    """Идея аудита 21.10.2026: тот же запрос, что ушёл бы по API, одним текстом — копируется только он."""
    chat_id = three_items(ivan, provider)
    ivan.post(f"/chats/{chat_id}/input", text="Отвечай кратко", source="instruction")
    page = ivan.get(f"/chats/{chat_id}/manual").text
    text = re.search(r'<pre class="text" id="manual-text">\n(.*?)</pre>', page, re.S).group(1)
    assert text.startswith("=== Инструкция ===\nВ тексте встречаются обозначения") and "Отвечай кратко" in text
    assert "=== Вопрос ===\nВопрос: почта &lt;EMAIL_1&gt;" in text and "=== Ответ модели ===\nОтвет про &lt;EMAIL_1&gt;" in text
    assert "a@x.example" not in page and 'data-copy="manual-text"' in page
    assert f'href="/chats/{chat_id}/manual"' in ivan.get(f"/chats/{chat_id}").text


def test_manual_transfer_offers_no_copy_when_a_fragment_is_blocked(ivan, repo, provider):
    chat_id = chat_with_question(ivan, provider)
    repo.set_policy(T.EMAIL, Policy.BLOCK)
    page = ivan.get(f"/chats/{chat_id}/manual").text
    assert "Копирование заблокировано" in page and 'data-copy="manual-text"' not in page


def test_route_leads_from_review_to_transfer_and_the_mark_is_cleared_by_an_edit(ivan, repo):
    """Маршрут чата: после очистки — «Проверить», после отметки — «Копировать очищенное…»; правка снимает отметку."""
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Проект Заря, почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    page = ivan.get(f"/chats/{chat_id}").text
    assert 'aria-current="step">Проверка</li>' in page and "требуется проверка" in page
    assert f'<a class="btn primary" href="/chats/{chat_id}/items/{item_id}">Проверить</a>' in page
    review = ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    shown = re.search(r'/reviewed"[^>]*>.*?name="digest" value="([0-9a-f]{64})"', review, re.S).group(1)
    assert ivan.post(f"/chats/{chat_id}/items/{item_id}/reviewed", digest="0" * 64).status_code == 400
    assert ivan.post(f"/chats/{chat_id}/items/{item_id}/reviewed", digest=shown).status_code == 303
    assert "Отметить проверенным" not in ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    page = ivan.get(f"/chats/{chat_id}").text
    assert "проверено пользователем" in page and f'href="/chats/{chat_id}/manual">Копировать очищенное…</a>' in page
    assert "анонимн" not in page.lower() and "безопасн" not in page.lower()
    ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value="Заря", type="TERM")
    assert "требуется проверка" in ivan.get(f"/chats/{chat_id}").text
