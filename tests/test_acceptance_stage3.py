"""Приёмочные проверки этапа 3 (TZ.md, раздел 11) на заглушке провайдера по петле: настоящий модуль выхода
в сеть, настоящие протоколы, сеть вне петли закрыта сторожем быстрого набора."""
import dataclasses
import logging
import re

import pytest

from cleaner.core.restore import restore
from cleaner.egress import cloud
from cleaner.local_llm import LocalLLM, LocalLLMConfig
from cleaner.storage.repo import Provider
from tests.stub_provider import StubProvider
from tests.test_acceptance_core import CONTROL, TEXT

KEY = "REDACTED_SK_KEY"


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


def connect(repo, stub: StubProvider, protocol: str) -> str:
    base = f"{stub.url}/v1" if protocol == "openai" else f"{stub.url}/anthropic"
    auth = "bearer" if protocol == "openai" else "x-api-key"
    return repo.add_provider(Provider("", "Заглушка", protocol, base, auth, KEY, ("stub-model",), 1024))


def send(ivan, chat_id: str):
    page = ivan.get(f"/chats/{chat_id}/send").text
    digest = re.search(r'name="digest" value="([0-9a-f]{64})"', page).group(1)
    return ivan.post(f"/chats/{chat_id}/send", digest=digest)


def answers(repo, chat_id: str):
    return [item for item in repo.items(chat_id) if item.kind == "answer"]


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_ac_3_2_no_control_original_reaches_the_provider(ivan, repo, stub, protocol):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text=TEXT)
    ivan.post(f"/chats/{chat_id}/provider", choice=f"{connect(repo, stub, protocol)}|stub-model")
    stub.pieces = ["Проверьте ", "<EMAIL_1>"]
    assert send(ivan, chat_id).status_code == 303
    [request] = stub.requests
    assert request["path"] == ("/v1/chat/completions" if protocol == "openai" else "/anthropic/v1/messages")
    sent = stub.bodies()
    for value in CONTROL:
        assert value not in sent, value
    [answer] = answers(repo, chat_id)
    assert (answer.status, answer.original) == ("done", "Проверьте <EMAIL_1>")
    assert "i.ivanov@contoso.ru</mark>" in ivan.get(f"/chats/{chat_id}").text


def test_ac_3_3_label_cut_between_chunks_at_every_position(ivan, repo, stub):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text=TEXT)
    ivan.post(f"/chats/{chat_id}/provider", choice=f"{connect(repo, stub, 'anthropic')}|stub-model")
    reply = "Пишите на <EMAIL_1>, узел \\<HOST\\_1\\> и <ACCOUNT_1>."
    stub.pieces = list(reply)                 # каждый знак — отдельный фрагмент: разрез в каждой позиции
    send(ivan, chat_id)
    [answer] = answers(repo, chat_id)
    assert answer.original == reply
    state, _ = repo.load_state(chat_id)
    restored = restore(state, reply, repo.settings()).text
    assert "i.ivanov@contoso.ru" in restored and "ivanov." in restored
    assert ivan.get(f"/chats/{chat_id}").text.count("i.ivanov@contoso.ru</mark>") == 1


def test_ac_3_4_planted_original_blocks_the_send_and_says_why(ivan, repo, stub, app, monkeypatch):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text=TEXT)
    ivan.post(f"/chats/{chat_id}/provider", choice=f"{connect(repo, stub, 'openai')}|stub-model")

    def planted(ctx, *args, **kwargs):
        last = dataclasses.replace(ctx.messages[-1], text=ctx.messages[-1].text + " (i.ivanov@contoso.ru)")
        return cloud.send(dataclasses.replace(ctx, messages=(*ctx.messages[:-1], last)), *args, **kwargs)

    monkeypatch.setattr(app.state.service, "cloud_send", planted)
    send(ivan, chat_id)
    assert stub.requests == []
    [answer] = answers(repo, chat_id)
    assert answer.status == "failed"
    assert "Ответ не получен: В исходящем тексте найден оригинал" in ivan.get(f"/chats/{chat_id}").text
    assert repo.audit_events("leak")[0].details["stage"] == "send"


def test_ac_3_5_three_turns_and_a_rule_before_the_third(ivan, repo, stub):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Почта a.petrova@kontora-test.ru, проект Заря-Восток. Что делать?")
    ivan.post(f"/chats/{chat_id}/provider", choice=f"{connect(repo, stub, 'anthropic')}|stub-model")
    stub.pieces = ["Напишите <EMAIL_1> про Заря-Восток."]
    send(ivan, chat_id)
    ivan.post(f"/chats/{chat_id}/input", text="А если a.petrova@kontora-test.ru не ответит?")
    send(ivan, chat_id)
    first_item = repo.items(chat_id)[0].id
    ivan.post(f"/chats/{chat_id}/mask", item_id=first_item, value="Заря-Восток", type="TERM")
    ivan.post(f"/chats/{chat_id}/input", text="Спасибо")
    send(ivan, chat_id)
    first, second, third = (request["body"]["messages"] for request in stub.requests)
    assert first[0]["content"] == second[0]["content"] == "Почта <EMAIL_1>, проект Заря-Восток. Что делать?"
    assert second[2]["content"] == "А если <EMAIL_1> не ответит?"
    assert [m["content"] for m in third[:2]] == ["Почта <EMAIL_1>, проект <TERM_1>. Что делать?", "Напишите <EMAIL_1> про <TERM_1>."]
    assert "Заря-Восток" not in str(third)


def test_ac_3_6_key_is_never_shown_logged_or_stored_in_clear(boss, repo, stub, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    provider = connect(repo, stub, "openai")
    pages = boss.get("/settings/providers").text
    boss.post(f"/settings/providers/{provider}/check", model="stub-model")
    chat_id = boss.chat()
    boss.post(f"/chats/{chat_id}/input", text="Вопрос")
    boss.post(f"/chats/{chat_id}/provider", choice=f"{provider}|stub-model")
    pages += boss.get(f"/chats/{chat_id}").text + send(boss, chat_id).text + boss.get(f"/chats/{chat_id}").text
    assert stub.requests[0]["headers"]["Authorization"] == f"Bearer {KEY}"      # ключ уходит только провайдеру
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))
    journal = repr([(event.event, event.details) for event in repo.audit_events(limit=1000)])
    for where in (pages, caplog.text, journal):
        assert "Kanareyka7Q4Z" not in where
    assert b"Kanareyka7Q4Z" not in raw and "Kanareyka7Q4Z".encode("utf-16-le") not in raw
    assert "…7Q4Z" in pages


def test_ac_4_3_local_question_goes_only_to_the_local_model(ivan, repo, stub, engines):
    engines.completer = LocalLLM(LocalLLMConfig(f"{stub.url}/v1", "local-model", "k-local"))
    stub.pieces = ["Локальный ответ"]
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text=TEXT)
    assert ivan.post(f"/chats/{chat_id}/ask-local").status_code == 303
    [request] = stub.requests
    assert request["path"] == "/v1/chat/completions" and request["body"]["model"] == "local-model"
    assert "i.ivanov@contoso.ru" in stub.bodies()                 # FR-9.4: текст не очищается
    [answer] = answers(repo, chat_id)
    assert (answer.source, answer.status, answer.original) == ("local", "done", "Локальный ответ")
