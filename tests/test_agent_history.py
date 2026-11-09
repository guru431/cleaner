"""Блок модели вне журнала out (спецификация 2026-10-28, 7.2.2): агент держит текст с оригиналами, которые восстановление
вывело само (FR-7.6), — адрес в фиктивной подсети. Ни после простоя дольше 30 дней, ни после «Начать заново», ни когда
клиент Responses присылает ответ ассистента строкой такой адрес не должен уйти провайдеру открытым. Служба шлюза целиком,
провайдер — MockTransport; проверяется тело, которое ушло провайдеру. Данные вымышленные."""
import json
import re
from dataclasses import replace
from functools import partial

import httpx
import pytest

from cleaner.agent_service import AgentCall, AgentService
from cleaner.egress import forward as egress
from cleaner.storage.repo import Provider

TASK = "Сервер 10.1.2.5 недоступен, назначь соседний адрес"
DERIVED = "10.1.2.77"           # адрес, который агент увидит после восстановления
_IP = re.compile(r"\b10\.\d+\.\d+\.5\b")


def _reply_text(body: dict, protocol: str) -> str:
    """Модель назначает новый адрес в той же фиктивной подсети, что и замена адреса из задачи (FR-7.6)."""
    sent = json.dumps(body["messages" if protocol != "responses" else "input"], ensure_ascii=False)
    fake = _IP.search(sent).group()
    return f"Назначь {fake.rsplit('.', 1)[0]}.77 узлу"


@pytest.fixture
def gateway(repo, clock):
    sent: list[dict] = []
    replies: list[str] = []

    def receive(request):
        body = json.loads(request.content)
        sent.append(body)
        protocol = "responses" if request.url.path.endswith("/responses") else "anthropic"
        text = _reply_text(body, protocol)
        replies.append(text)
        if protocol == "responses":
            part = {"type": "output_text", "text": text, "annotations": []}
            return httpx.Response(200, json={"output": [{"type": "message", "id": "msg_1", "role": "assistant", "content": [part]}]})
        return httpx.Response(200, json={"content": [{"type": "text", "text": text}]})

    user_id = repo.create_user("history", "hash", "user")
    forward = partial(egress.forward, transport=httpx.MockTransport(receive))

    def make(protocol: str = "anthropic"):
        provider_id = repo.add_provider(Provider("", "Stub", protocol, "http://127.0.0.1", "bearer", "stub-only", ("m",)))
        key_id = repo.add_api_key(user_id, "history", "hash-" + provider_id, "aaaa", "provider:" + provider_id, ("m",))
        path = "/responses" if protocol == "responses" else "/v1/messages"

        def call(body: dict) -> AgentCall:
            return AgentCall(repo.api_key(key_id), repo.user(user_id), protocol, path, "", {}, body)

        return AgentService(repo, None, clock, forward=forward), call

    return make, sent, replies


def _first_turn(service, call) -> str:
    """Ход 1: агент получает ответ с выведенным адресом; возвращает текст, который агент пришлёт в истории."""
    reply = service.handle(call({"model": "m", "stream": False, "messages": [{"role": "user", "content": TASK}]}))
    text = json.loads(reply.body)["content"][0]["text"]
    assert DERIVED in text
    return text


def _second(text: str) -> dict:
    return {"model": "m", "stream": False, "messages": [
        {"role": "user", "content": TASK}, {"role": "assistant", "content": [{"type": "text", "text": text}]},
        {"role": "user", "content": "Дальше"},
    ]}


def test_derived_address_does_not_leak_after_the_ledger_expired(gateway, clock):
    make, sent, _ = gateway
    service, call = make()
    text = _first_turn(service, call)
    clock.advance(days=31)                      # разговор удалён из журнала, текущий чат ключа устарел
    service.handle(call(_second(text)))
    assert DERIVED not in json.dumps(sent[-1], ensure_ascii=False)


def test_derived_address_does_not_leak_after_restart(gateway, repo):
    make, sent, _ = gateway
    service, call = make()
    text = _first_turn(service, call)
    repo.restart_key_chat(call({}).key.id)      # «Начать заново»: агент без id разговора начинает новый
    service.handle(call(_second(text)))
    assert DERIVED not in json.dumps(sent[-1], ensure_ascii=False)


def test_responses_assistant_string_is_found_in_the_ledger(gateway):
    """Ответ ассистента строкой и частью output_text — один отпечаток: к провайдеру уходит то, что прислала модель."""
    make, sent, replies = gateway
    service, call = make("responses")
    first = {"model": "m", "stream": False, "input": [
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": TASK}]},
    ]}
    reply = service.handle(call(first))
    text = json.loads(reply.body)["output"][0]["content"][0]["text"]
    assert DERIVED in text
    second = dict(first, input=[*first["input"], {"type": "message", "role": "assistant", "content": text},
                                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Дальше"}]}])
    service.handle(call(second))
    history = sent[-1]["input"]
    assert DERIVED not in json.dumps(sent[-1], ensure_ascii=False)
    assistant = next(item for item in history if item.get("role") == "assistant")
    assert assistant["content"] == replies[0]           # строкой, дословно как прислала модель
