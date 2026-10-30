"""Маршруты шлюза OpenAI (спецификация 2026-10-28, разделы 9.2, 9.3, 12; план 5В, задача 6): Chat Completions и
Responses, ключ — в любом из заголовков агента, ошибки — в виде OpenAI, без текста запроса."""
import gzip
import json

import pytest

from cleaner.storage.repo import Provider
from cleaner.web import auth, routes_agent
from tests.agent_bodies import body as claude_body
from tests.agent_bodies import model_turn
from tests.stub_provider import StubProvider
from tests.test_agent_chat import chunk, opencode
from tests.test_agent_responses import completed, message, text_events

BASE = "/agent/openai"
TASK = "Проверь узел srv-dc01.corp.contoso.ru"


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


@pytest.fixture
def agent(browser, repo, stub):
    """Клиент агента и ключи шлюза к заглушке — по подключению каждого протокола, модель m-1."""
    user_id = repo.create_user("petr", auth.hash_password("пароль-для-тестов"), "user")
    keys = {}
    for protocol in ("openai", "responses", "anthropic"):
        url = stub.url if protocol == "anthropic" else f"{stub.url}/v1"
        provider_id = repo.add_provider(Provider("", f"Заглушка {protocol}", protocol, url, "bearer", "sk-stub-0123456789", ("m-1", "m-2")))
        key = auth.new_api_key()
        repo.add_api_key(user_id, protocol, auth.token_hash(key), key[-4:], upstream=f"provider:{provider_id}", models=("m-1",))
        keys[protocol] = key
    client = browser().client
    client.keys = keys
    return client


def post(client, path: str, payload: object = None, key: str = "", headers: dict | None = None, content: bytes | None = None):
    headers = {"content-type": "application/json", **({"x-cleaner-key": key} if key else {}), **(headers or {})}
    raw = content if content is not None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return client.post(BASE + path, content=raw, headers=headers)


def openai_error(response, status: int, kind: str) -> str:
    assert response.status_code == status, response.text
    error = response.json()["error"]
    assert error["type"] == kind and error["message"].startswith("Cleaner:") and "code" in error
    return error["message"]


def chat_request() -> dict:
    return opencode({"role": "user", "content": TASK})


def responses_request() -> dict:
    return {"model": "m-1", "stream": True, "store": False, "input": TASK}


@pytest.mark.parametrize("header", ["x-cleaner-key", "authorization", "x-api-key"])
def test_chat_and_responses_stream_through_the_gateway(agent, stub, header):
    stub.script += [[chunk({"role": "assistant", "content": "Готово"}), chunk({}, "stop")],
                    [*text_events(0, message("msg_1", "Готово"), []), completed(message("msg_1", "Готово"))]]
    for protocol, path, request in (("openai", "/v1/chat/completions", chat_request()), ("responses", "/v1/responses", responses_request())):
        key = agent.keys[protocol]
        response = post(agent, path, request, headers={header: f"Bearer {key}" if header == "authorization" else key})
        assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream"), response.text
        assert "Готово" in response.text
    assert "event: response.completed" in response.text
    assert [r["path"] for r in stub.requests] == ["/v1/chat/completions", "/v1/responses"]
    assert "srv-dc01" not in stub.bodies() and "ck_" not in json.dumps([r["headers"] for r in stub.requests])


def test_chat_stream_ends_with_done(agent, stub):
    stub.script.append([chunk({"role": "assistant", "content": "Готово"}), chunk({}, "stop")])
    response = post(agent, "/v1/chat/completions", chat_request(), agent.keys["openai"])
    assert response.text.endswith("data: [DONE]\n\n")


def test_wrong_protocol_for_the_key_is_400(agent, stub):
    for key, path, request in ((agent.keys["anthropic"], "/v1/responses", responses_request()),
                               (agent.keys["responses"], "/v1/chat/completions", chat_request())):
        message_ = openai_error(post(agent, path, request, key), 400, "invalid_request_error")
        assert "протокол" in message_
    assert stub.requests == []


def test_openai_errors_have_the_openai_shape(agent, stub, monkeypatch):
    key = agent.keys["openai"]
    assert TASK not in openai_error(post(agent, "/v1/chat/completions", chat_request()), 401, "authentication_error")
    raw = json.dumps(chat_request(), ensure_ascii=False).encode("utf-8")
    monkeypatch.setattr(routes_agent, "MAX_BODY", len(raw) - 1)
    too_big = post(agent, "/v1/chat/completions", key=key, content=gzip.compress(raw), headers={"content-encoding": "gzip"})
    assert TASK not in openai_error(too_big, 413, "invalid_request_error")
    monkeypatch.undo()
    openai_error(post(agent, "/v1/responses", key=agent.keys["responses"], content=b"(zstd)", headers={"content-encoding": "zstd"}),
                 415, "invalid_request_error")
    assert TASK not in openai_error(post(agent, "/v1/chat/completions", key=key, content=f"{TASK} — не JSON".encode()), 400,
                                    "invalid_request_error")
    wrong_model = dict(chat_request(), model="m-2")
    openai_error(post(agent, "/v1/chat/completions", wrong_model, key), 400, "invalid_request_error")
    stub.script.append({"status": 429, "body": {"error": {"message": "slow down", "type": "rate_limit_error"}}, "headers": {"retry-after": "7"}})
    limited = post(agent, "/v1/chat/completions", chat_request(), key)
    assert limited.status_code == 429 and limited.headers["retry-after"] == "7" and limited.json()["error"]["message"] == "slow down"


@pytest.mark.parametrize("protocol", ["anthropic", "openai"])
def test_too_deep_body_is_400_not_500(agent, stub, repo, protocol):
    """Рекурсивные обходы очистки на теле у предела разбора JSON падали RecursionError → 500; теперь — отказ по телу."""
    if protocol == "anthropic":
        path, request, reply = "/agent/anthropic/v1/messages", {
            "model": "m-1", "max_tokens": 16, "stream": True, "messages": [{"role": "user", "content": "привет"}],
        }, model_turn("Готово")
    else:
        path, request, reply = BASE + "/v1/chat/completions", chat_request(), [
            chunk({"role": "assistant", "content": "Готово"}), chunk({}, "stop"),
        ]

    def send(depth: int):           # само тело — уровень 1; текстом: json.dumps такую глубину не пишет
        deep = "[" * (depth - 1) + '"лист"' + "]" * (depth - 1)
        raw = json.dumps(dict(request, metadata="@"), ensure_ascii=False).replace('"@"', deep).encode("utf-8")
        return agent.post(path, content=raw, headers={"content-type": "application/json", "x-cleaner-key": agent.keys[protocol]})

    # Служебное поле обходит проверка утечек. 2000 — разбор проходит, обход падал (500); 5000 — RecursionError уже в разборе.
    for depth in (2000, routes_agent.MAX_DEPTH + 1, 5000):
        response = send(depth)
        assert response.status_code == 400, response.text
        error = response.json()["error"]
        assert error["type"] == "invalid_request_error" and error["message"].startswith("Cleaner:")
        assert (response.json().get("type") == "error") == (protocol == "anthropic") and ("code" in error) == (protocol == "openai")
    assert send(routes_agent.MAX_DEPTH + 1).json()["error"]["message"] == "Cleaner: тело запроса вложено глубже 64 уровней"
    assert [event.details["reason"] for event in repo.audit_events("agent_refused")] == ["body"] * 4
    stub.script.append(reply)
    assert send(routes_agent.MAX_DEPTH).status_code == 200 and len(stub.requests) == 1


def test_models_list_in_openai_shape(agent):
    response = agent.get(BASE + "/v1/models", headers={"authorization": f"Bearer {agent.keys['responses']}"})
    assert response.json() == {"object": "list", "data": [{"id": "m-1", "object": "model", "created": 0, "owned_by": "cleaner"}]}
    openai_error(agent.get(BASE + "/v1/models"), 401, "authentication_error")


def test_unknown_openai_path_is_404_json(agent):
    for path in ("/v1/memories", "/v1/files", "/v2/responses"):
        openai_error(agent.post(BASE + path, json={}, headers={"x-cleaner-key": agent.keys["responses"]}), 404, "not_found_error")
    openai_error(agent.get(BASE + "/v1/responses", headers={"x-cleaner-key": agent.keys["responses"]}), 405, "invalid_request_error")


def test_anthropic_routes_are_unchanged(agent, stub):
    response = agent.post("/agent/anthropic/v1/messages", content=json.dumps(claude_body(TASK)).encode(),
                          headers={"content-type": "application/json"})
    assert response.status_code == 401 and response.json()["type"] == "error"
    assert response.json()["error"]["type"] == "authentication_error"
    wrong = agent.post("/agent/anthropic/v1/messages", content=json.dumps(claude_body(TASK)).encode(),
                       headers={"content-type": "application/json", "x-api-key": agent.keys["openai"]})
    assert wrong.status_code == 400 and wrong.json()["type"] == "error"
