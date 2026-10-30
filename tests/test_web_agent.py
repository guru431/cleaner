"""Маршруты шлюза Anthropic (спецификация 2026-10-28, разделы 8.2, 9.1, 12): ключ — в любом из заголовков агента,
тело — как его шлёт агент, ошибки — в виде Anthropic, без текста запроса."""
import gzip
import json
import zlib

import pytest

from cleaner.storage.repo import Provider, StaleState
from cleaner.web import auth, routes_agent
from tests.agent_bodies import agent_blocks, body, events_of, model_turn
from tests.stub_provider import StubProvider

BASE = "/agent/anthropic"
SECRET_TASK = "Проверь узел srv-dc01.corp.contoso.ru"


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


@pytest.fixture
def agent(browser, repo, stub):
    """Клиент агента и ключ шлюза к заглушке с моделями m-1 и m-2."""
    user_id = repo.create_user("petr", auth.hash_password("пароль-для-тестов"), "user")
    provider_id = repo.add_provider(Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", "sk-stub-0123456789", ("m-1", "m-2", "m-3")))
    key = auth.new_api_key()
    repo.add_api_key(user_id, "агент", auth.token_hash(key), key[-4:], upstream=f"provider:{provider_id}", models=("m-1", "m-2"))
    client = browser().client
    client.key = key
    return client


def post(client, path: str = "/v1/messages?beta=true", content: bytes | None = None, headers: dict | None = None, **kwargs):
    headers = {"x-api-key": client.key, "anthropic-version": "2023-06-01", "content-type": "application/json", **(headers or {})}
    return client.post(BASE + path, content=content, headers=headers, **kwargs)


def anthropic_error(response, status: int, kind: str) -> str:
    assert response.status_code == status, response.text
    data = response.json()
    assert data["type"] == "error" and data["error"]["type"] == kind
    assert data["error"]["message"].startswith("Cleaner:")
    return data["error"]["message"]


@pytest.mark.parametrize("header", ["x-api-key", "authorization", "x-cleaner-key"])
def test_messages_stream_through_the_gateway(agent, stub, header):
    stub.script.append(model_turn("Готово"))
    value = f"Bearer {agent.key}" if header == "authorization" else agent.key
    response = agent.post(
        BASE + "/v1/messages?beta=true", content=json.dumps(body(SECRET_TASK)).encode(),
        headers={header: value, "anthropic-version": "2023-06-01", "content-type": "application/json"},
    )
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream")
    assert agent_blocks(response.content) == [{"type": "text", "text": "Готово"}]
    assert events_of(response.content)[-1]["type"] == "message_stop"
    sent = stub.requests[0]
    assert sent["path"] == "/v1/messages?beta=true" and "srv-dc01" not in json.dumps(sent["body"])
    assert agent.key not in json.dumps(sent["headers"])


def test_bodies_are_decoded_or_refused_in_anthropic_shape(agent, stub, monkeypatch):
    stub.script += [model_turn("Раз"), model_turn("Два")]
    raw = json.dumps(body(SECRET_TASK), ensure_ascii=False).encode("utf-8")
    assert post(agent, content=gzip.compress(raw), headers={"content-encoding": "gzip"}).status_code == 200
    assert post(agent, content=zlib.compress(raw), headers={"content-encoding": "deflate"}).status_code == 200
    monkeypatch.setattr(routes_agent, "MAX_BODY", len(raw) - 1)
    message = anthropic_error(post(agent, content=gzip.compress(raw), headers={"content-encoding": "gzip"}), 413, "request_too_large")
    assert "srv-dc01" not in message
    anthropic_error(post(agent, content=b"(zstd)", headers={"content-encoding": "zstd"}), 415, "invalid_request_error")
    anthropic_error(post(agent, content=b"{"), 400, "invalid_request_error")
    anthropic_error(post(agent, content=b"[1, 2]"), 400, "invalid_request_error")
    anthropic_error(post(agent, content=b"not gzip", headers={"content-encoding": "gzip"}), 400, "invalid_request_error")
    anthropic_error(post(agent, content=b'{"model": "m-1", "messages": "\\ud800"}'), 400, "invalid_request_error")
    assert len(stub.requests) == 2


def test_wrong_key_is_401_authentication_error(agent, stub, repo):
    response = agent.post(BASE + "/v1/messages", content=b"{}", headers={"x-api-key": "ck_" + "Z" * 43})
    anthropic_error(response, 401, "authentication_error")
    anthropic_error(agent.post(BASE + "/v1/messages", content=b"{}"), 401, "authentication_error")
    stub.script.append(model_turn("x"))
    request = body(SECRET_TASK, model="m-3")            # у подключения есть, ключу не разрешена
    message = anthropic_error(post(agent, content=json.dumps(request).encode()), 400, "invalid_request_error")
    assert "модель" in message and stub.requests == []
    assert anthropic_error(agent.get(BASE + "/v1/unknown", headers={"x-api-key": agent.key}), 404, "not_found_error")


def test_count_tokens_404_passes_through(agent, stub):
    response = post(agent, "/v1/messages/count_tokens?beta=true", content=json.dumps(body(SECRET_TASK)).encode())
    assert response.status_code == 404 and response.json()["error"]["type"] == "not_found_error"
    assert stub.requests[0]["path"] == "/v1/messages/count_tokens?beta=true"
    assert "srv-dc01" not in json.dumps(stub.requests[0]["body"])


def test_models_lists_the_key_models(agent):
    response = agent.get(BASE + "/v1/models", headers={"x-api-key": agent.key})
    assert response.status_code == 200
    data = response.json()
    assert [m["id"] for m in data["data"]] == ["m-1", "m-2"]
    assert data["data"][0] == {"type": "model", "id": "m-1", "display_name": "m-1", "created_at": "1970-01-01T00:00:00Z"}
    assert (data["has_more"], data["first_id"], data["last_id"]) == (False, "m-1", "m-2")


def test_hello_is_204_without_a_key(agent):
    assert agent.head(BASE + "/api/hello").status_code == 204
    assert agent.get(BASE + "/api/hello").status_code == 204


@pytest.mark.parametrize(("case", "reason", "status"), [
    ("no_upstream", "no_upstream", 403), ("connection_gone", "connection_gone", 400), ("model", "model", 400),
    ("protocol", "protocol", 400), ("subscription_role", "subscription_role", 403),
    ("subscription_login", "subscription_login", 401), ("layer_down", "layer_down", 503),
    ("layer_down_midway", "layer_down", 503), ("busy", "busy", 503), ("body", "body", 400),
])
def test_every_refusal_is_recorded_with_its_reason(agent, stub, repo, engines, monkeypatch, case, reason, status):
    """Раздел 12: каждый отказ шлюза — событие agent_refused с причиной; ни ключа, ни текста запроса в нём нет."""
    petr = repo.user_by_login("petr").id
    upstream = repo.api_key_by_hash(auth.token_hash(agent.key)).upstream

    def new_key(user_id: str = petr, **access) -> str:
        value = auth.new_api_key()
        repo.add_api_key(user_id, "отказ", auth.token_hash(value), value[-4:], **access)
        return value

    def failing(exc: Exception):
        def fail(*args, **kwargs):
            raise exc
        return fail

    key, request, content = agent.key, body(SECRET_TASK), None
    if case == "no_upstream":
        key = new_key()
    elif case == "connection_gone":
        gone = repo.add_provider(Provider("", "Выключено", "anthropic", stub.url, "x-api-key", "sk-off-0123", ("m-1",), enabled=False))
        key = new_key(upstream=f"provider:{gone}")
    elif case == "model":
        request = body(SECRET_TASK, model="m-3")
    elif case == "protocol":
        openai = repo.add_provider(Provider("", "OpenAI", "openai", stub.url, "bearer", "sk-openai-0123", ("m-1",)))
        key = new_key(upstream=f"provider:{openai}")
    elif case == "subscription_role":
        key = new_key(upstream="claude-subscription")
    elif case == "subscription_login":
        key = new_key(repo.create_user("boss", "hash", "admin"), upstream="claude-subscription")
    elif case.startswith("layer_down"):
        key = new_key(upstream=upstream, models=("m-1",), layers={"llm": True})
        if case == "layer_down":
            engines.unavailable = "локальная модель недоступна"
        else:
            monkeypatch.setattr(engines.second, "find", failing(OSError("модель упала")))
    elif case == "busy":
        monkeypatch.setattr(repo, "commit_chat", failing(StaleState("правка в интерфейсе")))
    else:
        content = b'{"model": "m-1", "messages": [{"role": "user", "content": "' + SECRET_TASK.encode() + b'"'
    response = post(agent, content=content or json.dumps(request).encode(), headers={"x-api-key": key})
    assert response.status_code == status, response.text
    assert response.json()["error"]["message"].startswith("Cleaner:") and stub.requests == []
    [event] = repo.audit_events("agent_refused")
    assert event.details["reason"] == reason and event.user_id == repo.api_key_by_hash(auth.token_hash(key)).user_id
    assert event.details["key"] == repo.api_key_by_hash(auth.token_hash(key)).id
    assert (event.chat_id is not None) == (case in ("layer_down_midway", "busy"))     # чат — когда он уже известен
    raw = json.dumps(event.details, ensure_ascii=False)
    assert key not in raw and key[-8:] not in raw and "srv-dc01" not in raw and "Проверь" not in raw


def test_session_cookie_does_not_open_the_gateway(ivan, agent):
    response = ivan.client.post(BASE + "/v1/messages", content=json.dumps(body(SECRET_TASK)).encode())
    anthropic_error(response, 401, "authentication_error")
