"""Маршруты шлюза Anthropic (спецификация 2026-10-28, разделы 8.2, 9.1, 12): ключ — в любом из заголовков агента,
тело — как его шлёт агент, ошибки — в виде Anthropic, без текста запроса."""
import asyncio
import gzip
import json
import logging
import threading
import time
import zlib
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor

import pytest

from cleaner.agent_service import AgentCall, AgentReply, AgentService
from cleaner.egress import forward
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


@pytest.mark.parametrize("base", ["/agent/anthropic", "/agent/openai"])
def test_model_lists_intersect_current_provider_scope_and_hide_disabled_connections(agent, repo, base):
    provider = repo.providers()[0]
    repo.update_provider(replace(provider, models=("m-2", "m-3")), None)
    response = agent.get(base + "/v1/models", headers={"x-cleaner-key": agent.key})
    assert response.status_code == 200 and [m["id"] for m in response.json()["data"]] == ["m-2"]
    repo.update_provider(replace(provider, enabled=False), None)
    assert agent.get(base + "/v1/models", headers={"x-cleaner-key": agent.key}).json()["data"] == []


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
    ("layer_down_midway", "layer_down", 503), ("busy", "busy", 503), ("body", "body", 400), ("body_size", "body", 413),
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
    elif case == "body_size":
        monkeypatch.setattr("cleaner.web.app.AGENT_BODY_BYTES", 64)        # предел BodyLimit, а не разбора тела
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


def test_agent_leaving_while_the_provider_is_silent_frees_the_thread(caplog):
    """Агент закрыл соединение, пока провайдер молчит (ревью 5Г, п. 1): stop рвёт ожидание, начатый next возвращается, и
    генератор закрывается в пуле — без «generator already executing»; поток пула свободен сразу, а не через 300 с."""
    reading, silent, stopped, closed = threading.Event(), threading.Event(), threading.Event(), []

    def events():
        try:
            yield b"data: 1\n\n"
            reading.set()
            silent.wait(5)                  # провайдер молчит, пока stop не закроет соединение
            yield b"data: 2\n\n"
        finally:
            closed.append(threading.current_thread().name)

    def stop():
        stopped.set()
        silent.set()

    pool = ThreadPoolExecutor(2, thread_name_prefix="cleaner-agent")

    async def agent():
        stream = routes_agent._Stream(pool, AgentReply(200, {}, events=events(), stop=stop)).body_iterator
        assert await anext(stream) == b"data: 1\n\n"
        waiting = asyncio.ensure_future(anext(stream))
        while not reading.is_set():
            await asyncio.sleep(0.005)
        waiting.cancel()                    # агент ушёл: Starlette отменяет чтение
        with pytest.raises(asyncio.CancelledError):
            await waiting

    started = time.perf_counter()
    with caplog.at_level(logging.ERROR):
        asyncio.run(agent())
        pool.shutdown(wait=True)
    assert stopped.is_set() and time.perf_counter() - started < 1
    assert len(closed) == 1 and closed[0].startswith("cleaner-agent")
    assert not caplog.records


def test_agent_leaving_mid_stream_closes_the_provider_and_keeps_the_record(repo, engines, clock, stub):
    """То же на службе: модель думает посреди ответа, агент ушёл после первого блока — соединение с провайдером закрыто
    сразу, agent_send записан с finished: false, журнал out — по отданной части."""
    thinking = threading.Event()
    stub.script.append([*model_turn("Смотрю журнал")[:-2], {"pause": thinking}])
    user_id = repo.create_user("ivan", "hash", "user")
    provider = repo.add_provider(Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", "sk-stub-0123456789", ("m-1",)))
    key_id = repo.add_api_key(user_id, "агент", "h1", "aaaa", upstream=f"provider:{provider}", models=("m-1",))
    reply = AgentService(repo, engines, clock).handle(AgentCall(
        repo.api_key(key_id), repo.user(user_id), "anthropic", "/v1/messages", "",
        {"anthropic-version": "2023-06-01", "x-api-key": "ck_agent"}, body(SECRET_TASK),
    ))
    try:
        got = [next(reply.events)]
        while events_of(b"".join(got))[-1]["type"] != "content_block_stop":
            got.append(next(reply.events))
        reader = threading.Thread(target=next, args=(reply.events, None))
        reader.start()
        time.sleep(0.05)                    # next ждёт провайдера
        started = time.perf_counter()
        reply.stop()
        reader.join(2)
        assert not reader.is_alive() and time.perf_counter() - started < 1
        reply.close()
        reply.close()                       # конец — один раз: начатый поток закрылся своим finally
    finally:
        thinking.set()
    [send] = repo.audit_events("agent_send")
    assert send.details["finished"] is False
    out = [json.loads(entry.local) for entry, _ in repo.ledger_page(send.chat_id, 0, 100) if entry.direction == "out"]
    assert out == [{"type": "text", "text": "Смотрю журнал"}]


def _checked_out() -> int:
    """Запросы, которые держат соединения пула egress (вместе с их заголовками — входом агента по подписке)."""
    return sum(len(client._transport._pool._requests) for client in forward._clients.values())


def test_agent_gone_before_the_stream_starts_frees_the_pooled_connection(app, agent, stub, repo):
    """Агент ушёл, пока шлюз очищал запрос или ждал заголовков провайдера (финальное ревью 5Г, C1): receive уже отвечает
    http.disconnect, и Starlette отменяет отправку раньше первого чтения потока. Ответ провайдера всё равно закрыт —
    соединение пула свободно, agent_send записан с finished: false."""
    thinking = threading.Event()
    stub.script.append([*model_turn("Смотрю")[:2], {"pause": thinking}])
    raw = json.dumps(body(SECRET_TASK)).encode()
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": BASE + "/v1/messages", "raw_path": (BASE + "/v1/messages").encode(), "query_string": b"",
        "root_path": "", "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 5464),
        "headers": [(b"host", b"127.0.0.1:5464"), (b"content-type", b"application/json"), (b"x-api-key", agent.key.encode()),
                    (b"anthropic-version", b"2023-06-01"), (b"content-length", str(len(raw)).encode())],
    }
    messages = [{"type": "http.request", "body": raw, "more_body": False}]

    async def receive() -> dict:
        return messages.pop(0) if messages else {"type": "http.disconnect"}       # как uvicorn после ухода клиента

    async def send(message: dict) -> None:
        pass

    try:
        asyncio.run(app(scope, receive, send))
        app.state.agent_pool.shutdown(wait=True)
    finally:
        thinking.set()
    assert len(stub.requests) == 1 and _checked_out() == 0
    [sent] = repo.audit_events("agent_send")
    assert sent.details["finished"] is False


def test_agent_gone_while_the_first_read_waits_for_a_thread_frees_the_pooled_connection(repo, engines, clock, stub):
    """Пул шлюза занят, первое чтение потока ждёт в очереди, и агент ушёл: чтение отменено, не начавшись, — ответ
    провайдера всё равно закрыт (финальное ревью 5Г, C1)."""
    thinking, busy = threading.Event(), threading.Event()
    stub.script.append([*model_turn("Смотрю")[:2], {"pause": thinking}])
    user_id = repo.create_user("ivan", "hash", "user")
    provider = repo.add_provider(Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", "sk-stub-0123456789", ("m-1",)))
    key_id = repo.add_api_key(user_id, "агент", "h1", "aaaa", upstream=f"provider:{provider}", models=("m-1",))
    reply = AgentService(repo, engines, clock).handle(AgentCall(
        repo.api_key(key_id), repo.user(user_id), "anthropic", "/v1/messages", "",
        {"anthropic-version": "2023-06-01", "x-api-key": "ck_agent"}, body(SECRET_TASK),
    ))
    pool = ThreadPoolExecutor(1, thread_name_prefix="cleaner-agent")
    pool.submit(busy.wait, 5)                       # единственный поток занят другим агентом

    async def agent():
        stream = routes_agent._Stream(pool, reply).body_iterator
        waiting = asyncio.ensure_future(anext(stream))
        await asyncio.sleep(0)                      # next в очереди пула
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting

    try:
        asyncio.run(agent())
        busy.set()
        pool.shutdown(wait=True)
    finally:
        busy.set()
        thinking.set()
    assert _checked_out() == 0
    [sent] = repo.audit_events("agent_send")
    assert sent.details["finished"] is False


def test_session_cookie_does_not_open_the_gateway(ivan, agent):
    response = ivan.client.post(BASE + "/v1/messages", content=json.dumps(body(SECRET_TASK)).encode())
    anthropic_error(response, 401, "authentication_error")
