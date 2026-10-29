"""Запрос шлюза в ядре и модуль выхода egress.forward (спецификация 2026-10-28, разделы 5, 8.9, 9.1; SEC-1, SEC-2,
SEC-13): провайдер получает только собранное pipeline, заголовки из списка и ключ подключения."""
import json

import httpx
import pytest

from cleaner.core.agent.protocol import PROTOCOLS
from cleaner.core.pipeline import AgentOutgoing, build_agent_outgoing, sanitize
from cleaner.egress import ProviderError
from cleaner.egress import forward as egress
from cleaner.egress.cloud import Connection, LeakDetected
from tests.stub_provider import StubProvider

KEY = "REDACTED_SK_KEY"
AGENT_HEADERS = {
    "anthropic-version": "2023-06-01", "anthropic-beta": "claude-code-20250219", "content-type": "application/json",
    "accept": "application/json", "x-claude-code-session-id": "s-1", "x-claude-code-agent-id": "a-1",
    "authorization": "Bearer ck_agent_key", "x-api-key": "ck_agent_key", "x-cleaner-key": "ck_agent_key",
    "user-agent": "claude-cli/2.1.270", "x-stainless-os": "Windows", "cookie": "session=1",
    "x-claude-code-parent-agent-id": "агент",          # не ASCII: заголовком HTTP не отправить — отбрасывается
}
EVENTS = [
    {"type": "message_start", "message": {"id": "msg_1", "content": []}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Готово"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_stop"},
]


def outgoing(state, settings, checked=(), path="/v1/messages", query="beta=true"):
    body = {"model": "m-1", "stream": True, "messages": [{"role": "user", "content": "вопрос"}]}
    return build_agent_outgoing(
        state, settings, chat_id=state.chat_id, provider_id="p1", path=path, query=query, headers=AGENT_HEADERS,
        allowed=PROTOCOLS["anthropic"].headers, body=body, checked=list(checked),
    )


def connection(url: str, auth_style: str = "bearer") -> Connection:
    return Connection("anthropic", url, auth_style, KEY, 1024)


def test_build_keeps_listed_headers_and_finds_leaks(state, settings):
    sanitize(state, "Почта ivan.petrov@contoso.ru", settings)
    out, leaks = outgoing(state, settings, checked=["m-1", "ivan.petrov@contoso.ru", "<EMAIL_1>"])
    assert isinstance(out, AgentOutgoing) and len(leaks) == 1
    assert dict(out.headers) == {
        "anthropic-version": "2023-06-01", "anthropic-beta": "claude-code-20250219", "content-type": "application/json",
        "accept": "application/json", "x-claude-code-session-id": "s-1", "x-claude-code-agent-id": "a-1",
    }
    assert json.loads(out.body)["messages"] == [{"role": "user", "content": "вопрос"}]
    assert (out.path, out.query, out.provider_id, out.chat_id) == ("/v1/messages", "beta=true", "p1", state.chat_id)


def test_forward_refuses_anything_else(state, settings):
    out, _ = outgoing(state, settings)
    with pytest.raises(TypeError):
        egress.forward({"path": out.path, "body": out.body}, connection("http://127.0.0.1:1"), state, settings)


def test_forward_rechecks_leaks_before_sending(state, settings):
    sanitize(state, "Почта ivan.petrov@contoso.ru", settings)
    out, leaks = outgoing(state, settings, checked=["вопрос про ivan.petrov@contoso.ru"])
    assert leaks
    with StubProvider([EVENTS]) as stub:
        with pytest.raises(LeakDetected):
            egress.forward(out, connection(stub.url), state, settings)
        assert stub.requests == []


@pytest.mark.parametrize("auth_style", ["bearer", "x-api-key"])
def test_agent_headers_and_keys_never_reach_the_provider(state, settings, auth_style):
    out, _ = outgoing(state, settings, checked=["вопрос"])
    with StubProvider([EVENTS]) as stub:
        upstream = egress.forward(out, connection(stub.url + "/anthropic/", auth_style), state, settings)
        try:
            lines = list(upstream.lines())
        finally:
            upstream.close()
        headers = stub.headers()
        assert stub.requests[0]["path"] == "/anthropic/v1/messages?beta=true"
    assert upstream.status == 200 and upstream.headers == {"content-type": "text/event-stream", "request-id": "req_stub"}
    assert "event: message_stop" in lines
    assert "x-cleaner-key" not in headers and "cookie" not in headers and "x-stainless-os" not in headers
    assert "ck_agent_key" not in json.dumps(headers)
    if auth_style == "bearer":
        assert headers["authorization"] == f"Bearer {KEY}" and "x-api-key" not in headers
    else:
        assert headers["x-api-key"] == KEY and "authorization" not in headers
    assert headers["anthropic-beta"] == "claude-code-20250219" and headers["x-claude-code-session-id"] == "s-1"


def test_error_body_comes_back_as_is_without_the_key(state, settings):
    out, _ = outgoing(state, settings)
    error = {"type": "error", "error": {"type": "rate_limit_error", "message": f"slow down, key {KEY}"}}
    with StubProvider([{"status": 429, "body": error, "headers": {"retry-after": "7"}}]) as stub:
        upstream = egress.forward(out, connection(stub.url), state, settings)
        raw = upstream.read(1 << 20)
        upstream.close()
    assert (upstream.status, upstream.headers["retry-after"]) == (429, "7")
    assert KEY not in raw.decode() and json.loads(raw)["error"]["type"] == "rate_limit_error"


def test_plain_http_is_refused_beyond_loopback(state, settings):
    out, _ = outgoing(state, settings)
    with pytest.raises(ValueError):
        egress.forward(out, connection("http://10.20.30.40/anthropic"), state, settings)


def test_redirect_is_not_followed(state, settings):
    out, _ = outgoing(state, settings)
    with StubProvider([{"status": 307, "headers": {"location": "http://127.0.0.1:1/v1/messages"}}]) as stub:
        with pytest.raises(ProviderError, match="переадрес"):
            egress.forward(out, connection(stub.url), state, settings)
        assert len(stub.requests) == 1


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout])
def test_connection_error_is_a_provider_error_without_the_key(state, settings, error):
    """Сеть подменена: отказ соединения с закрытым портом на Windows ждёт повторов около двух секунд."""
    def fail(request: httpx.Request) -> httpx.Response:
        raise error(f"не удалось, ключ {KEY}", request=request)

    out, _ = outgoing(state, settings)
    with pytest.raises(ProviderError) as caught:
        egress.forward(out, connection("http://127.0.0.1:1"), state, settings, transport=httpx.MockTransport(fail))
    assert KEY not in str(caught.value) and KEY not in repr(caught.value)
    assert isinstance(caught.value, egress.ProviderTimeout) is (error is httpx.ReadTimeout)
