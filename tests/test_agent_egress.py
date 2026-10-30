"""Запрос шлюза в ядре и модуль выхода egress.forward (спецификация 2026-10-28, разделы 5, 8.9, 9.1; SEC-1, SEC-2,
SEC-13): провайдер получает только собранное pipeline, заголовки из списка и ключ подключения."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


@pytest.fixture
def pool():
    """Пул соединений шлюза — общий для процесса: в каждом тесте свой, закрывается в конце."""
    egress.close_clients()
    yield
    egress.close_clients()


class _Provider(ThreadingHTTPServer):
    """Провайдер на петле: HTTP/1.1, ответ 400 с content-length; считает принятые соединения и пишет вход запросов.
    drop — закрыть сокет после ответа, не предупредив заголовком Connection: close. silent — на первый запрос начать
    поток и молчать до release."""
    daemon_threads = True

    def __init__(self, drop: bool = False, silent: bool = False):
        self.drop = drop
        self.silent = silent
        self.release = threading.Event()
        self.connections = 0
        self.logins: list[str] = []
        self.cookies: list[str] = []                # заголовок Cookie каждого запроса
        self.closed = threading.Event()             # сокет, закрытый после ответа, закрыт
        super().__init__(("127.0.0.1", 0), _ProviderHandler)
        self.url = f"http://127.0.0.1:{self.server_address[1]}"

    def get_request(self):
        accepted = super().get_request()
        self.connections += 1
        return accepted

    def shutdown_request(self, request) -> None:
        super().shutdown_request(request)
        self.closed.set()

    def __enter__(self):
        threading.Thread(target=self.serve_forever, args=(0.01,), daemon=True).start()     # остановка без ожидания 0,5 с
        return self

    def __exit__(self, *exc) -> None:
        self.shutdown()
        self.server_close()


class _ProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers["content-length"]))
        self.server.logins.append(self.headers.get("authorization", ""))
        self.server.cookies.append(self.headers.get("cookie", ""))
        if self.server.silent and len(self.server.logins) == 1:
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"9\r\ndata: 1\n\n\r\n")    # часть потока, как у провайдера, — chunked
            self.server.release.wait(5)            # модель думает
            self.close_connection = True
            return
        body = json.dumps({"type": "error", "error": {"type": "invalid_request_error", "message": "нет"}}).encode()
        self.send_response(400)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("set-cookie", "acct=first-user-session; Path=/")     # как __cf_bm у Cloudflare
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = self.server.drop

    def log_message(self, *args) -> None:
        pass


def _ask(out, conn, state, settings) -> int:
    upstream = egress.forward(out, conn, state, settings)
    try:
        upstream.read(1 << 20)
    finally:
        upstream.close()
    return upstream.status


def test_provider_connection_is_reused_between_requests(state, settings, pool):
    out, _ = outgoing(state, settings)
    with _Provider() as provider:
        statuses = [_ask(out, connection(provider.url), state, settings) for _ in range(2)]
    assert statuses == [400, 400] and provider.connections == 1


def test_connection_closed_by_the_provider_between_requests_is_not_reused(state, settings, pool):
    """Провайдер закрыл соединение из пула, пока агент выполнял команду: следующий ход — по новому, а не 502."""
    out, _ = outgoing(state, settings)
    with _Provider(drop=True) as provider:
        assert _ask(out, connection(provider.url), state, settings) == 400
        assert provider.closed.wait(5)
        assert _ask(out, connection(provider.url), state, settings) == 400
    assert provider.connections == 2


def test_aborted_response_frees_the_reader_and_its_connection_is_not_reused(state, settings, pool):
    """Агент ушёл, пока провайдер молчит: abort из другого потока будит чтение сразу, а не через 300 с, и соединение с
    недочитанным ответом в пул не возвращается."""
    out, _ = outgoing(state, settings)
    with _Provider(silent=True) as provider:
        upstream = egress.forward(out, connection(provider.url), state, settings)
        lines, first = [], threading.Event()

        def read() -> None:
            try:
                for line in upstream.lines():
                    lines.append(line)
                    first.set()
            except ProviderError:
                pass

        reader = threading.Thread(target=read)
        reader.start()
        try:
            assert first.wait(2)
            time.sleep(0.05)                        # чтение ждёт провайдера
            started = time.perf_counter()
            upstream.abort()
            reader.join(2)
            assert not reader.is_alive() and time.perf_counter() - started < 1
            upstream.close()
            assert _ask(out, connection(provider.url), state, settings) == 400
        finally:
            provider.release.set()
    assert lines[0] == "data: 1" and provider.connections == 2


def test_abort_after_the_response_ended_leaves_the_socket_alone(state, settings, pool, monkeypatch):
    """Ответ дочитан: httpx закрыл его и вернул соединение в пул раньше, чем Upstream.close. abort в этом окне не трогает
    сокет — его мог уже взять другой запрос (финальное ревью 5Г, M4). Путь Linux — подменой платформы."""
    out, _ = outgoing(state, settings)
    shut: list = []
    with _Provider() as provider:
        upstream = egress.forward(out, connection(provider.url), state, settings)
        upstream.read(1 << 20)
        with monkeypatch.context() as patch:
            patch.setattr(egress.sys, "platform", "linux")
            patch.setattr(egress.socket.socket, "shutdown", lambda sock, how: shut.append(how))
            upstream.abort()
        upstream.close()
    assert shut == []


def test_pooled_connection_carries_each_requests_own_login(state, settings, pool):
    """Вход по подписке — заголовок запроса, а не состояние соединения: два агента через одно соединение. Cookie
    провайдера клиент пула не хранит и следующему агенту не отдаёт (финальное ревью 5Г, I1)."""
    proto = PROTOCOLS["anthropic"]
    logins = ["Bearer REDACTED_ANTHROPIC_KEY", "Bearer REDACTED_ANTHROPIC_KEY"]
    with _Provider() as provider:
        subscription = Connection("anthropic", provider.url, "passthrough", "", 0)
        for login in logins:
            out, _ = build_agent_outgoing(
                state, settings, chat_id=state.chat_id, provider_id="sub", path="/v1/messages", query="",
                headers={**AGENT_HEADERS, "authorization": login}, allowed=proto.headers | proto.subscription_headers,
                body={"model": "m-1", "messages": [{"role": "user", "content": "вопрос"}]}, checked=[],
            )
            assert _ask(out, subscription, state, settings) == 400
    assert provider.logins == logins and provider.connections == 1
    assert provider.cookies == ["", ""]
