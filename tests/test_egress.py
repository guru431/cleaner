"""Модуль выхода в сеть (раздел 10.3): протоколы, проверка утечек, адреса, ошибки провайдера. Сеть подменена."""
import json
import threading
import uuid
from dataclasses import replace

import httpx
import pytest

from cleaner.agent_service import SUBSCRIPTIONS
from cleaner.core.pipeline import OutMessage, Turn, build_outgoing, probe_context
from cleaner.egress import ProviderError
from cleaner.egress.cloud import Connection, LeakDetected, check_extra_body, check_url, send, session_headers

KEY = 'sk-t' 'est-0123456789abcdef'  # secret-scan:allow -- synthetic test fixture


def connection(protocol: str = "openai", base_url: str = "https://llm.example/v1", **extra) -> Connection:
    auth = "bearer" if protocol == "openai" else "x-api-key"
    return Connection(protocol, base_url, auth, KEY, 1024, extra)


def sse(*events: object, done: bool = True) -> bytes:
    lines = [f"data: {json.dumps(event, ensure_ascii=False)}\n\n" for event in events]
    return ("".join(lines) + ("data: [DONE]\n\n" if done else "")).encode("utf-8")


def openai_chunks(*pieces: str) -> bytes:
    return sse(*({"choices": [{"delta": {"content": piece}}]} for piece in pieces))


def anthropic_chunks(*pieces: str, stop: str = "end_turn") -> bytes:
    events = [{"type": "message_start", "message": {}}, {"type": "ping"}]
    events += [{"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}} for p in pieces]
    events += [{"type": "message_delta", "delta": {"stop_reason": stop}}, {"type": "message_stop"}]
    return sse(*events, done=False)


class Recorder:
    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None):
        self.body, self.status, self.headers = body, status, headers or {}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, content=self.body, headers={"content-type": "text/event-stream", **self.headers})

    @property
    def json(self) -> dict:
        return json.loads(self.requests[-1].content)


def run(ctx, conn, recorder, state=None, settings=None, **kwargs) -> str:
    return "".join(send(ctx, conn, state, settings, transport=httpx.MockTransport(recorder), **kwargs))


@pytest.fixture
def ctx(state, settings):
    turns = [Turn("system", "Кратко"), Turn("user", "Вопрос про a@contoso.example")]
    return build_outgoing(state, turns, settings, "p1", "model-x").context


def test_openai_request_and_stream(ctx, state, settings):
    recorder = Recorder(openai_chunks("Отв", "ет: <EMAIL_1>"))
    assert run(ctx, connection(), recorder, state, settings) == "Ответ: <EMAIL_1>"
    request = recorder.requests[0]
    assert str(request.url) == "https://llm.example/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {KEY}" and "x-api-key" not in request.headers
    body = recorder.json
    assert (body["model"], body["max_tokens"], body["stream"]) == ("model-x", 1024, True)
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert body["messages"][1]["content"] == "Вопрос про <EMAIL_1>"


def test_anthropic_request_and_stream(ctx, state, settings):
    recorder = Recorder(anthropic_chunks("Готово, ", "<EMAIL_1>"))
    conn = connection("anthropic", "https://llm.example/anthropic")
    assert run(ctx, conn, recorder, state, settings) == "Готово, <EMAIL_1>"
    request = recorder.requests[0]
    assert str(request.url) == "https://llm.example/anthropic/v1/messages"
    assert request.headers["x-api-key"] == KEY and "authorization" not in request.headers
    assert request.headers["anthropic-version"] == "2023-06-01"
    body = recorder.json
    assert body["system"].endswith("Кратко") and [m["role"] for m in body["messages"]] == ["user"]


def responses_events(*pieces: str, end: dict | None = None) -> bytes:
    events = [{"type": "response.created", "response": {"id": "resp_1", "status": "in_progress", "output": []}}]
    events += [{"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": p}
               for p in pieces]
    events.append(end or {"type": "response.completed", "response": {"id": "resp_1", "status": "completed"}})
    return sse(*events, done=False)


def test_responses_adapter_sends_input_and_reads_deltas(ctx, state, settings):
    """Подключение с протоколом Responses (план 5В, задача 5): OpenAI API, модели OpenCode Go на /v1/responses."""
    recorder = Recorder(responses_events("Отв", "ет: <EMAIL_1>"))
    conn = Connection("responses", "https://llm.example/v1", "bearer", KEY, 1024, {"reasoning": {"effort": "low"}})
    assert run(ctx, conn, recorder, state, settings) == "Ответ: <EMAIL_1>"
    request = recorder.requests[0]
    assert str(request.url) == "https://llm.example/v1/responses" and request.headers["authorization"] == f"Bearer {KEY}"
    body = recorder.json
    assert (body["model"], body["stream"], body["store"], body["max_output_tokens"]) == ("model-x", True, False, 1024)
    assert body["reasoning"] == {"effort": "low"}
    assert [(m["role"], m["content"][-6:]) for m in body["input"]] == [("developer", "Кратко"), ("user", "AIL_1>")]
    incomplete = {"type": "response.incomplete", "response": {"incomplete_details": {"reason": "max_output_tokens"}}}
    outcome: dict = {}
    assert run(probe_context("p", "m"), conn, Recorder(responses_events("Обры", end=incomplete)), outcome=outcome) == "Обры"
    assert outcome == {"truncated": True}
    failed = {"type": "response.failed", "response": {"error": {"code": "server_error", "message": "упало"}}}
    with pytest.raises(ProviderError) as caught:
        run(probe_context("p", "m"), conn, Recorder(responses_events("x", end=failed)))
    assert (caught.value.kind, caught.value.detail) == ("server_error", "упало")
    with pytest.raises(ValueError, match="input"):
        check_extra_body({"input": [{"role": "user", "content": "в обход очистки"}]})


def test_reasoning_is_not_shown():
    openai = sse({"choices": [{"delta": {"reasoning_content": "думаю"}}]}, {"choices": [{"delta": {"content": "итог"}}]})
    assert run(probe_context("p", "m"), connection(), Recorder(openai)) == "итог"
    thinking = sse(
        {"type": "content_block_delta", "delta": {"type": "thinking_delta", "thinking": "думаю"}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "итог"}}, {"type": "message_stop"},
        done=False,
    )
    assert run(probe_context("p", "m"), connection("anthropic"), Recorder(thinking)) == "итог"


def test_truncated_answer_is_reported():
    outcome: dict = {}
    run(probe_context("p", "m"), connection("anthropic"), Recorder(anthropic_chunks("часть", stop="max_tokens")), outcome=outcome)
    assert outcome == {"truncated": True}
    outcome = {}
    body = sse({"choices": [{"delta": {"content": "часть"}, "finish_reason": "length"}]})
    run(probe_context("p", "m"), connection(), Recorder(body), outcome=outcome)
    assert outcome == {"truncated": True}


def test_leak_blocks_the_request_before_any_connection(ctx, state, settings):
    """AC-3.4: подложенный в исходящий текст оригинал — отказ, провайдер ничего не получает."""
    leaky = replace(ctx, messages=(*ctx.messages, OutMessage("user", "напомню: a@contoso.example")))
    recorder = Recorder(openai_chunks("x"))
    with pytest.raises(LeakDetected):
        run(leaky, connection(), recorder, state, settings)
    assert recorder.requests == []


@pytest.mark.parametrize("url", ["http://llm.example/v1", "http://10.20.0.10:30000/v1", "ftp://llm.example", "llm.example"])
def test_plain_http_is_refused_beyond_loopback(url):
    with pytest.raises(ValueError):
        check_url(url)
    with pytest.raises(ValueError):
        run(probe_context("p", "m"), connection(base_url=url), Recorder(openai_chunks("x")))


@pytest.mark.parametrize("url", ["https://llm.example/v1", "http://127.0.0.1:8080/v1", "http://localhost/v1", "http://[::1]:9/v1"])
def test_https_and_loopback_are_accepted(url):
    check_url(url)


def test_redirect_is_not_followed():
    recorder = Recorder(b"", status=307, headers={"location": "https://other.example/v1/chat/completions"})
    with pytest.raises(ProviderError, match="307"):
        run(probe_context("p", "m"), connection(), recorder)
    assert len(recorder.requests) == 1


def test_key_is_scrubbed_from_provider_errors():
    body = json.dumps({"error": {"type": "invalid_api_key", "message": f"Incorrect API key provided: {KEY}"}}).encode()
    with pytest.raises(ProviderError) as error:
        run(probe_context("p", "m"), connection(), Recorder(body, status=401))
    assert str(error.value) == "провайдер отклонил ключ подключения (код 401, invalid_api_key)"
    assert error.value.detail == "Incorrect API key provided: ***"


def test_provider_message_stays_out_of_the_stored_reason():
    """Сообщение провайдера может повторять текст запроса: в постоянное объяснение (meta, журнал) оно не входит."""
    body = json.dumps({"error": {"type": "invalid_request_error", "message": "в запросе «<PERSON_1> из бухгалтерии»"}}).encode()
    with pytest.raises(ProviderError) as error:
        run(probe_context("p", "m"), connection(), Recorder(body, status=400))
    assert "PERSON" not in str(error.value) and "PERSON" in error.value.detail
    with pytest.raises(ProviderError, match="сбой на стороне провайдера \\(код 502\\)"):
        run(probe_context("p", "m"), connection(), Recorder(b"<html>Bad gateway</html>", status=502))


def test_error_event_inside_the_stream():
    body = sse({"choices": [{"delta": {"content": "нач"}}]}, {"error": {"message": "overloaded"}})
    pieces = []
    with pytest.raises(ProviderError, match="прервал ответ ошибкой") as error:
        for piece in send(probe_context("p", "m"), connection(), None, None, transport=httpx.MockTransport(Recorder(body))):
            pieces.append(piece)
    assert pieces == ["нач"] and error.value.detail == "overloaded"
    anthropic = sse({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}, done=False)
    with pytest.raises(ProviderError, match="overloaded_error"):
        run(probe_context("p", "m"), connection("anthropic"), Recorder(anthropic))


def test_connection_failure_has_a_fixed_message():
    def refuse(request):
        raise httpx.ConnectError("[Errno 111] Connection refused to llm.example")

    with pytest.raises(ProviderError, match="соединение с провайдером"):
        "".join(send(probe_context("p", "m"), connection(), None, None, transport=httpx.MockTransport(refuse)))


def test_cancel_stops_reading():
    cancel = threading.Event()
    pieces = []
    for piece in send(probe_context("p", "m"), connection(), None, None, cancel=cancel,
                      transport=httpx.MockTransport(Recorder(openai_chunks("a", "b", "c")))):
        pieces.append(piece)
        cancel.set()
    assert pieces == ["a"]


@pytest.mark.parametrize("protocol, body", [
    ("openai", sse({"choices": [{"delta": {"content": "половина"}}]}, done=False)),
    ("anthropic", sse({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "половина"}}, done=False)),
])
def test_stream_cut_without_its_end_marker_is_an_error(protocol, body):
    """Раздел 16: соединение закрылось без [DONE] или message_stop — обрыв, а не весь ответ."""
    pieces = []
    with pytest.raises(ProviderError, match="оборвался"):
        for piece in send(probe_context("p", "m"), connection(protocol), None, None,
                          transport=httpx.MockTransport(Recorder(body))):
            pieces.append(piece)
    assert pieces == ["половина"]


def test_finish_reason_without_done_is_a_complete_answer():
    body = sse({"choices": [{"delta": {"content": "всё"}, "finish_reason": "stop"}]}, done=False)
    assert run(probe_context("p", "m"), connection(), Recorder(body)) == "всё"


def test_stop_before_the_request_sends_nothing():
    cancel = threading.Event()
    cancel.set()
    recorder = Recorder(openai_chunks("x"))
    assert run(probe_context("p", "m"), connection(), recorder, cancel=cancel) == ""
    assert recorder.requests == []


def test_closing_the_connection_from_stop_ends_the_stream_quietly():
    """«Остановить» закрывает соединение: ожидание молчащего провайдера прерывается без ошибки."""
    cancel, closers, pieces = threading.Event(), [], []
    for piece in send(probe_context("p", "m"), connection(), None, None, cancel=cancel, on_open=closers.append,
                      transport=httpx.MockTransport(Recorder(openai_chunks("a", "b", "c")))):
        pieces.append(piece)
        cancel.set()
        closers[0]()
    assert pieces == ["a"]


def test_max_completion_tokens_replaces_max_tokens():
    recorder = Recorder(openai_chunks("x"))
    run(probe_context("p", "m"), connection(max_completion_tokens=4000), recorder)
    assert recorder.json["max_completion_tokens"] == 4000 and "max_tokens" not in recorder.json


@pytest.mark.parametrize(
    "protocol, chunks", [("openai", openai_chunks("x")), ("anthropic", anthropic_chunks("x"))], ids=["openai", "anthropic"],
)
def test_max_tokens_in_extra_body_wins_over_the_connection_limit(protocol, chunks):
    """FINDINGS P2 «Если пользователь задал max_tokens в extra_body подключения,...»: предел подключения затирал его молча."""
    recorder = Recorder(chunks)
    run(probe_context("p", "m"), connection(protocol, max_tokens=8000), recorder)
    assert recorder.json["max_tokens"] == 8000


def test_extra_body_cannot_add_tools_or_replace_messages():
    check_extra_body({"temperature": 0.2, "provider": {"data_collection": "deny"}})
    for extra in ({"tools": []}, {"messages": []}, {"model": "x"}, {"web_search_options": {}}, {"plugins": []},
                  {"enable_search": True}, ["list"]):
        with pytest.raises(ValueError):
            check_extra_body(extra)


def test_extra_body_reaches_the_request():
    recorder = Recorder(openai_chunks("x"))
    run(probe_context("p", "m"), connection(temperature=0.2), recorder)
    assert recorder.json["temperature"] == 0.2


def test_only_context_from_the_pipeline_is_accepted():
    with pytest.raises(TypeError):
        "".join(send({"messages": [{"role": "user", "content": "x"}]}, connection(), None, None))


def test_connection_repr_hides_the_key():
    assert KEY not in repr(connection()) and KEY not in str(connection())


def test_session_header_only_for_listed_hosts():
    """OpenCode Go без x-opencode-session отвечает 400 MissingSessionID по всем трём протоколам (план 5Г)."""
    for url in ("https://opencode.ai/zen/go", "https://opencode.ai/zen/go/v1"):
        header = session_headers(url, "seed-1")
        assert list(header) == ["x-opencode-session"] and uuid.UUID(header["x-opencode-session"]).version == 4
        assert header == session_headers(url, "seed-1") != session_headers(url, "seed-2")
    for url in ("https://api.deepseek.com/anthropic", *(address for _, address in SUBSCRIPTIONS.values())):
        assert session_headers(url, "seed-1") == {}


def test_chat_send_and_provider_check_carry_the_session_header(ctx, state, settings):
    conn = connection("anthropic", "https://opencode.ai/zen/go")
    sessions = []
    for context, chat_state in ((ctx, state), (ctx, state), (probe_context("p", "m"), None), (probe_context("p", "m"), None)):
        recorder = Recorder(anthropic_chunks("x"))
        run(context, conn, recorder, chat_state, settings)
        sessions.append(recorder.requests[0].headers["x-opencode-session"])
    assert sessions[0] == sessions[1] == session_headers(conn.base_url, ctx.chat_id)["x-opencode-session"]
    # Проверка подключения — с пустым chat_id: значение случайное, но заголовок есть.
    assert uuid.UUID(sessions[2]).version == 4 and len(set(sessions)) == 3
    recorder = Recorder(anthropic_chunks("x"))
    run(probe_context("p", "m"), connection("anthropic", "https://llm.example/anthropic"), recorder)
    assert "x-opencode-session" not in recorder.requests[0].headers
