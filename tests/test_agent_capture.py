"""Заглушка записи запросов агента (scripts/agent_capture.py): подстановки в шаги сценария из запроса — так сценарий
«прочитать файл → правка» берёт строку файла в том виде, в каком её увидела модель за шлюзом (приёмка AC-5.1)."""
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from scripts import agent_capture

REQUEST = {"messages": [
    {"role": "user", "content": "Прочитай notes.txt"},
    {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {}}]},
    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
        {"type": "text", "text": '     1\tУзел host-1.sub-2.domain-1.example\n     2\tПочта: "<EMAIL_2>" \\ отчёты\n'},
    ]}]},
]}


def test_steps_take_lines_and_matches_from_the_last_tool_result():
    step = [
        {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(
            {"old_string": "{{line:Почта:}}", "command": "ping {{re:host-\\d+(?:\\.[\\w-]+)+}}"}, ensure_ascii=False,
        )}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "Строка: {{line:Узел}}"}},
    ]
    rendered = agent_capture.render(step, REQUEST)
    assert json.loads(rendered[0]["delta"]["partial_json"]) == {
        "old_string": 'Почта: "<EMAIL_2>" \\ отчёты', "command": "ping host-1.sub-2.domain-1.example",
    }
    assert rendered[1]["delta"]["text"] == "Строка: Узел host-1.sub-2.domain-1.example"
    assert agent_capture.render(step, {"messages": []}) == step          # подставить нечего — как есть


OUTPUT = 'Узел host-1.sub-2.domain-1.example\nПочта: "<EMAIL_2>" \\ отчёты\n'
CHAT = {"model": "m", "stream": True, "tools": [{"type": "function"}], "messages": [
    {"role": "user", "content": "Прочитай notes.txt"},
    {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "read", "arguments": "{}"}}]},
    {"role": "tool", "tool_call_id": "c1", "content": OUTPUT},
]}
RESPONSES = {"model": "m", "stream": True, "tools": [{"type": "function"}], "input": [
    {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Прочитай notes.txt"}]},
    {"type": "function_call", "call_id": "c1", "name": "shell_command", "arguments": "{}"},
    {"type": "function_call_output", "call_id": "c1", "output": OUTPUT},
]}


def test_chat_and_responses_steps_take_lines_from_tool_outputs():
    call = {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {
        "arguments": json.dumps({"old": "{{line:Почта:}}"}, ensure_ascii=False)}}]}}]}
    assert json.loads(agent_capture.render([call], CHAT)[0]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]) == {
        "old": 'Почта: "<EMAIL_2>" \\ отчёты'}
    patch = {"type": "response.output_item.done", "item": {"type": "custom_tool_call", "input": "-{{line:Почта:}}"}}
    done = {"type": "response.output_item.done", "item": {"type": "function_call", "arguments": json.dumps(
        {"command": "ping {{re:host-\\d+(?:\\.[\\w-]+)+}}"})}}
    rendered = agent_capture.render([patch, done], RESPONSES)
    assert rendered[0]["item"]["input"] == '-Почта: "<EMAIL_2>" \\ отчёты'          # текст патча — без экранирования
    assert json.loads(rendered[1]["item"]["arguments"]) == {"command": "ping host-1.sub-2.domain-1.example"}


@pytest.fixture
def capture(tmp_path):
    servers = []

    def start(steps, *, headers_only=False):
        server = ThreadingHTTPServer(("127.0.0.1", 0), agent_capture.make_handler(tmp_path, steps, headers_only=headers_only))
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _post(url: str, body: dict, headers: dict | None = None) -> str:
    request = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", **(headers or {})})
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read().decode("utf-8")


def test_each_protocol_gets_its_stream_format(capture, tmp_path):
    chunk = {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "Готово"}, "finish_reason": "stop"}]}
    event = {"type": "response.completed", "response": {"id": "resp_1", "output": []}}
    url = capture([[chunk], [event]])
    assert _post(f"{url}/v1/chat/completions", CHAT) == f"data: {json.dumps(chunk, ensure_ascii=False)}\n\ndata: [DONE]\n\n"
    assert _post(f"{url}/v1/responses", RESPONSES) == f"event: response.completed\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
    service = _post(f"{url}/v1/responses", dict(RESPONSES, tools=[]))      # служебный запрос без инструментов — «ok»
    assert '"delta": "ok"' in service and "response.completed" in service
    assert json.loads((tmp_path / "001.json").read_text(encoding="utf-8"))["body"]["messages"][0]["content"] == "Прочитай notes.txt"


def test_code_mode_tools_in_input_take_a_step(capture):
    """Codex в «code mode» (модели gpt-6.x) шлёт инструменты элементом input вида additional_tools, а не полем tools."""
    event = {"type": "response.completed", "response": {"id": "resp_1", "output": []}}
    request = dict(RESPONSES, tools=None, input=[{"type": "additional_tools", "tools": [{"type": "custom"}]}, *RESPONSES["input"]])
    assert "resp_1" in _post(f"{capture([[event]])}/v1/responses", request)


def test_headers_only_keeps_no_body_and_no_token(capture, tmp_path):
    url = capture([], headers_only=True)
    _post(f"{url}/v1/messages", {"messages": [{"role": "user", "content": "личное"}]}, {"authorization": "Bearer secret-token-1"})
    record = (tmp_path / "001.json").read_text(encoding="utf-8")
    assert "личное" not in record and "secret-token-1" not in record
    assert json.loads(record)["headers"]["authorization"] == "Bearer (14)"
