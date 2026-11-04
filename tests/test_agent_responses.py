"""Протокол OpenAI Responses в шлюзе (спецификация 2026-10-28, разделы 9.3, 10.1–10.2; план 5В, задача 4): обход тела
Codex, журнал отправленного, восстановление событий потока. Тела — записи настоящего Codex
(tests/fixtures/agents/codex) и свои, с вымышленными контрольными значениями."""
import json
import re
from pathlib import Path

import pytest

from cleaner.agent_service import AgentCall, AgentService
from cleaner.core.agent import ledger
from cleaner.core.agent.protocol import PROTOCOLS
from cleaner.core.agent.responses import ResponsesStream
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import originals
from cleaner.core.types import ChatState, Settings
from cleaner.storage.repo import Provider
from tests.stub_provider import StubProvider

FIXTURES = Path(__file__).parent / "fixtures" / "agents" / "codex"
RESPONSES = PROTOCOLS["responses"]
TEXT = (
    "Почта Ivan.Petrov@Contoso.RU, узел srv-dc01.corp.contoso.ru (10.1.2.5), "
    r"профиль C:\Users\ivanov_ii\notes.txt, учётная запись CONTOSO\ivanov, password=Hunter2Hunter2"
)
HOST = re.compile(r"host-\d+\.sub-\d+\.domain-\d+\.example")
STUB_KEY = 'sk-s' 'tub-responses-0123456789'  # secret-scan:allow -- synthetic test fixture


def recorded(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def script() -> list[list[dict]]:
    return json.loads((FIXTURES / "script.json").read_text(encoding="utf-8"))


@pytest.fixture
def chat() -> tuple[ChatState, Settings]:
    state = ChatState(chat_id="agent", net_key=bytes(range(32)))
    state.written = True
    settings = Settings()
    sanitize(state, TEXT, settings)
    return state, settings


def fake(chat, text: str) -> str:
    state, settings = chat
    return sanitize(state, text, settings).sanitized


def run(stream: ResponsesStream, events: list[dict]) -> list[dict]:
    out = []
    for event in events:
        out += stream.feed(event)
    return out


def message(item_id: str, *texts: str) -> dict:
    return {"type": "message", "id": item_id, "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []} for text in texts]}


def text_events(index: int, item: dict, cuts: list[int]) -> list[dict]:
    """События сообщения: каждая часть — дельтами, разрезанными в позициях cuts, затем итоговые объекты."""
    events = [{"type": "response.output_item.added", "output_index": index, "item": dict(item, status="in_progress", content=[])}]
    for j, part in enumerate(item["content"]):
        text = part["text"]
        events.append({"type": "response.content_part.added", "item_id": item["id"], "output_index": index,
                       "content_index": j, "part": {"type": "output_text", "text": "", "annotations": []}})
        bounds = [0, *[c for c in cuts if 0 < c < len(text)], len(text)]
        events += [{"type": "response.output_text.delta", "item_id": item["id"], "output_index": index, "content_index": j,
                    "delta": text[a:b]} for a, b in zip(bounds, bounds[1:])]
        events.append({"type": "response.output_text.done", "item_id": item["id"], "output_index": index,
                       "content_index": j, "text": text})
        events.append({"type": "response.content_part.done", "item_id": item["id"], "output_index": index,
                       "content_index": j, "part": part})
    events.append({"type": "response.output_item.done", "output_index": index, "item": item})
    return events


def completed(*items: dict, cached: int = 0) -> dict:
    return {"type": "response.completed", "response": {"id": "resp_1", "status": "completed", "output": list(items), "usage": {
        "input_tokens": 1200, "input_tokens_details": {"cached_tokens": cached}, "output_tokens": 30,
        "output_tokens_details": {"reasoning_tokens": 4}, "total_tokens": 1230}}}


def call_events(index: int, item: dict, size: int = 5) -> list[dict]:
    """Вызов функции или свободного инструмента: начало, дельты аргументов по size знаков, done, output_item.done."""
    custom = item["type"] == "custom_tool_call"
    field, kind = ("input", "custom_tool_call_input") if custom else ("arguments", "function_call_arguments")
    raw = item[field]
    events = [{"type": "response.output_item.added", "output_index": index, "item": dict(item, **{field: ""}, status="in_progress")}]
    events += [{"type": f"response.{kind}.delta", "item_id": item["id"], "output_index": index, "delta": raw[i:i + size]}
               for i in range(0, len(raw), size)]
    events.append({"type": f"response.{kind}.done", "item_id": item["id"], "output_index": index, field: raw})
    events.append({"type": "response.output_item.done", "output_index": index, "item": item})
    return events


REASONING = {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "думаю про <HOST_7>"}],
             "encrypted_content": "gAAAAAB-encrypted"}


def test_codex_turn_is_split_into_units():
    body = recorded("turn3")
    units = {u.path: u for u in RESPONSES.units(body)}
    assert [units[("input", i, "content", 0)].role for i in (0, 1, 2, 3)] == ["developer", "developer", "user", "user"]
    assert units[("input", 4)].kind == "opaque"                                     # reasoning с encrypted_content
    text = units[("input", 5, "content", 0)]
    assert RESPONSES.is_model_block(text) and text.node == {"type": "output_text", "text": "Читаю файл.", "annotations": []}
    call = units[("input", 6)]
    assert RESPONSES.is_model_block(call) and call.node == {
        "type": "function_call", "name": "exec_command", "arguments": {"cmd": "Get-Content -Encoding UTF8 notes.txt"},
        "call_id": "call_cap_1"}
    assert (units[("input", 7)].kind, units[("input", 7)].role) == ("tool_result", "tool")
    patch = units[("input", 9)]
    assert patch.kind == "tool_use" and patch.node["name"] == "apply_patch" and "id" not in patch.node and "status" not in patch.node
    assert units[("input", 10)].kind == "tool_result"
    tools = {u.node["name"]: u for u in units.values() if u.kind == "tool_def" and "name" in u.node}
    grammar = tools["apply_patch"].node["format"]
    cleaned = RESPONSES.sanitize_unit(tools["apply_patch"], str.upper)
    assert cleaned["format"] == grammar and cleaned["description"] == tools["apply_patch"].node["description"].upper()
    assert units[("client_metadata",)].kind == "other"          # метаданные хода с рабочими каталогами — очищаются
    assert {"gpt-5.5", "exec_command", "apply_patch"} <= set(RESPONSES.structural(body))
    assert RESPONSES.first_user(recorded("resume")) == RESPONSES.first_user(recorded("turn1"))
    code = {u.path: u for u in RESPONSES.units(recorded("code_turn3"))}
    namespace = code[("input", 0, "tools", 0)]
    assert namespace.kind == "tool_def" and [t["name"] for t in namespace.node["tools"]][:2] == ["exec", "wait"]
    nested = RESPONSES.sanitize_unit(namespace, str.upper)["tools"][0]
    assert nested["name"] == "exec" and nested["format"] == namespace.node["tools"][0]["format"]
    assert code[("input", 9)].node["name"] == "exec" and code[("input", 9)].kind == "tool_use"


class Gateway:
    def __init__(self, repo, engines, clock, stub):
        self.repo, self.stub = repo, stub
        self.user_id = repo.create_user("ivan", "hash", "user")
        provider = repo.add_provider(Provider("", "Заглушка", "responses", f"{stub.url}/v1", "bearer", STUB_KEY, ()))
        self.key_id = repo.add_api_key(self.user_id, "агент", "h1", "aaaa", upstream=f"provider:{provider}", models=())
        self.service = AgentService(repo, engines, clock)

    def send(self, request: dict, headers: dict | None = None) -> bytes:
        reply = self.service.handle(AgentCall(
            key=self.repo.api_key(self.key_id), user=self.repo.user(self.user_id), protocol="responses", path="/responses",
            query="", headers=headers or json.loads((FIXTURES / "headers.json").read_text(encoding="utf-8"))["turn1"]["headers"],
            body=request,
        ))
        assert reply.status == 200, reply.body
        return b"".join(reply.events) if reply.events is not None else reply.body


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


@pytest.fixture
def gw(repo, engines, clock, stub) -> Gateway:
    return Gateway(repo, engines, clock, stub)


def received(raw: bytes) -> list[dict]:
    return [json.loads(line[6:]) for block in raw.decode("utf-8").split("\n\n") for line in block.split("\n")
            if line.startswith("data: ")]


def test_codex_history_hits_the_ledger(gw, stub, repo):
    """Второй ход из записи: прежние элементы — повтор из журнала, ответ модели уходит провайдеру тем, что она прислала."""
    stub.script += script()[:2]
    gw.send(recorded("turn1"))
    gw.send(recorded("turn2"))
    first, second = (request["body"]["input"] for request in stub.requests)
    assert second[:len(first)] == first                         # прежнее — тем же видом
    model = [event["item"] for event in script()[0] if event["type"] == "response.output_item.done"]
    assert second[len(first):len(first) + 3] == [dict(item, **{"content": None} if item["type"] == "reasoning" else {}) for item in model]
    latest = repo.audit_events("agent_send")[0].details           # свежие первыми
    assert latest["blocks_new"] == 2        # результат команды и впервые пересланный summary рассуждения


def test_reserialized_arguments_still_hit_the_ledger(gw, stub):
    sent: dict = {}

    def model(request: dict) -> list[dict]:
        host = HOST.search(json.dumps(request, ensure_ascii=False)).group()
        sent["arguments"] = '{"cmd":  "ping %s", "workdir": "C:\\\\repo"}' % host
        item = {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "exec_command", "arguments": sent["arguments"]}
        return [*call_events(0, item), completed(item)]

    stub.script += [model, [*text_events(0, message("msg_2", "Готово"), []), completed(message("msg_2", "Готово"))]]
    task = {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Проверь srv-dc01.corp.contoso.ru"}]}
    body = {"model": "gpt-5.5", "stream": True, "store": False, "input": [task], "tools": recorded("turn1")["tools"]}
    done = [e for e in received(gw.send(body)) if e["type"] == "response.output_item.done"][0]["item"]
    restored = json.loads(done["arguments"])
    assert restored == {"cmd": "ping srv-dc01.corp.contoso.ru", "workdir": "C:\\repo"}
    again = dict(done, arguments=json.dumps(dict(reversed(list(restored.items()))), separators=(",", ":")))
    output = {"type": "function_call_output", "call_id": "call_1", "output": "ok"}
    gw.send(dict(body, input=[task, again, output]))
    assert stub.requests[1]["body"]["input"][-2]["arguments"] == sent["arguments"]
    assert stub.requests[1]["body"]["input"][-2]["id"] == "fc_1" and "srv-dc01" not in stub.bodies()


def test_done_objects_equal_the_concatenated_deltas(chat):
    state, settings = chat
    first = fake(chat, "Узел srv-dc01.corp.contoso.ru и CONTOSO\\ivanov")
    second = fake(chat, "почта Ivan.Petrov@Contoso.RU")
    third = fake(chat, "адрес 10.1.2.5")
    restore = originals(state, settings)
    for cut in range(len(first) + 1):
        one, two = message("msg_1", first, second), message("msg_2", third)
        events = [{"type": "response.created", "response": {"id": "resp_1", "output": []}}, *text_events(0, one, [cut, cut + 3]),
                  {"type": "response.output_item.added", "output_index": 1, "item": dict(REASONING, summary=[])},
                  {"type": "response.output_item.done", "output_index": 1, "item": REASONING},
                  *text_events(2, two, [cut]), completed(one, REASONING, two)]
        out = run(ResponsesStream(state, settings), events)
        deltas: dict = {}
        for e in out:
            if e["type"] == "response.output_text.delta":
                deltas[(e["item_id"], e["content_index"])] = deltas.get((e["item_id"], e["content_index"]), "") + e["delta"]
        expected = {("msg_1", 0): restore(first), ("msg_1", 1): restore(second), ("msg_2", 0): restore(third)}
        assert deltas == expected, cut
        for e in out:
            if e["type"] == "response.output_text.done":
                assert e["text"] == expected[(e["item_id"], e["content_index"])]
            if e["type"] == "response.content_part.done":
                assert e["part"]["text"] == expected[(e["item_id"], e["content_index"])]
        items = [e["item"] for e in out if e["type"] == "response.output_item.done"]
        final = [e for e in out if e["type"] == "response.completed"][0]["response"]["output"]
        assert items == final and items[1] == REASONING
        assert [p["text"] for p in items[0]["content"]] == [restore(first), restore(second)]
        assert items[2]["content"][0]["text"] == restore(third)


def test_apply_patch_is_restored_exactly_once(chat):
    state, settings = chat
    line = fake(chat, "Учётная запись: CONTOSO\\ivanov, почта ivan.petrov@contoso.ru")
    patch = f"*** Begin Patch\n*** Update File: notes.txt\n@@\n-{line}\n+{line} (проверено)\n*** End Patch\n"
    item = {"type": "custom_tool_call", "id": "ctc_1", "call_id": "call_1", "name": "apply_patch", "input": patch, "status": "completed"}
    out = run(ResponsesStream(state, settings), [*call_events(0, item, size=4), completed(item)])
    real = "Учётная запись: CONTOSO\\ivanov, почта ivan.petrov@contoso.ru"
    expected = f"*** Begin Patch\n*** Update File: notes.txt\n@@\n-{real}\n+{real} (проверено)\n*** End Patch\n"
    deltas = [e for e in out if e["type"] == "response.custom_tool_call_input.delta"]
    assert [d["delta"] for d in deltas] == [expected]
    assert [e["input"] for e in out if e["type"] == "response.custom_tool_call_input.done"] == [expected]
    assert [e["item"]["input"] for e in out if e["type"] == "response.output_item.done"] == [expected]
    assert out[-1]["response"]["output"][0]["input"] == expected
    order = [e["type"] for e in out]
    assert order.index("response.custom_tool_call_input.delta") == order.index("response.custom_tool_call_input.done") - 1


def test_shell_command_arguments_are_restored_exactly(chat):
    state, settings = chat
    arguments = json.dumps({"cmd": fake(chat, r"Get-Content C:\Users\ivanov_ii\notes.txt; ping srv-dc01.corp.contoso.ru"),
                            "workdir": fake(chat, r"C:\Users\ivanov_ii")}, ensure_ascii=False)
    item = {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "exec_command", "arguments": arguments}
    out = run(ResponsesStream(state, settings), [*call_events(0, item, size=3), completed(item)])
    expected = {"cmd": r"Get-Content C:\Users\ivanov_ii\notes.txt; ping srv-dc01.corp.contoso.ru", "workdir": r"C:\Users\ivanov_ii"}
    assert not [e for e in out if e["type"] == "response.function_call_arguments.delta"]
    assert [json.loads(e["arguments"]) for e in out if e["type"] == "response.function_call_arguments.done"] == [expected]
    assert json.loads([e for e in out if e["type"] == "response.output_item.done"][0]["item"]["arguments"]) == expected
    assert json.loads(out[-1]["response"]["output"][0]["arguments"]) == expected


def test_instruction_goes_before_the_first_user_message():
    body = recorded("turn1")
    out = RESPONSES.add_instruction(RESPONSES.rebuild(body, {}), "ИНСТРУКЦИЯ")
    assert [(i.get("role"), i["content"][0]["text"][:20]) for i in out["input"][1:4]] == [
        ("developer", body["input"][1]["content"][0]["text"][:20]), ("developer", "ИНСТРУКЦИЯ"), ("user", "<environment_context")]
    assert len(body["input"]) == 4
    plain = RESPONSES.add_instruction({"input": "Привет"}, "И")["input"]
    assert plain == [{"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "И"}]},
                     {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Привет"}]}]


def test_encrypted_reasoning_passes_untouched(chat, gw, stub):
    state, settings = chat
    summary = [{"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "output_index": 0, "delta": "про <HOST_7>"}]
    assert run(ResponsesStream(state, settings), summary) == summary
    stub.script.append([*text_events(0, message("msg_1", "Готово"), []), completed(message("msg_1", "Готово"))])
    history = dict(REASONING, summary=[{"type": "summary_text", "text": "узел srv-dc01.corp.contoso.ru"}])
    task = {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Привет"}]}
    gw.send({"model": "gpt-5.5", "stream": True, "input": [task, history, dict(task, content=[{"type": "input_text", "text": "Дальше"}])]})
    assert stub.requests[0]["body"]["input"][2] == history


@pytest.mark.parametrize("kind", ["message", "function_call"])
def test_items_without_ids_are_restored_once_per_output_index(chat, kind):
    state, settings = chat
    host = fake(chat, "srv-dc01.corp.contoso.ru")
    if kind == "message":
        items = [message("unused", f"Узел {host}"), message("unused", "Готово")]
        for item in items:
            item.pop("id")
    else:
        items = [{"type": "function_call", "call_id": f"call_{i}", "name": "run",
                  "arguments": json.dumps({"host": host})} for i in range(2)]
    stream = ResponsesStream(state, settings)
    done = [stream.feed({"type": "response.output_item.done", "output_index": i, "item": item})[-1]["item"]
            for i, item in enumerate(items)]
    result = stream.feed(completed(*items))[-1]["response"]["output"]
    assert result == done
    assert len(stream.pairs) == 2


def test_text_streams_without_ids_stay_separate_by_output_index(chat):
    state, settings = chat
    host = fake(chat, "srv-dc01.corp.contoso.ru")
    stream = ResponsesStream(state, settings)
    for i, text in enumerate((f"Узел {host}", "Готово")):
        stream.feed({"type": "response.output_text.delta", "output_index": i, "content_index": 0, "delta": text})
    items = [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}
             for text in (f"Узел {host}", "Готово")]
    for i, item in enumerate(items):
        stream.feed({"type": "response.output_item.done", "output_index": i, "item": item})
    result = stream.feed(completed(*items))[-1]["response"]["output"]
    assert [item["content"][0]["text"] for item in result] == ["Узел srv-dc01.corp.contoso.ru", "Готово"]
    assert len(stream.pairs) == 2


def test_usage_is_read_from_completed(gw, stub, repo):
    stub.script.append([*text_events(0, message("msg_1", "Готово"), []), completed(message("msg_1", "Готово"), cached=1024)])
    gw.send({"model": "gpt-5.5", "stream": True, "input": "Привет"})
    assert repo.audit_events("agent_send")[0].details["usage"] == {"input": 1200, "output": 30, "cache_read": 1024}


def test_two_codex_sessions_are_two_conversations_and_resume_is_one():
    """Первое сообщение user у Codex — <environment_context>: у сессий в одном каталоге в один день оно одинаково. Сессию
    различает id этого элемента — свой у каждой сессии и тот же после resume (проверка 18.1b 5В)."""
    secret = bytes(range(32))
    ids = {name: ledger.conversation_id(secret, "key-1", RESPONSES.first_user(recorded(name)))
           for name in ("turn1", "resume", "code_turn3")}
    assert ids["turn1"] == ids["resume"] and ids["turn1"] != ids["code_turn3"]


def test_unknown_fields_of_items_are_cleaned(gw, stub):
    """Незнакомое поле элемента input (у сообщения, у additional_tools) — текст: очищается, а не уходит как есть (8.3)."""
    stub.script.append([*text_events(0, message("msg_1", "Готово"), []), completed(message("msg_1", "Готово"))])
    note = "заметка про srv-dc01.corp.contoso.ru"
    gw.send({"model": "gpt-5.5", "stream": True, "input": [
        {"type": "additional_tools", "role": "developer", "note": note, "tools": []},
        {"type": "message", "role": "user", "phase": note, "content": [{"type": "input_text", "text": "Проверь srv-dc01.corp.contoso.ru"}]},
    ]})
    assert "srv-dc01" not in stub.bodies()


def test_code_mode_exec_output_in_json_is_cleaned(gw, stub):
    """Приёмка 5В по подписке ChatGPT: в «code mode» вывод команды приходит строкой JSON внутри результата exec —
    «\\r\\n» знаками и «CONTOSO\\\\ivanov» с удвоенной косой. Учётная запись не уходит провайдеру."""
    stub.script.append([*text_events(0, message("msg_1", "Готово"), []), completed(message("msg_1", "Готово"))])
    shown = json.dumps({"output": "[database]\r\nhost = srv-db01.corp.contoso.ru\r\nuser = CONTOSO\\ivanov\r\n"})
    gw.send({"model": "gpt-6.1-sol", "stream": True, "input": [
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Прочитай config/app.ini"}]},
        {"type": "custom_tool_call", "call_id": "call_1", "name": "exec", "input": "text(await tools.exec_command({cmd: 'type config/app.ini'}))"},
        {"type": "custom_tool_call_output", "call_id": "call_1", "output": [
            {"type": "input_text", "text": "Script completed\nOutput:\n"}, {"type": "input_text", "text": shown}]},
    ]})
    sent = stub.bodies()
    assert "ivanov" not in sent and "CONTOSO" not in sent and "srv-db01" not in sent


def test_turn_metadata_is_cleaned_and_its_header_dropped(gw, stub):
    """x-codex-turn-metadata и client_metadata несут рабочие каталоги агента: заголовок не уходит (его не очистить), поле
    тела очищается как текст."""
    stub.script.append([*text_events(0, message("msg_1", "Готово"), []), completed(message("msg_1", "Готово"))])
    headers = json.loads((FIXTURES / "headers.json").read_text(encoding="utf-8"))["turn1"]["headers"]
    meta = json.dumps({"workspaces": {"C:\\Users\\ivanov_ii\\repo": {}}})
    body = {"model": "gpt-5.5", "stream": True, "client_metadata": {"x-codex-turn-metadata": meta}, "input": [
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Открой C:\\Users\\ivanov_ii\\repo"}]}]}
    gw.send(body, headers=dict(headers, **{"x-codex-turn-metadata": meta}))
    sent = stub.headers(0)
    assert "x-codex-turn-metadata" not in sent and sent["session-id"] == headers["session-id"]
    assert sent["x-codex-window-id"] == headers["x-codex-window-id"] and "ivanov_ii" not in stub.bodies()
