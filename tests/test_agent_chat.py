"""Протокол Chat Completions в шлюзе (спецификация 2026-10-28, разделы 9.2, 10.1–10.2; план 5В, задача 3): обход тела
OpenCode, журнал отправленного по разобранным аргументам, восстановление частей потока. Тела — записи настоящего
OpenCode (tests/fixtures/agents/opencode) и свои, с вымышленными контрольными значениями."""
import json
import re
from pathlib import Path

import pytest

from cleaner.agent_service import AgentCall, AgentService
from cleaner.core.agent.chat import ChatStream
from cleaner.core.agent.protocol import PROTOCOLS
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import originals
from cleaner.core.types import ChatState, Policy, Settings
from cleaner.core.types import EntityType as T
from cleaner.storage.repo import Provider
from tests import test_agent_responses as responses_tests
from tests.stub_provider import StubProvider

FIXTURES = Path(__file__).parent / "fixtures" / "agents" / "opencode"
CHAT = PROTOCOLS["chat"]
TEXT = (
    "Почта Ivan.Petrov@Contoso.RU, узел srv-dc01.corp.contoso.ru (10.1.2.5), "
    r"профиль C:\Users\ivanov_ii\notes.txt, учётная запись CONTOSO\ivanov, password=Hunter2Hunter2"
)
HOST = re.compile(r"host-\d+\.sub-\d+\.domain-\d+\.example")
STUB_KEY = "REDACTED_SK_KEY"


def recorded(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


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


def chunk(delta: dict | None = None, finish: str | None = None, index: int = 0) -> dict:
    return {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 0, "model": "m-1",
            "choices": [{"index": index, "delta": delta or {}, "finish_reason": finish}]}


def usage_chunk(cached: int = 0) -> dict:
    return {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 0, "model": "m-1", "choices": [],
            "usage": {"prompt_tokens": 100, "completion_tokens": 9, "total_tokens": 109,
                      "prompt_tokens_details": {"cached_tokens": cached}}}


def call_chunks(index: int, call_id: str, name: str, arguments: str, size: int = 7) -> list[dict]:
    """Вызов частями: первая — с id и именем, затем аргументы по size знаков."""
    out = [chunk({"tool_calls": [{"index": index, "id": call_id, "type": "function", "function": {"name": name, "arguments": ""}}]})]
    out += [chunk({"tool_calls": [{"index": index, "function": {"arguments": arguments[i:i + size]}}]})
            for i in range(0, len(arguments), size)]
    return out


def run(stream: ChatStream, chunks: list[dict]) -> list[dict]:
    out = []
    for part in chunks:
        out += stream.feed(part)
    return out


def content_of(chunks: list[dict]) -> str:
    return "".join(c["choices"][0]["delta"].get("content") or "" for c in chunks if c.get("choices"))


def calls_of(chunks: list[dict]) -> list[dict]:
    return [call for c in chunks if c.get("choices") for call in c["choices"][0]["delta"].get("tool_calls") or ()]


def test_opencode_turn_is_split_into_units():
    units = {u.path: u for u in CHAT.units(recorded("turn2"))}
    assert (units[("messages", 0, "content")].role, units[("messages", 0, "content")].kind) == ("system", "text")
    assert units[("messages", 1, "content")].node == {"type": "text", "text": "\"Прочитай notes.txt и отметь строку учётной записи\"\n"}
    assert CHAT.is_model_block(units[("messages", 2, "content")])
    call = units[("messages", 2, "tool_calls", 0)]
    assert call.kind == "tool_use" and CHAT.is_model_block(call) and call.node == {"id": "call_cap_1", "type": "function", "function": {
        "name": "read", "arguments": {"filePath": "C:\\cleaner-capture\\contoso-repo\\notes.txt"}}}
    assert units[("messages", 2, "reasoning_content")].kind == "reasoning"
    result = units[("messages", 3)]
    assert (result.role, result.kind) == ("tool", "tool_result") and "Учётная запись: CONTOSO\\ivanov" in result.node["content"]
    tools = [u for u in units.values() if u.kind == "tool_def"]
    assert [u.node["function"]["name"] for u in tools] == [
        "bash", "read", "glob", "grep", "edit", "write", "task", "webfetch", "todowrite", "skill",
    ]
    read = CHAT.sanitize_unit(tools[1], str.upper)["function"]
    assert read["name"] == "read" and read["description"] == tools[1].node["function"]["description"].upper()
    assert read["parameters"]["type"] == "object" and read["parameters"]["required"] == tools[1].node["function"]["parameters"]["required"]
    assert not [u for u in units.values() if u.role == "params"]        # все поля OpenCode — известные параметры
    assert {"capture-model", "read", "bash"} <= set(CHAT.structural(recorded("turn2")))
    assert CHAT.first_user(recorded("turn3")) == CHAT.first_user(recorded("turn1"))


class Gateway:
    """Ключ шлюза к подключению OpenAI-совместимой заглушки и служба шлюза."""

    def __init__(self, repo, engines, clock, stub):
        self.repo, self.stub = repo, stub
        self.user_id = repo.create_user("ivan", "hash", "user")
        provider = repo.add_provider(Provider("", "Заглушка", "openai", f"{stub.url}/v1", "bearer", STUB_KEY, ("m-1",)))
        self.key_id = repo.add_api_key(self.user_id, "агент", "h1", "aaaa", upstream=f"provider:{provider}", models=())
        self.service = AgentService(repo, engines, clock)

    def send(self, request: dict) -> bytes:
        reply = self.service.handle(AgentCall(
            key=self.repo.api_key(self.key_id), user=self.repo.user(self.user_id), protocol="chat", path="/chat/completions",
            query="", headers={"content-type": "application/json", "authorization": "Bearer ck_agent", "x-session-affinity": "ses_1"},
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


def opencode(*messages: dict) -> dict:
    """Ход OpenCode: системная часть и инструменты из записи, свои сообщения."""
    base = recorded("turn1")
    return dict(base, model="m-1", messages=[base["messages"][0], *messages])


def received(raw: bytes) -> list[dict | str]:
    """Части потока, которые получил агент; «[DONE]» — строкой."""
    out = []
    for line in raw.decode("utf-8").split("\n\n"):
        if line.startswith("data: "):
            data = line[6:]
            out.append(data if data == "[DONE]" else json.loads(data))
    return out


def test_recorded_opencode_turn_goes_through(gw, stub):
    """Первый ход OpenCode как есть: в описании bash пример «/Users/name/My Documents» даёт учётную запись «name», а схема
    инструмента skill требует свойство «name» (required) — имена свойств схемы не очищаются и на утечки не проверяются."""
    stub.script.append([chunk({"content": "Готово"}), chunk({}, "stop")])
    gw.send(dict(recorded("turn1"), model="m-1"))
    skill = stub.requests[0]["body"]["tools"][-1]["function"]
    assert skill["name"] == "skill" and skill["parameters"]["required"] == ["name"]


def test_reserialized_arguments_still_hit_the_ledger(gw, stub):
    """AI SDK пишет аргументы вызова в истории заново (без пробелов, своим порядком ключей, проверка 18.1c 5В): блок
    находится в журнале по разобранным аргументам, а к провайдеру уходит то, что прислала модель."""
    sent: dict = {}

    def model(request: dict) -> list[dict]:
        host = HOST.search(json.dumps(request, ensure_ascii=False)).group()
        sent["arguments"] = '{"host": "%s",  "filePath": "C:\\\\a.txt"}' % host          # два пробела — вид модели
        return [chunk({"role": "assistant", "content": "Смотрю."}), *call_chunks(0, "call_1", "read", sent["arguments"]),
                chunk({}, "tool_calls")]

    stub.script += [model, [chunk({"role": "assistant", "content": "Готово"}), chunk({}, "stop")]]
    task = {"role": "user", "content": "Проверь узел srv-dc01.corp.contoso.ru"}
    first = received(gw.send(opencode(task)))
    restored = json.loads(calls_of([c for c in first if isinstance(c, dict)])[1]["function"]["arguments"])
    assert restored == {"host": "srv-dc01.corp.contoso.ru", "filePath": "C:\\a.txt"}
    again = json.dumps(dict(reversed(list(restored.items()))), ensure_ascii=False, separators=(",", ":"))
    history = {"role": "assistant", "content": "Смотрю.", "tool_calls": [
        {"id": "call_1", "type": "function", "function": {"name": "read", "arguments": again}}]}
    gw.send(opencode(task, history, {"role": "tool", "tool_call_id": "call_1", "content": "файл прочитан"}))
    assert stub.requests[1]["body"]["messages"][3]["tool_calls"][0]["function"]["arguments"] == sent["arguments"]
    assert "srv-dc01" not in stub.bodies()


def test_label_cut_at_every_position_restores_like_the_whole_text(chat):
    state, settings = chat
    answer = fake(chat, "Узел srv-dc01.corp.contoso.ru, почта Ivan.Petrov@Contoso.RU и CONTOSO\\ivanov")
    whole = originals(state, settings)(answer)
    for cut in range(len(answer) + 1):
        parts = [chunk({"role": "assistant", "content": answer[:cut]}), chunk({"content": answer[cut:]}), chunk({}, "stop")]
        out = run(ChatStream(state, settings), parts)
        assert content_of(out) == whole, cut
        assert out[-1]["choices"][0]["finish_reason"] == "stop"


def test_tool_arguments_are_sent_once_restored_exactly(chat):
    state, settings = chat
    arguments = json.dumps({
        "filePath": fake(chat, r"C:\Users\ivanov_ii\notes.txt"), "oldString": fake(chat, "password=Hunter2Hunter2"),
        "newString": fake(chat, "почта Ivan.Petrov@Contoso.RU для CONTOSO\\ivanov"),
    }, ensure_ascii=False)
    out = run(ChatStream(state, settings), [*call_chunks(0, "call_1", "edit", arguments, size=3), chunk({}, "tool_calls")])
    calls = calls_of(out)
    assert calls[0] == {"index": 0, "id": "call_1", "type": "function", "function": {"name": "edit", "arguments": ""}}
    assert len(calls) == 2 and json.loads(calls[1]["function"]["arguments"]) == {
        "filePath": r"C:\Users\ivanov_ii\notes.txt", "oldString": "password=Hunter2Hunter2",
        "newString": "почта Ivan.Petrov@Contoso.RU для CONTOSO\\ivanov",
    }
    assert calls_of(out[-2:-1]) == calls[1:] and out[-1]["choices"][0]["finish_reason"] == "tool_calls"


def test_two_tool_calls_and_usage_after_finish(gw, stub):
    """Два вызова в одном ответе, finish_reason — в части с текстом, usage — отдельной частью после конца."""
    def model(request: dict) -> list[dict]:
        host = HOST.search(json.dumps(request, ensure_ascii=False)).group()
        first = json.dumps({"command": f"ping {host}"})
        second = json.dumps({"filePath": "C:\\b.txt", "note": host})
        text = f"Проверяю {host}"
        return [
            chunk({"role": "assistant", "content": text[:6]}), *call_chunks(0, "call_a", "bash", first, size=4),
            *call_chunks(1, "call_b", "read", second, size=5), chunk({"content": text[6:]}, "tool_calls"),
            usage_chunk(cached=64),
        ]

    stub.script.append(model)
    parts = received(gw.send(opencode({"role": "user", "content": "Проверь srv-dc01.corp.contoso.ru"})))
    assert parts[-1] == "[DONE]" and parts[-2] == usage_chunk(cached=64)
    finish = next(i for i, p in enumerate(parts) if isinstance(p, dict) and p.get("choices") and p["choices"][0]["finish_reason"])
    assert parts[finish]["choices"][0]["finish_reason"] == "tool_calls" and "content" not in parts[finish]["choices"][0]["delta"]
    full = calls_of(parts[finish - 1:finish])
    assert [json.loads(c["function"]["arguments"]) for c in full] == [
        {"command": "ping srv-dc01.corp.contoso.ru"}, {"filePath": "C:\\b.txt", "note": "srv-dc01.corp.contoso.ru"},
    ]
    assert [c["index"] for c in full] == [0, 1]
    heads = [c for c in calls_of(parts[:finish - 1]) if "id" in c]
    assert [(c["id"], c["function"]) for c in heads] == [("call_a", {"name": "bash", "arguments": ""}), ("call_b", {"name": "read", "arguments": ""})]
    assert content_of([p for p in parts if isinstance(p, dict)]) == "Проверяю srv-dc01.corp.contoso.ru"
    assert gw.repo.audit_events("agent_send")[0].details["usage"] == {"input": 100, "output": 9, "cache_read": 64}


def test_done_without_finish_reason_ends_the_stream(gw, stub):
    """Совместимый провайдер кончает поток «data: [DONE]» без finish_reason: это конец ответа, а не обрыв."""
    stub.script.append([chunk({"role": "assistant", "content": "Узел srv-dc01"})])
    parts = received(gw.send(opencode({"role": "user", "content": "Проверь srv-dc01.corp.contoso.ru"})))
    assert parts[-1] == "[DONE]" and not [p for p in parts if isinstance(p, dict) and "error" in p]
    assert gw.repo.audit_events("agent_send")[0].details["finished"] is True


def test_usage_only_chunk_reaches_the_agent(chat):
    """Провайдер шлёт usage частью с пустой дельтой: дельты агенту нет, а usage уходит — частью без choices."""
    state, settings = chat
    last = dict(chunk(), usage=usage_chunk(cached=8)["usage"])
    out = run(ChatStream(state, settings), [chunk({"role": "assistant", "content": "Готово"}), chunk({}, "stop"), last])
    assert out[-1] == dict(last, choices=[])


def test_held_delta_with_null_usage_sends_no_empty_chunk(chat):
    """С include_usage провайдер шлёт «usage: null» в каждой части: удержанная дельта (аргументы вызова) не становится
    частью без choices — наивный клиент читает choices[0] (финальное ревью 5Г, M3)."""
    state, settings = chat
    arguments = json.dumps({"filePath": fake(chat, r"C:\Users\ivanov_ii\notes.txt")}, ensure_ascii=False)
    chunks = [dict(part, usage=None) for part in [*call_chunks(0, "call_1", "read", arguments, size=4), chunk({}, "tool_calls")]]
    out = run(ChatStream(state, settings), chunks)
    assert all(part["choices"] for part in out) and out[-1]["choices"][0]["finish_reason"] == "tool_calls"


def test_tool_calls_without_index_stay_separate(chat):
    """Совместимый провайдер шлёт вызовы без index: часть с новым id — следующий вызов, без id — продолжение последнего."""
    state, settings = chat

    def parts(call_id: str, name: str, arguments: str) -> list[dict]:
        head = {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments[:6]}}
        return [chunk({"tool_calls": [head]}), chunk({"tool_calls": [{"function": {"arguments": arguments[6:]}}]})]

    first = json.dumps({"command": "dir"})
    second = json.dumps({"filePath": fake(chat, r"C:\Users\ivanov_ii\notes.txt")}, ensure_ascii=False)
    chunks = [*parts("call_a", "bash", first), *parts("call_b", "read", second), chunk({}, "tool_calls")]
    out = run(ChatStream(state, settings), chunks)
    heads = [(call["index"], call["id"], call["function"]["name"]) for call in calls_of(out) if "id" in call]
    assert heads == [(0, "call_a", "bash"), (1, "call_b", "read")]
    full = calls_of(out[-2:-1])
    assert [(call["index"], json.loads(call["function"]["arguments"])) for call in full] == [
        (0, {"command": "dir"}), (1, {"filePath": r"C:\Users\ivanov_ii\notes.txt"}),
    ]


def _cut_turn(protocol: str, text: str, error: dict | None = None) -> object:
    """Ответ модели, оборванный посреди текста: у Chat — без «[DONE]», у Responses — без response.completed; error —
    событие ошибки провайдера после текста."""
    if protocol == "chat":
        events = [chunk({"role": "assistant", "content": text[:5]}), chunk({"content": text[5:]})]
        return {"events": events + ([error] if error else []), "cut": True}
    events = responses_tests.text_events(0, responses_tests.message("msg_1", text), [5])[:-3]     # без done
    return events + ([error] if error else [])


def _send_cut(protocol: str, repo, engines, clock, stub, error: dict | None = None) -> list[dict]:
    """Ход агента протоколом protocol, ответ модели с заменой узла — оборванный; части, которые получил агент."""
    def model(request: dict) -> object:
        return _cut_turn(protocol, f"Проверяю {HOST.search(json.dumps(request, ensure_ascii=False)).group()}", error)

    stub.script.append(model)
    task = "Проверь srv-dc01.corp.contoso.ru"
    if protocol == "chat":
        request = {"model": "m-1", "stream": True, "messages": [{"role": "user", "content": task}]}
        raw = Gateway(repo, engines, clock, stub).send(request)
    else:
        message = {"type": "message", "role": "user", "content": [{"type": "input_text", "text": task}]}
        raw = responses_tests.Gateway(repo, engines, clock, stub).send({"model": "m-1", "stream": True, "input": [message]})
    return responses_tests.received(raw)


def _text_of(protocol: str, parts: list[dict]) -> str:
    if protocol == "chat":
        return content_of(parts)
    return "".join(part["delta"] for part in parts if part.get("type") == "response.output_text.delta")


@pytest.mark.parametrize("protocol", ["chat", "responses"])
def test_cut_stream_ends_with_the_restored_text_and_an_error(repo, engines, clock, stub, protocol):
    parts = _send_cut(protocol, repo, engines, clock, stub)
    assert _text_of(protocol, parts[:-1]) == "Проверяю srv-dc01.corp.contoso.ru"
    message = parts[-1]["error"]["message"] if protocol == "chat" else parts[-1]["message"]
    assert message.startswith("Cleaner:") and (protocol == "chat" or parts[-1]["type"] == "error")
    assert repo.audit_events("agent_send")[0].details["finished"] is False


@pytest.mark.parametrize("protocol", ["chat", "responses"])
def test_provider_error_mid_stream_is_passed_as_a_protocol_error(repo, engines, clock, stub, protocol):
    """Ошибка провайдера посреди ответа: агенту — восстановленный остаток текста и ошибка провайдера как есть, своей
    ошибки Cleaner не добавляет."""
    if protocol == "chat":
        error = {"error": {"message": "upstream overloaded", "type": "server_error", "code": None}}
    else:
        error = {"type": "error", "code": "server_error", "message": "upstream overloaded", "param": None}
    parts = _send_cut(protocol, repo, engines, clock, stub, error)
    assert _text_of(protocol, parts[:-1]) == "Проверяю srv-dc01.corp.contoso.ru" and parts[-1] == error
    assert not [part for part in parts[:-1] if "error" in part or part.get("type") == "error"]
    assert repo.audit_events("agent_send")[0].details["finished"] is False


def test_reasoning_content_passes_untouched(chat, gw, stub):
    state, settings = chat
    thought = "думаю про <HOST_7> и host-1.sub-2.domain-3.example"
    out = run(ChatStream(state, settings), [chunk({"role": "assistant", "reasoning_content": thought}), chunk({}, "stop")])
    assert out[0]["choices"][0]["delta"]["reasoning_content"] == thought
    stub.script.append([chunk({"content": "Готово"}), chunk({}, "stop")])
    history = {"role": "assistant", "content": "Смотрю.", "reasoning_content": "рассуждение srv-dc01.corp.contoso.ru"}
    gw.send(opencode({"role": "user", "content": "Привет"}, history, {"role": "user", "content": "Дальше"}))
    assert stub.requests[0]["body"]["messages"][3]["reasoning_content"] == "рассуждение srv-dc01.corp.contoso.ru"


@pytest.mark.parametrize("protocol", ["chat", "responses"])
@pytest.mark.parametrize("policy", [Policy.MASK, Policy.BLOCK])
def test_unsigned_reasoning_uses_known_values_and_dictionary_then_freezes(repo, engines, clock, stub, protocol, policy):
    repo.set_policy(T.TERM, policy)
    entry = repo.add_dictionary("always", "ProjectAster", T.TERM)
    thought = "known@contoso.ru ProjectAster unknown@elsewhere.test"
    if protocol == "chat":
        gateway = Gateway(repo, engines, clock, stub)
        history = {"role": "assistant", "content": "", "reasoning_content": thought}
        request = opencode({"role": "user", "content": "Почта known@contoso.ru"}, history)
        field = "messages"
        reply = [chunk({"content": "Готово"}), chunk({}, "stop")]
        extract = lambda body: body[field][-1]["reasoning_content"]
    else:
        gateway = responses_tests.Gateway(repo, engines, clock, stub)
        task = {"role": "user", "content": "Почта known@contoso.ru"}
        history = {"type": "reasoning", "id": "rs_1", "encrypted_content": "opaque-signed-content",
                   "summary": [{"type": "summary_text", "text": thought}]}
        request = {"model": "m-1", "stream": True, "input": [task, history]}
        field = "input"
        reply = [responses_tests.completed()]
        extract = lambda body: body[field][-1]["summary"][0]["text"]
    stub.script += [reply, reply]
    gateway.send(request)
    first = stub.requests[0]["body"]
    cleaned = extract(first)
    assert "known@contoso.ru" not in cleaned and "ProjectAster" not in cleaned
    if policy is Policy.MASK:
        assert "unknown@elsewhere.test" in cleaned
    else:
        assert cleaned.startswith("[Cleaner: блок не передан")
    if protocol == "responses":
        assert first[field][-1]["encrypted_content"] == history["encrypted_content"]
    repo.delete_dictionary(entry)
    gateway.send(request)
    assert stub.requests[1]["body"][field] == first[field]
    assert repo.audit_events("agent_send")[0].details["blocks_new"] == 0


def test_instruction_goes_before_the_first_user_message():
    body = {"messages": [
        {"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": "a"},
        {"role": "user", "content": "u2"},
    ]}
    out = CHAT.add_instruction(CHAT.rebuild(body, {}), "ИНСТРУКЦИЯ")
    assert [m["role"] for m in out["messages"]] == ["system", "system", "user", "assistant", "user"]
    assert out["messages"][1] == {"role": "system", "content": "ИНСТРУКЦИЯ"}
    assert len(body["messages"]) == 4                       # присланное тело не меняется
    assert CHAT.add_instruction({"messages": [{"role": "system", "content": "s"}]}, "И")["messages"][-1] == {"role": "system", "content": "И"}


def test_media_parts_are_withheld(gw, stub, repo):
    stub.script.append([chunk({"content": "Вижу"}), chunk({}, "stop")])
    image = {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}
    gw.send(opencode({"role": "user", "content": [{"type": "text", "text": "Что на снимке?"}, image]}))
    parts = stub.requests[0]["body"]["messages"][-1]["content"]
    assert parts[0] == {"type": "text", "text": "Что на снимке?"} and parts[1]["type"] == "text"
    assert "Cleaner: блок не передан" in parts[1]["text"] and "base64" not in stub.bodies()
    assert repo.audit_events("agent_withheld")[0].details["reasons"] == {"media": 1}
