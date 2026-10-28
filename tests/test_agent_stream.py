"""Восстановление потока Anthropic для агента (спецификация 2026-10-28, раздел 10): текст — по мере прихода, аргументы
вызова инструмента — целиком в конце блока и точно."""
import json
from pathlib import Path

import pytest

from cleaner.core.agent import ledger
from cleaner.core.agent.stream import AnthropicStream, DeltaRestorer
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import originals
from cleaner.core.types import ChatState, Settings

FIXTURES = Path(__file__).parent / "fixtures" / "agents" / "claude_code"
TEXT = (
    "Почта Ivan.Petrov@Contoso.RU, узел srv-dc01.corp.contoso.ru (10.1.2.5), "
    r"профиль C:\Users\ivanov_ii\notes.txt, password=Hunter2Hunter2"
)
# Знаки, из которых состоят записи замен (restore._TOKEN_CHAR): ими дельта текста не кончается — иначе замена разрезана.
TOKEN = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:/<>[]&;\\-")


@pytest.fixture
def chat() -> tuple[ChatState, Settings]:
    state = ChatState(chat_id="agent", net_key=bytes(range(32)))
    state.written = True
    settings = Settings()       # SECRET — «скрывать без восстановления»
    sanitize(state, TEXT, settings)
    return state, settings


def fake(chat, text: str) -> str:
    """Запись text с заменами чата — как её пишет модель."""
    state, settings = chat
    return sanitize(state, text, settings).sanitized


def message_start() -> dict:
    return {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "content": [],
                                                 "model": "m", "stop_reason": None, "usage": {"input_tokens": 1}}}


def text_events(parts: list[str], index: int = 0) -> list[dict]:
    return [
        {"type": "content_block_start", "index": index, "content_block": {"type": "text", "text": ""}},
        *({"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": part}} for part in parts),
        {"type": "content_block_stop", "index": index},
    ]


def tool_events(name: str, arguments: str, index: int, size: int = 1, ping_every: int = 0) -> list[dict]:
    events = [{"type": "content_block_start", "index": index,
               "content_block": {"type": "tool_use", "id": f"toolu_{index}", "name": name, "input": {}}}]
    for n, start in enumerate(range(0, len(arguments), size)):
        events.append({"type": "content_block_delta", "index": index,
                       "delta": {"type": "input_json_delta", "partial_json": arguments[start:start + size]}})
        if ping_every and n % ping_every == 0:
            events.append({"type": "ping"})
    events.append({"type": "content_block_stop", "index": index})
    return events


def run(stream: AnthropicStream, events: list[dict]) -> list[dict]:
    return [out for event in events for out in stream.feed(event)]


def texts(events: list[dict]) -> list[str]:
    return [e["delta"]["text"] for e in events if e.get("delta", {}).get("type") == "text_delta"]


def test_label_cut_at_every_position_restores_like_the_whole_text(chat):
    state, settings = chat
    # Искажённые записи меток с пробелами внутри (FR-7.3) — единственные замены, которые пробел не обрывает.
    answer = (
        fake(chat, TEXT) + " — готово, и < EMAIL_1 > и EMAIL _ 1 тоже, <SECRET_1 >.\nИтог: "
        + fake(chat, "srv-dc01.corp.contoso.ru")
    )
    whole = originals(state, settings)(answer)
    assert "srv-dc01.corp.contoso.ru" in whole and "<SECRET_1>" in whole
    assert whole.count("Ivan.Petrov@Contoso.RU") == 3 and "<SECRET_1 >" not in whole
    for cut in range(len(answer) + 1):
        parts = texts(run(AnthropicStream(state, settings), [message_start(), *text_events([answer[:cut], answer[cut:]])]))
        assert "".join(parts) == whole, cut
        assert all(part[-1] not in TOKEN for part in parts[:-1]), (cut, parts)


def test_delta_restorer_gives_only_the_increment(chat):
    state, settings = chat
    restorer = DeltaRestorer(state, settings)
    first = restorer.feed(fake(chat, "узел srv-dc01.corp.contoso.ru "))
    assert first == "узел srv-dc01.corp.contoso.ru "
    assert restorer.feed("и ") == "и "
    assert restorer.feed(fake(chat, "Ivan.Petrov@Contoso.RU")) == ""      # хвост без пробела ждёт
    assert restorer.finish() == "Ivan.Petrov@Contoso.RU"


def test_tool_input_is_sent_once_restored_exactly(chat):
    state, settings = chat
    arguments = json.dumps({
        "file_path": fake(chat, r"C:\Users\ivanov_ii\notes.txt"),
        "old_string": fake(chat, "password=Hunter2Hunter2"),
        "new_string": fake(chat, "почта Ivan.Petrov@Contoso.RU на srv-dc01.corp.contoso.ru"),
        "nested": [{"to": fake(chat, "10.1.2.5")}, 7],
    }, ensure_ascii=False)
    out = run(AnthropicStream(state, settings), [message_start(), *tool_events("Edit", arguments, 0)])
    assert [e["type"] for e in out] == ["message_start", "content_block_start", "content_block_delta", "content_block_stop"]
    assert out[1]["content_block"]["input"] == {}
    assert json.loads(out[2]["delta"]["partial_json"]) == {
        "file_path": r"C:\Users\ivanov_ii\notes.txt",
        "old_string": "password=Hunter2Hunter2",
        "new_string": "почта Ivan.Petrov@Contoso.RU на srv-dc01.corp.contoso.ru",
        "nested": [{"to": "10.1.2.5"}, 7],
    }


def test_secret_stays_a_label_in_text_but_is_restored_in_tool_input(chat):
    state, settings = chat
    secret = fake(chat, "password=Hunter2Hunter2")
    out = run(AnthropicStream(state, settings), [
        message_start(), *text_events([f"Пароль: {secret} "]),
        *tool_events("Bash", json.dumps({"command": f"echo {secret}"}), 1, size=7),
    ])
    assert "".join(texts(out)) == "Пароль: password=<SECRET_1> "
    [arguments] = [e["delta"]["partial_json"] for e in out if e.get("delta", {}).get("type") == "input_json_delta"]
    assert json.loads(arguments) == {"command": "echo password=Hunter2Hunter2"}


def test_thinking_and_pings_pass_untouched_and_immediately(chat):
    state, settings = chat
    stream = AnthropicStream(state, settings)
    thinking = [
        {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": fake(chat, "Узел 10.1.2.5")}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "c2ln"}},
        {"type": "content_block_stop", "index": 0},
    ]
    for event in [message_start(), *thinking]:
        assert stream.feed(event) == [event]
    seen = []
    for event in tool_events("Read", json.dumps({"file_path": "a.txt"}), 1, size=3, ping_every=2):
        out = stream.feed(event)
        if event["type"] == "ping":
            assert out == [event]
        seen += [e["type"] for e in out]
    assert seen[0] == "content_block_start" and seen[-2:] == ["content_block_delta", "content_block_stop"]
    assert seen.count("ping") >= 2 and seen.index("content_block_delta") > seen.index("ping")
    for event in ({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}, {"type": "message_stop"},
                  {"type": "brand_new_event", "x": 1}):
        assert stream.feed(event) == [event]


def test_pairs_describe_what_the_agent_will_send_back(chat):
    """Пара «как агент пришлёт блок в истории — как его прислала модель»; вид первого — как в записи Claude Code."""
    state, settings = chat
    recorded = json.loads((FIXTURES / "turn2.json").read_text(encoding="utf-8"))["messages"][2]["content"]
    path = recorded[2]["input"]["file_path"]
    stream = AnthropicStream(state, settings)
    run(stream, [message_start(), *text_events(["Читаю ", "файл."], 1),
                 *tool_events("Read", json.dumps({"file_path": path}), 2, size=5)])
    [(text_local, text_wire), (tool_local, tool_wire)] = stream.pairs
    assert ledger.canonical(text_local) == ledger.canonical(recorded[1])
    assert ledger.canonical(dict(tool_local, id=recorded[2]["id"])) == ledger.canonical(recorded[2])
    assert text_wire == text_local and tool_wire == tool_local      # замен нет — стороны совпадают
    masked = fake(chat, "srv-dc01.corp.contoso.ru")
    stream = AnthropicStream(state, settings)
    run(stream, [message_start(), *text_events([f"Узел {masked}"]), *tool_events("Bash", json.dumps({"c": masked}), 1)])
    [(text_local, text_wire), (tool_local, tool_wire)] = stream.pairs
    assert text_local == {"type": "text", "text": "Узел srv-dc01.corp.contoso.ru"}
    assert text_wire == {"type": "text", "text": f"Узел {masked}"}
    assert tool_local == {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"c": "srv-dc01.corp.contoso.ru"}}
    assert tool_wire == {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"c": masked}}


def test_cut_stream_leaves_incomplete_tool_input_as_is(chat):
    state, settings = chat
    stream = AnthropicStream(state, settings)
    partial = '{"file_path": "' + fake(chat, r"C:\Users\ivanov_ii")
    events = tool_events("Read", partial, 0, size=4)[:-1]       # без content_block_stop
    assert [e["type"] for e in run(stream, [message_start(), *text_events(["Сейчас "]), *events])] == [
        "message_start", "content_block_start", "content_block_delta", "content_block_stop", "content_block_start",
    ]
    rest = stream.cut()
    assert rest == [{"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": partial}}]
    assert [local["type"] for local, _ in stream.pairs] == ["text"]
    error = {"type": "error", "error": {"type": "overloaded_error", "message": "x"}}
    stream = AnthropicStream(state, settings)
    run(stream, [message_start(), *text_events(["Начало "])[:2]])
    assert stream.feed({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "хвост"}}) == []
    assert stream.feed(error) == [
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "хвост"}}, error,
    ]
    assert stream.pairs == []


def test_complete_message_restores_text_and_tool_input(chat):
    state, settings = chat
    masked = fake(chat, "srv-dc01.corp.contoso.ru")
    secret = fake(chat, "password=Hunter2Hunter2")
    stream = AnthropicStream(state, settings)
    message = {"id": "msg_1", "type": "message", "role": "assistant", "model": "m", "content": [
        {"type": "thinking", "thinking": f"узел {masked}", "signature": "c2ln"},
        {"type": "text", "text": f"Узел {masked}, {secret}"},
        {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": f"ssh {masked} {secret}"}},
    ], "stop_reason": "tool_use"}
    out = stream.complete(message)
    assert out["content"][0] == message["content"][0]
    assert out["content"][1]["text"] == "Узел srv-dc01.corp.contoso.ru, password=<SECRET_1>"
    assert out["content"][2]["input"] == {"command": "ssh srv-dc01.corp.contoso.ru password=Hunter2Hunter2"}
    assert [wire for _, wire in stream.pairs] == message["content"][1:]
