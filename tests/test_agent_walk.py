"""Обход тела запроса Anthropic и отпечатки блоков журнала (спецификация 2026-10-28, разделы 7.2, 8, 9.1) — по записям
настоящего Claude Code (tests/fixtures/agents/claude_code, проверки раздела 18)."""
import copy
import json
from pathlib import Path

from cleaner.core.agent import ledger, walk

FIXTURES = Path(__file__).parent / "fixtures" / "agents" / "claude_code"
SECRET = bytes(range(32))


def body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def digest(unit: walk.Unit) -> str:
    return ledger.block_digest(SECRET, "anthropic", unit.role, unit.kind, unit.node)


def by_path(units: list[walk.Unit]) -> dict[tuple, walk.Unit]:
    return {unit.path: unit for unit in units}


def test_claude_code_turn_is_split_into_units():
    units = walk.anthropic_units(body("turn2"))
    assert [(u.role, u.kind) for u in units if u.kind != "tool_def"] == [
        ("system", "opaque"),           # блок атрибуции x-anthropic-billing-header
        ("system", "text"),
        ("system", "text"),
        ("user", "text"),               # напоминание агента
        ("user", "text"),               # «Прочитай notes.txt»
        ("system", "text"),             # окружение — сообщение system внутри messages, строкой
        ("assistant", "opaque"),        # рассуждение с подписью
        ("assistant", "text"),
        ("assistant", "tool_use"),
        ("user", "tool_result"),        # содержимое notes.txt
        ("system", "text"),             # остаток токенов
    ]
    tools = [u for u in units if u.kind == "tool_def"]
    assert len(tools) == 24 and {u.role for u in tools} == {"tools"}
    result = by_path(units)[("messages", 3, "content", 0)]
    assert "srv-dc01.corp.contoso.ru" in json.dumps(result.node, ensure_ascii=False)


def test_moved_cache_control_still_hits_and_is_kept():
    """Claude Code пишет последнее сообщение system блоком с cache_control, а в следующем ходе — строкой без него."""
    first, second = body("turn1"), body("turn2")
    before = by_path(walk.anthropic_units(first))[("messages", 1, "content", 0)]
    after = by_path(walk.anthropic_units(second))[("messages", 1, "content")]
    assert "cache_control" in first["messages"][1]["content"][0] and isinstance(second["messages"][1]["content"], str)
    assert digest(before) == digest(after)
    # cache_control переехал с одного блока system на другой: отпечатки те же, у каждого блока — нынешний.
    moved = copy.deepcopy(first)
    moved["system"][2].pop("cache_control")
    moved["system"][1]["cache_control"] = {"type": "ephemeral", "ttl": "1h"}
    assert [digest(u) for u in walk.anthropic_units(moved)] == [digest(u) for u in walk.anthropic_units(first)]
    replaced = {u.path: dict(u.node, text="ЗАМЕНА") for u in walk.anthropic_units(moved) if u.path[0] == "system"}
    replaced[before.path] = dict(before.node, text="строкой")
    rebuilt = walk.rebuild(moved, replaced)
    assert rebuilt["system"][1] == {"type": "text", "text": "ЗАМЕНА", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
    assert rebuilt["system"][2] == {"type": "text", "text": "ЗАМЕНА"}
    assert rebuilt["messages"][1]["content"] == [{"type": "text", "text": "строкой", "cache_control": {"type": "ephemeral"}}]
    assert walk.rebuild(second, {after.path: dict(after.node, text="строкой")})["messages"][1]["content"] == "строкой"
    assert moved["system"][1]["text"] != "ЗАМЕНА"      # присланное тело не меняется


def test_key_order_does_not_change_the_digest():
    block = {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"a": 1, "b": "два"}}
    reordered = {"input": {"b": "два", "a": 1}, "name": "Read", "id": "toolu_1", "type": "tool_use"}
    assert ledger.canonical(block) == ledger.canonical(reordered)
    assert ledger.block_digest(SECRET, "anthropic", "assistant", "tool_use", block) == ledger.block_digest(
        SECRET, "anthropic", "assistant", "tool_use", reordered
    )
    assert ledger.block_digest(SECRET, "anthropic", "user", "tool_use", block) != ledger.block_digest(
        SECRET, "anthropic", "assistant", "tool_use", block
    )
    assert ledger.block_digest(bytes(32), "anthropic", "assistant", "tool_use", block) != ledger.block_digest(
        SECRET, "anthropic", "assistant", "tool_use", block
    )


def test_conversation_id_is_the_same_after_resume():
    """Проверка 18.1e: после --resume первое сообщение пользователя то же (6.3)."""
    ids = {name: ledger.conversation_id(SECRET, "key-1", walk.first_user(body(name))) for name in ("turn1", "turn2", "resume")}
    assert len(set(ids.values())) == 1
    assert ledger.conversation_id(SECRET, "key-2", walk.first_user(body("turn1"))) != ids["turn1"]
    marked = body("turn1")
    marked["messages"][0]["content"][-1]["cache_control"] = {"type": "ephemeral"}
    assert ledger.conversation_id(SECRET, "key-1", walk.first_user(marked)) == ids["turn1"]
    plain = {"messages": [{"role": "user", "content": "Привет"}]}
    listed = {"messages": [{"role": "user", "content": [{"type": "text", "text": "Привет"}]}]}
    assert walk.first_user(plain) == walk.first_user(listed)


def test_sanitize_unit_touches_only_content_strings():
    units = by_path(walk.anthropic_units({
        "system": "система",
        "tools": [{
            "name": "Read", "description": "читает файл", "cache_control": {"type": "ephemeral"},
            "input_schema": {
                "$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "required": ["path"],
                "properties": {"path": {"type": "string", "format": "uri", "description": "путь к файлу"}},
            },
        }],
        "messages": [
            {"role": "user", "content": "вопрос"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "ping srv", "opts": [{"cwd": "c:/x"}, 3]}},
                {"type": "fancy_new_block", "id": "blk_1", "payload": {"note": "заметка", "type": "kind"}},
            ]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ответ узла"}]},
        ],
    }))
    clean = str.upper
    assert walk.sanitize_unit(units[("system",)], clean) == {"type": "text", "text": "СИСТЕМА"}
    tool_use = walk.sanitize_unit(units[("messages", 1, "content", 0)], clean)
    assert tool_use == {
        "type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "PING SRV", "opts": [{"cwd": "C:/X"}, 3]},
    }
    other = walk.sanitize_unit(units[("messages", 1, "content", 1)], clean)
    assert other == {"type": "fancy_new_block", "id": "blk_1", "payload": {"note": "ЗАМЕТКА", "type": "kind"}}
    assert units[("messages", 1, "content", 1)].kind == "other"
    result = walk.sanitize_unit(units[("messages", 2, "content", 0)], clean)
    assert result == {"type": "tool_result", "tool_use_id": "toolu_1", "content": "ОТВЕТ УЗЛА"}
    tool = walk.sanitize_unit(units[("tools", 0)], clean)
    assert tool["name"] == "Read" and tool["description"] == "ЧИТАЕТ ФАЙЛ" and "cache_control" not in tool
    schema = tool["input_schema"]
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#" and schema["required"] == ["path"]
    assert schema["properties"]["path"] == {"type": "string", "format": "uri", "description": "ПУТЬ К ФАЙЛУ"}


def test_images_inside_tool_results_are_media():
    image = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
    units = walk.anthropic_units({"messages": [
        {"role": "user", "content": [
            image,
            {"type": "document", "source": {"type": "url", "url": "https://example.com/a.pdf"}},
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "снимок"}, image]},
        ]},
    ]})
    assert [u.kind for u in units] == ["media", "media", "tool_result"]
    assert walk.contains_media(units[2]) and not walk.contains_media(walk.anthropic_units({"messages": [
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "текст"}]},
    ]})[0])
    cleaned = walk.sanitize_unit(units[2], str.upper)
    assert cleaned["content"] == [
        {"type": "text", "text": "СНИМОК"}, {"type": "text", "text": ledger.placeholder(ledger.REASONS["media"])},
    ]


def test_structural_strings_list_names_and_metadata():
    strings = walk.structural(body("turn2"))
    assert strings[0] == "capture-model" and "Read" in strings and "Bash" in strings
    assert any("device_id" in s for s in strings)
    assert walk.structural({"model": "m", "tool_choice": {"type": "tool", "name": "Grep"}, "metadata": {"user_id": "u"}}) == [
        "m", "tool", "Grep", "u",
    ]
    units = walk.anthropic_units({"model": "m", "stream": True, "unknown_field": {"note": "заметка"}})
    assert [(u.path, u.role, u.kind) for u in units] == [(("unknown_field",), "params", "other")]
