"""Тела запросов Claude Code и ответы модели для тестов шлюза (план 5Б): основа — записи настоящего агента
(tests/fixtures/agents/claude_code), задача и история — свои, с вымышленными контрольными значениями."""
from __future__ import annotations

import copy
import json
from collections.abc import Iterable
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "agents" / "claude_code"
TOOLS = ("Read", "Edit", "Bash")        # описаний инструментов — три из 24: очистка первого хода дешевле
# Каталог вымышленного репозитория записи назван «contoso-repo» — с контрольным значением CONTOSO он совпал бы при проверке.
_BASE = json.loads((FIXTURES / "turn1.json").read_text(encoding="utf-8").replace("contoso-repo", "demo-repo"))


def body(first: str, *history: dict, tools: Iterable[str] = TOOLS, model: str = "m-1") -> dict:
    """Тело хода Claude Code: первое сообщение пользователя — его напоминание и first; без истории — первый ход (окружение —
    блоком с cache_control), с историей — как следующие ходы: окружение строкой, в конце — остаток токенов с cache_control
    (проверка 18.1d)."""
    out = copy.deepcopy(_BASE)
    out["model"] = model
    wanted = set(tools)
    out["tools"] = [tool for tool in out["tools"] if tool["name"] in wanted]
    user = out["messages"][0]
    user["content"][-1]["text"] = first
    if not history:
        return out
    environment = out["messages"][1]["content"][0]["text"]
    tokens = {"type": "text", "text": "<total_tokens>14999970 tokens left</total_tokens>", "cache_control": {"type": "ephemeral"}}
    out["messages"] = [user, {"role": "system", "content": environment}, *history, {"role": "system", "content": [tokens]}]
    return out


def assistant(*blocks: dict) -> dict:
    return {"role": "assistant", "content": list(blocks)}


def tool_result(tool_use_id: str, content: object) -> dict:
    return {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tool_use_id, "content": content}]}


def model_turn(text: str, tool: tuple[str, str, dict] | None = None, thinking: str = "", cut: bool = False) -> list[dict]:
    """События ответа модели: рассуждение, текст, вызов инструмента (id, имя, аргументы — одной дельтой); cut — поток
    обрывается посреди аргументов вызова."""
    events: list[dict] = [{"type": "message_start", "message": {
        "id": "msg_stub", "type": "message", "role": "assistant", "model": "m-1", "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}]
    index = 0
    if thinking:
        events += [
            {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": thinking}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "c2lnLXN0dWI="}},
            {"type": "content_block_stop", "index": 0},
        ]
        index = 1
    words = text.split(" ")
    events += [
        {"type": "content_block_start", "index": index, "content_block": {"type": "text", "text": ""}},
        *({"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": part}}
          for part in [word + " " for word in words[:-1]] + words[-1:]),       # по слову: метка режется дельтами
        {"type": "content_block_stop", "index": index},
    ]
    if tool is not None:
        tool_id, name, arguments = tool
        raw = json.dumps(arguments, ensure_ascii=False)
        events += [
            {"type": "content_block_start", "index": index + 1,
             "content_block": {"type": "tool_use", "id": tool_id, "name": name, "input": {}}},
            {"type": "ping"},
            {"type": "content_block_delta", "index": index + 1,
             "delta": {"type": "input_json_delta", "partial_json": raw[: len(raw) // 2] if cut else raw}},
        ]
        if cut:
            return events
        events.append({"type": "content_block_stop", "index": index + 1})
    return events + [
        {"type": "message_delta", "delta": {"stop_reason": "tool_use" if tool else "end_turn", "stop_sequence": None},
         "usage": {"output_tokens": 20}},
        {"type": "message_stop"},
    ]


def events_of(raw: bytes) -> list[dict]:
    """События потока, который получил агент."""
    return [json.loads(line[5:]) for line in raw.decode("utf-8").splitlines() if line.startswith("data:")]


def agent_blocks(raw: bytes) -> list[dict]:
    """Блоки ответа так, как их соберёт агент из потока и пришлёт в истории следующего хода."""
    blocks: dict[int, dict] = {}
    partial: dict[int, str] = {}
    for event in events_of(raw):
        index = event.get("index")
        if event["type"] == "content_block_start":
            blocks[index] = dict(event["content_block"])
        elif event["type"] == "content_block_delta":
            delta = event["delta"]
            if delta["type"] == "text_delta":
                blocks[index]["text"] += delta["text"]
            elif delta["type"] == "input_json_delta":
                partial[index] = partial.get(index, "") + delta["partial_json"]
            elif delta["type"] == "thinking_delta":
                blocks[index]["thinking"] += delta["thinking"]
            elif delta["type"] == "signature_delta":
                blocks[index]["signature"] = delta["signature"]
        elif event["type"] == "content_block_stop" and index in partial:
            blocks[index]["input"] = json.loads(partial.pop(index))
    return [blocks[index] for index in sorted(blocks)]
