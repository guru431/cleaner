"""Нагрузка для замеров шлюза агентов (спецификация 2026-10-28, раздел 13): длинные журналы из вымышленных значений,
тела Claude Code и Codex размером от 1 МиБ, чат с заданным числом сущностей. Только стандартная библиотека и cleaner:
модуль импортирует и сценарий памяти scripts/checks/gateway_memory.py на сервере, где pytest нет."""
from __future__ import annotations

import json
from pathlib import Path

from cleaner.core import pipeline
from cleaner.core.types import ChatState, Settings
from tests.agent_bodies import assistant, body, tool_result

CODEX = Path(__file__).parent / "fixtures" / "agents" / "codex" / "turn1.json"
RESULT_LINES = 2_000            # строк журнала в одном выводе инструмента тела
FILL_START = 100_000            # строки fill_state — не те, что в телах: сущности новые
_FILL_PORTION = 500


def fictional_lines(count: int, start: int = 0) -> str:
    """Строки журнала: в строке n — узел, почта, частный адрес и учётная запись с номером n."""
    return "".join(
        f"{n:05d} вход CONTOSO\\u{n:05d} с узла srv-app{n:05d}.corp.contoso.ru "
        f"(10.{n // 256 % 256}.{n % 256}.{n * 7 % 250 + 2}), отчёт на user{n:05d}@contoso.ru\n"
        for n in range(start, start + count)
    )


def size_of(request: dict) -> int:
    return len(json.dumps(request, ensure_ascii=False).encode("utf-8"))


def _codex(task: str) -> dict:
    """Тело первого хода Codex из записи, как класс Codex в tests/test_acceptance_stage5v.py: каталог репозитория записи
    «contoso-repo» совпал бы с контрольным значением, модель — модель подключения заглушки."""
    out = json.loads(CODEX.read_text(encoding="utf-8").replace("contoso-repo", "demo-repo"))
    out["model"] = "m-1"
    out["input"][3]["content"][0]["text"] = task
    return out


def _pair(number: int, text: str) -> tuple[dict, dict]:
    call = {"type": "tool_use", "id": f"toolu_{number:04d}", "name": "Bash", "input": {"command": f"cat /var/log/app/{number}.log"}}
    return assistant(call), tool_result(call["id"], text)


def add_result(protocol: str, request: dict, number: int, text: str) -> dict:
    """Тело следующего хода: прежнее плюс вызов команды number и её вывод text."""
    out = dict(request)
    if protocol == "anthropic":
        # Последнее сообщение хода Claude Code — остаток токенов (tests/agent_bodies.py): новая пара — перед ним.
        out["messages"] = [*request["messages"][:-1], *_pair(number, text), request["messages"][-1]]
    elif protocol == "responses":
        out["input"] = [*request["input"],
                        {"type": "function_call", "id": f"fc_{number:04d}", "call_id": f"call_{number:04d}",
                         "name": "exec_command", "arguments": json.dumps({"cmd": f"cat /var/log/app/{number}.log"})},
                        {"type": "function_call_output", "call_id": f"call_{number:04d}", "output": text}]
    else:
        raise ValueError(protocol)
    return out


def long_body(protocol: str, size: int, task: str) -> dict:
    """Тело не меньше size байт в JSON: пары «вызов команды — вывод» по RESULT_LINES строк fictional_lines (одни и те же
    строки: сущностей в теле — 4 × RESULT_LINES, чат дополняет fill_state)."""
    lines = fictional_lines(RESULT_LINES)
    if protocol == "anthropic":
        request, number = body(task, *_pair(1, lines)), 1
    elif protocol == "responses":
        request, number = _codex(task), 0
    else:
        raise ValueError(protocol)
    while size_of(request) < size:
        number += 1
        request = add_result(protocol, request, number, lines)
    return request


def fill_state(state: ChatState, settings: Settings, entities: int) -> None:
    """Состояние чата дополняется сущностями строк fictional_lines (с FILL_START), пока их не станет не меньше entities."""
    start = FILL_START
    while len(state.entities) < entities:
        pipeline.sanitize(state, fictional_lines(_FILL_PORTION, start), settings)
        start += _FILL_PORTION
