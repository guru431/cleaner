"""Протокол OpenAI Chat Completions в шлюзе (спецификация 2026-10-28, разделы 9.2, 10.1–10.2): обход тела запроса
(OpenCode с @ai-sdk/openai-compatible, проекты с SDK OpenAI) и восстановление частей потока.

Аргументы вызова в истории — строка JSON, которую AI SDK пишет заново (проверка 18.1c 5В): блок ищется в журнале по
разобранному объекту, а к провайдеру уходит записанный вид. Текст отдаётся по мере прихода; аргументы вызовов копятся по
index и уходят одной частью перед частью с finish_reason, восстановленные точно (10.3)."""
from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass, field

from cleaner.core.agent import ledger
from cleaner.core.agent.stream import DeltaRestorer, map_strings, usage_numbers
from cleaner.core.agent.walk import (
    OTHER_KEYS, SCHEMA_KEYS, Unit, bare, parsed_arguments, strings, strings_of, text_block,
)
from cleaner.core.restore import originals
from cleaner.core.types import ChatState, Settings

MEDIA = frozenset({"image_url", "input_audio", "file"})
# Параметры запроса — служебные строки (8.3); поле не из этого списка и не messages, tools — незнакомое: очищается.
PARAMS = frozenset({
    "model", "stream", "stream_options", "temperature", "top_p", "max_tokens", "max_completion_tokens", "tool_choice",
    "parallel_tool_calls", "response_format", "reasoning_effort", "metadata", "user", "seed", "stop", "n",
})
_MESSAGE_KEYS = frozenset({"role", "content", "tool_calls", "tool_call_id", "reasoning_content"})
_USAGE = {
    "prompt_tokens": "input", "completion_tokens": "output", "prompt_tokens_details.cached_tokens": "cache_read",
    "prompt_cache_hit_tokens": "cache_read",            # DeepSeek
}


def _media(part: object) -> bool:
    return isinstance(part, dict) and part.get("type") in MEDIA


def _part_kind(part: object) -> str:
    if _media(part):
        return "media"
    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
        return "text"
    return "other"


def _call_node(call: object) -> object:
    if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
        return call
    return dict(call, function=dict(call["function"], arguments=parsed_arguments(call["function"].get("arguments"))))


def chat_units(body: dict) -> list[Unit]:
    units: list[Unit] = []
    for i, message in enumerate(body.get("messages") or ()):
        if not isinstance(message, dict):
            units.append(Unit(("messages", i), "user", "other", message))
            continue
        role = str(message.get("role", ""))
        if role == "tool":
            units.append(Unit(("messages", i), "tool", "tool_result", message))       # результат — сообщение целиком
            continue
        content = message.get("content")
        if isinstance(content, str):
            units.append(Unit(("messages", i, "content"), role, "text", text_block(content)))
        elif isinstance(content, list):
            units += [Unit(("messages", i, "content", j), role, _part_kind(part), bare(part)) for j, part in enumerate(content)]
        elif content is not None:
            units.append(Unit(("messages", i, "content"), role, "other", content))
        units += [
            Unit(("messages", i, "tool_calls", j), role, "tool_use", _call_node(call))
            for j, call in enumerate(message.get("tool_calls") or ())
        ]
        if "reasoning_content" in message:           # рассуждения DeepSeek и подобных — как пришли (7.2.3)
            units.append(Unit(("messages", i, "reasoning_content"), role, "opaque", message["reasoning_content"]))
        units += [Unit(("messages", i, key), role, "other", value) for key, value in message.items() if key not in _MESSAGE_KEYS]
    units += [Unit(("tools", j), "tools", "tool_def", tool) for j, tool in enumerate(body.get("tools") or ())]
    units += [
        Unit((key,), "params", "other", value) for key, value in body.items()
        if key not in PARAMS and key not in ("messages", "tools")
    ]
    return units


def _name(node: object) -> str | None:
    function = node.get("function") if isinstance(node, dict) else None
    name = function.get("name") if isinstance(function, dict) else None
    return name if isinstance(name, str) else None


def structural(body: dict) -> list[str]:
    """Служебные строки: модель, имена инструментов (в описаниях и в вызовах истории), параметры запроса."""
    out = [name for tool in body.get("tools") or () if (name := _name(tool))]
    for message in body.get("messages") or ():
        calls = message.get("tool_calls") if isinstance(message, dict) else None
        out += [name for call in calls or () if (name := _name(call))]
    for key, value in body.items():
        if key in PARAMS:
            out += strings_of(value)
    return out


def _result_part(part: object, clean: Callable[[str], str]) -> object:
    if _media(part):
        return text_block(ledger.placeholder(ledger.REASONS["media"]))
    if _part_kind(part) == "text":
        return dict(part, text=clean(part["text"]))
    return strings(part, clean, OTHER_KEYS)


def _tool_def(node: dict, clean: Callable[[str], str]) -> dict:
    """Описание инструмента: имя, вид и strict — служебные; схема parameters — без служебных ключей схемы."""
    out = {}
    for key, value in node.items():
        if key in ("type", "name", "strict"):
            out[key] = value
        elif key == "function" and isinstance(value, dict):
            out[key] = _tool_def(value, clean)
        else:
            out[key] = strings(value, clean, SCHEMA_KEYS if key == "parameters" else OTHER_KEYS)
    return out


def sanitize_unit(unit: Unit, clean: Callable[[str], str]) -> object:
    """Новый узел с очищенным текстом в виде запроса: аргументы вызова — снова строкой JSON."""
    node = unit.node
    if unit.kind == "text":
        return dict(node, text=clean(node["text"]))
    if unit.kind == "tool_result":
        content = node.get("content")
        if isinstance(content, str):
            return dict(node, content=clean(content))
        if isinstance(content, list):
            return dict(node, content=[_result_part(part, clean) for part in content])
        return dict(node)
    if unit.kind == "tool_use" and isinstance(node, dict) and isinstance(node.get("function"), dict):
        arguments = node["function"].get("arguments")
        if isinstance(arguments, str):
            arguments = clean(arguments)
        elif arguments is not None:
            arguments = json.dumps(strings(arguments, clean, frozenset()), ensure_ascii=False)
        return dict(node, function=dict(node["function"], arguments=arguments))
    if unit.kind == "tool_def" and isinstance(node, dict):
        return _tool_def(node, clean)
    if unit.kind in ("other", "tool_use"):
        return strings(node, clean, OTHER_KEYS)
    return copy.deepcopy(node)          # непрозрачный и удерживаемый — как есть


def contains_media(unit: Unit) -> bool:
    if unit.kind == "media":
        return True
    content = unit.node.get("content") if unit.kind == "tool_result" and isinstance(unit.node, dict) else None
    return isinstance(content, list) and any(_media(part) for part in content)


def placeholder(unit: Unit, reason: str) -> object:
    """Пометка удержанного блока того же вида (7.4): у результата инструмента — его содержимым."""
    text = ledger.placeholder(reason)
    node = unit.node if isinstance(unit.node, dict) else {}
    if unit.kind == "tool_result":
        return dict(node, content=text)
    if unit.kind == "tool_use" and isinstance(node.get("function"), dict):
        return dict(node, function=dict(node["function"], arguments=json.dumps({"cleaner": text}, ensure_ascii=False)))
    if unit.kind == "tool_def" and isinstance(node.get("function"), dict):
        return dict(node, function=dict(node["function"], description=text, parameters={"type": "object"}))
    return text_block(text)


def model_kind(node: dict) -> str:
    return "tool_use" if "function" in node else "text"


def add_instruction(body: dict, text: str) -> dict:
    """Служебная инструкция — сообщением system перед первым сообщением пользователя (8.8); нет его — в конце."""
    messages = list(body.get("messages") or ())
    at = next((i for i, m in enumerate(messages) if isinstance(m, dict) and m.get("role") == "user"), len(messages))
    messages.insert(at, {"role": "system", "content": text})
    body["messages"] = messages
    return body


def sse(event: dict) -> bytes:
    return f"data: {json.dumps(event, ensure_ascii=False, separators=(',', ':'))}\n\n".encode("utf-8")


def error_event(message: str) -> dict:
    return {"error": {"message": message, "type": "server_error", "code": None}}


def usage(event: dict) -> dict[str, int]:
    return usage_numbers(event.get("usage"), _USAGE)


@dataclass
class _Call:
    head: dict                                          # первая часть: index, id, type, function.name
    parts: list[str] = field(default_factory=list)      # части arguments


@dataclass
class _Choice:
    restorer: DeltaRestorer
    parts: list[str] = field(default_factory=list)      # текст модели
    shown: list[str] = field(default_factory=list)      # отданный агенту текст
    calls: dict[int, _Call] = field(default_factory=dict)
    last: int = 0                                       # номер последнего вызова — для частей без index


class ChatStream:
    """Части потока для агента. pairs — для каждого текста и вызова пара «как агент пришлёт в истории — как прислала
    модель» (журнал out, 7.2): аргументы у первого — разобранным объектом, у второго — строкой модели."""

    def __init__(self, state: ChatState, settings: Settings):
        self.state = state
        self.settings = settings
        self.choices: dict[int, _Choice] = {}
        self.pairs: list[tuple[dict, dict]] = []
        self._head: dict = {}
        self._text: Callable[[str], str] | None = None
        self._exact: Callable[[str], str] | None = None

    def _restore_text(self, text: str) -> str:
        if self._text is None:
            self._text = originals(self.state, self.settings)
        return self._text(text)

    def _restore_arguments(self, value: object) -> object:
        if self._exact is None:
            self._exact = originals(self.state, self.settings, exact=True)
        return map_strings(value, self._exact)

    @staticmethod
    def finished(event: dict) -> bool:
        return any(isinstance(choice, dict) and choice.get("finish_reason") for choice in event.get("choices") or ())

    def _slot(self, index: int) -> _Choice:
        if index not in self.choices:
            self.choices[index] = _Choice(DeltaRestorer(self.state, self.settings, self._restore_text))
        return self.choices[index]

    def _part(self, index: int, delta: dict) -> dict:
        return {**self._head, "choices": [{"index": index, "delta": delta, "finish_reason": None}]}

    @staticmethod
    def _index(slot: _Choice, part: dict) -> int:
        """Номер вызова. Совместимые провайдеры шлют части без index: часть с новым id — следующий вызов, без id —
        продолжение последнего."""
        if "index" in part:
            return part["index"]
        call_id = part.get("id")
        if call_id is None:
            return slot.last
        known = next((index for index, call in slot.calls.items() if call.head.get("id") == call_id), None)
        return known if known is not None else max(slot.calls, default=-1) + 1

    @classmethod
    def _heads(cls, slot: _Choice, parts: object) -> list[dict]:
        """Части вызовов: первая часть каждого уходит сразу с пустыми аргументами, аргументы копятся."""
        heads = []
        for part in parts if isinstance(parts, list) else ():
            if not isinstance(part, dict):
                continue
            function = part.get("function") if isinstance(part.get("function"), dict) else {}
            index = slot.last = cls._index(slot, part)
            if index not in slot.calls:
                slot.calls[index] = _Call(dict(part, index=index, function=dict(function, arguments="")))
                heads.append(slot.calls[index].head)
            arguments = function.get("arguments")
            slot.calls[index].parts.append(arguments if isinstance(arguments, str) else "")
        return heads

    def _close(self, slot: _Choice) -> list[dict]:
        """Конец ответа: аргументы каждого вызова целиком, восстановленные точно; пары — в pairs."""
        out = []
        for index in sorted(slot.calls):
            call = slot.calls[index]
            raw = "".join(call.parts) or "{}"
            try:
                arguments = json.loads(raw)
            except ValueError:
                out.append({"index": index, "function": {"arguments": raw}})       # незаконченный JSON — как пришёл
                continue
            restored = self._restore_arguments(arguments)
            out.append({"index": index, "function": {"arguments": json.dumps(restored, ensure_ascii=False)}})
            head = {"id": call.head.get("id"), "type": call.head.get("type", "function")}
            name = (call.head.get("function") or {}).get("name")
            self.pairs.append((
                {**head, "function": {"name": name, "arguments": restored}}, {**head, "function": {"name": name, "arguments": raw}},
            ))
        slot.calls.clear()
        if slot.parts:
            self.pairs.append(({"type": "text", "text": "".join(slot.shown)}, {"type": "text", "text": "".join(slot.parts)}))
            slot.parts, slot.shown = [], []
        return out

    def feed(self, event: dict) -> list[dict]:
        if "error" in event:
            return self.cut() + [event]
        choices = event.get("choices")
        if not isinstance(choices, list) or not choices:
            return [event]                      # usage после конца и прочее — как пришло
        self._head = {key: value for key, value in event.items() if key not in ("choices", "usage")}
        before: list[dict] = []
        kept = []
        for choice in choices:
            if not isinstance(choice, dict):
                kept.append(choice)
                continue
            index = choice.get("index", 0)
            slot = self._slot(index)
            delta = dict(choice.get("delta") or {})
            text = delta.pop("content", None)
            heads = self._heads(slot, delta.pop("tool_calls", None))
            shown = ""
            if isinstance(text, str) and text:
                slot.parts.append(text)
                shown = slot.restorer.feed(text)
            if choice.get("finish_reason"):
                # Перед частью с finish_reason: новые вызовы, остаток текста, аргументы всех вызовов одной частью.
                if heads:
                    before.append(self._part(index, {"tool_calls": heads}))
                shown += slot.restorer.finish()
                if shown:
                    slot.shown.append(shown)
                    before.append(self._part(index, {"content": shown}))
                calls = self._close(slot)
                if calls:
                    before.append(self._part(index, {"tool_calls": calls}))
                kept.append(dict(choice, delta=delta))
                continue
            if shown:
                slot.shown.append(shown)
                delta["content"] = shown
            if heads:
                delta["tool_calls"] = heads
            if delta:
                kept.append(dict(choice, delta=delta))
        if kept:
            return before + [dict(event, choices=kept)]
        # Отдавать из choices нечего, но поля сверх шапки есть (usage с пустой дельтой) — часть уходит без choices.
        # «usage: null» (include_usage, в каждой части) — не usage: иначе каждая удержанная дельта дала бы пустую часть.
        return before + ([dict(event, choices=[])] if event.get("usage") else [])

    def cut(self) -> list[dict]:
        """Поток оборвался: несколько знаков текста и незаконченные аргументы — как пришли; пар у них нет."""
        out = []
        for index, slot in self.choices.items():
            rest = slot.restorer.finish()
            if rest:
                out.append(self._part(index, {"content": rest}))
            calls = [
                {"index": k, "function": {"arguments": "".join(call.parts)}} for k, call in sorted(slot.calls.items())
                if "".join(call.parts)
            ]
            if calls:
                out.append(self._part(index, {"tool_calls": calls}))
        self.choices.clear()
        return out

    def complete(self, body: dict) -> dict:
        """Ответ без потока: тот же текст, что дала бы склейка частей, и те же аргументы."""
        choices = []
        for choice in body.get("choices") or ():
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict):
                choices.append(choice)
                continue
            message = dict(message)
            text = message.get("content")
            if isinstance(text, str):
                message["content"] = self._restore_text(text)
                self.pairs.append(({"type": "text", "text": message["content"]}, {"type": "text", "text": text}))
            if isinstance(message.get("tool_calls"), list):
                slot = _Choice(DeltaRestorer(self.state, self.settings, self._restore_text))
                for index, call in enumerate(message["tool_calls"]):
                    function = call.get("function") if isinstance(call, dict) else None
                    if isinstance(function, dict):
                        slot.calls[index] = _Call(dict(call, function=dict(function, arguments="")), [function.get("arguments") or ""])
                restored = {part["index"]: part["function"]["arguments"] for part in self._close(slot)}
                message["tool_calls"] = [
                    dict(call, function=dict(call["function"], arguments=restored[index])) if index in restored else call
                    for index, call in enumerate(message["tool_calls"])
                ]
            choices.append(dict(choice, message=message))
        return dict(body, choices=choices)
