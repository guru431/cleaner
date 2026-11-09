"""Протокол OpenAI Responses в шлюзе (спецификация 2026-10-28, разделы 9.3, 10.1–10.2): обход тела запроса Codex и
восстановление событий потока.

Codex повторяет историю дословно и после возобновления (проверка 18.1b 5В), но элементы модели записывает заново по-
своему: вызовы ищутся в журнале по узлу без id и status, а эти поля при сборке берутся из элемента, который прислал
агент. Инструменты бывают и элементом input вида additional_tools
(«code mode» моделей gpt-6.x). Текст отдаётся по мере прихода; итоговые объекты (…done, output_item.done,
response.completed) получают тот же восстановленный текст, что склейка дельт: Codex кладёт в историю output_item.done.
Аргументы вызовов и патч копятся и уходят восстановленными точно (10.3); патчу — одна дельта перед done."""
from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass, field

from cleaner.core.agent import ledger, walk
from cleaner.core.agent.stream import DeltaRestorer, RestorationBudget, map_strings, usage_numbers
from cleaner.core.agent.walk import (
    OTHER_KEYS, SCHEMA_KEYS, Unit, bare, parameter_strings, parsed_arguments, strings, text_block,
)
from cleaner.core.types import ChatState, Settings

TEXT_PARTS = frozenset({"input_text", "output_text"})
MEDIA = frozenset({"input_image", "input_file", "input_audio"})
CALLS = frozenset({"function_call", "custom_tool_call", "local_shell_call"})
RESULTS = frozenset({"function_call_output", "custom_tool_call_output", "local_shell_call_output"})
OPAQUE = frozenset({"reasoning", "compaction", "context_compaction", "web_search_call", "image_generation_call"})
# Параметры — служебные строки. client_metadata — не здесь: в нём x-codex-turn-metadata с рабочими каталогами агента,
# он очищается как незнакомое поле.
PARAMS = frozenset({
    "model", "stream", "store", "include", "reasoning", "text", "tool_choice", "parallel_tool_calls", "prompt_cache_key",
    "service_tier", "stream_options", "max_output_tokens", "metadata", "previous_response_id", "truncation", "user",
})
KEEP = ("id", "status")         # из элемента агента при сборке: в отпечатке их нет
_ITEM_KEYS = frozenset({"type", "id", "call_id", "status"})
_MESSAGE_KEYS = frozenset({"type", "id", "role", "content", "status"})
_TOOLS_ITEM_KEYS = frozenset({"type", "id", "role", "tools"})
_TOOL_SERVICE = frozenset({"type", "name", "strict", "format"})     # format — грамматика свободного инструмента
_USAGE = {"input_tokens": "input", "output_tokens": "output", "input_tokens_details.cached_tokens": "cache_read"}


def _part_kind(part: object) -> str:
    if isinstance(part, dict):
        if part.get("type") in MEDIA:
            return "media"
        if part.get("type") in TEXT_PARTS and isinstance(part.get("text"), str):
            return "text"
    return "other"


def _item_node(item: dict) -> dict:
    return {key: value for key, value in item.items() if key not in ("id", "status")}


def _opaque_node(item: dict) -> dict:
    # Codex adds content:null on replay; it carries no new data and does not change provenance.
    return {key: value for key, value in item.items() if key != "content" or value is not None}


def _call_node(item: dict) -> dict:
    node = _item_node(item)
    if "arguments" in node:
        node["arguments"] = parsed_arguments(node["arguments"])
    return node


def responses_units(body: dict) -> list[Unit]:
    units: list[Unit] = []
    instructions = body.get("instructions")
    if isinstance(instructions, str):
        units.append(Unit(("instructions",), "system", "text", text_block(instructions)))
    elif instructions is not None:
        units.append(Unit(("instructions",), "system", "other", instructions))
    items = body.get("input")
    if isinstance(items, str):
        units.append(Unit(("input",), "user", "text", text_block(items)))
    for i, item in enumerate(items if isinstance(items, list) else ()):
        path = ("input", i)
        kind = item.get("type") if isinstance(item, dict) else None
        if not isinstance(item, dict):
            units.append(Unit(path, "user", "other", item))
        elif kind == "message" or (kind is None and "role" in item):
            role, content = str(item.get("role", "")), item.get("content")
            if isinstance(content, str):
                units.append(Unit((*path, "content"), role, "text", text_block(content)))
            elif isinstance(content, list):
                units += [Unit((*path, "content", j), role, _part_kind(p), bare(p)) for j, p in enumerate(content)]
            elif content is not None:
                units.append(Unit((*path, "content"), role, "other", content))
            # Незнакомое поле сообщения — текст (8.3): очищается, а не уходит как есть.
            units += [Unit((*path, key), role, "other", value) for key, value in item.items() if key not in _MESSAGE_KEYS]
        elif kind in CALLS:
            units.append(Unit(path, "assistant", "tool_use", _call_node(item)))
        elif kind in RESULTS:
            units.append(Unit(path, "tool", "tool_result", _item_node(item)))
        elif kind in OPAQUE:
            units.append(Unit(path, "assistant", "opaque", _opaque_node(item)))
            if kind == "reasoning" and item.get("summary"):
                units.append(Unit((*path, "summary"), "assistant", "reasoning", item["summary"]))
        elif kind == "additional_tools":
            units += [Unit((*path, "tools", j), "tools", "tool_def", tool) for j, tool in enumerate(item.get("tools") or ())]
            units += [Unit((*path, key), "tools", "other", value) for key, value in item.items() if key not in _TOOLS_ITEM_KEYS]
        else:
            units.append(Unit(path, "user", "other", item))
    units += [Unit(("tools", j), "tools", "tool_def", tool) for j, tool in enumerate(body.get("tools") or ())]
    units += [
        Unit((key,), "params", "other", value) for key, value in body.items()
        if key not in PARAMS and key not in ("instructions", "input", "tools")
    ]
    return units


def first_user(body: dict) -> object:
    """Первое сообщение пользователя — для отпечатка разговора (6.3). У Codex это окружение (<environment_context>):
    у сессий в одном каталоге в один день оно одинаково, поэтому в отпечаток входит и id элемента — свой у сессии и тот
    же после возобновления (проверка 18.1b 5В)."""
    items = body.get("input")
    if isinstance(items, str):
        return [text_block(items)]
    for item in items if isinstance(items, list) else ():
        if isinstance(item, dict) and item.get("role") == "user":
            content = item.get("content")
            blocks = [text_block(content)] if isinstance(content, str) else content if isinstance(content, list) else [content]
            parts = [bare(block) for block in blocks]
            return {"id": item["id"], "content": parts} if isinstance(item.get("id"), str) else parts
    return None


def structural(body: dict) -> list[str]:
    """Служебные строки: имена инструментов (в tools, в additional_tools, вложенные, в вызовах истории), параметры."""
    out: list[str] = []

    def names(tools: object) -> None:
        for tool in tools if isinstance(tools, list) else ():
            if isinstance(tool, dict):
                if isinstance(tool.get("name"), str):
                    out.append(tool["name"])
                names(tool.get("tools"))

    names(body.get("tools"))
    for item in body.get("input") if isinstance(body.get("input"), list) else ():
        if isinstance(item, dict) and item.get("type") == "additional_tools":
            names(item.get("tools"))
        elif isinstance(item, dict) and item.get("type") in CALLS and isinstance(item.get("name"), str):
            out.append(item["name"])
    for key, value in body.items():
        if key in PARAMS:
            out += parameter_strings(value, data=key == "metadata")
    return out


def _result_part(part: object, clean: Callable[[str], str]) -> object:
    kind = _part_kind(part)
    if kind == "media":
        return {"type": "input_text", "text": ledger.placeholder(ledger.REASONS["media"])}   # снимок view_image (7.4)
    if kind == "text":
        return dict(part, text=clean(part["text"]))
    return strings(part, clean, OTHER_KEYS)


def _tool_def(node: dict, clean: Callable[[str], str]) -> dict:
    """Описание инструмента: вид, имя, strict и грамматика format — служебные; схема parameters — без служебных ключей
    схемы; пространство имён — вложенные описания тем же порядком."""
    out = {}
    for key, value in node.items():
        if key in _TOOL_SERVICE:
            out[key] = value
        elif key == "tools" and isinstance(value, list):
            out[key] = [_tool_def(tool, clean) if isinstance(tool, dict) else tool for tool in value]
        else:
            out[key] = strings(value, clean, SCHEMA_KEYS if key == "parameters" else OTHER_KEYS)
    return out


def sanitize_unit(unit: Unit, clean: Callable[[str], str]) -> object:
    """Новый узел с очищенным текстом в виде запроса: аргументы вызова — снова строкой JSON."""
    node = unit.node
    if unit.kind == "text":
        return dict(node, text=clean(node["text"]))
    if unit.kind == "tool_result":
        output = node.get("output")
        if isinstance(output, str):
            return dict(node, output=clean(output))
        if isinstance(output, list):
            return dict(node, output=[_result_part(part, clean) for part in output])
        return strings(node, clean, _ITEM_KEYS)
    if unit.kind == "tool_use":
        if "arguments" in node:
            arguments = node["arguments"]
            cleaned = clean(arguments) if isinstance(arguments, str) else json.dumps(strings(arguments, clean, frozenset()), ensure_ascii=False)
            return dict(node, arguments=cleaned)
        if isinstance(node.get("input"), str):
            return dict(node, input=clean(node["input"]))
        return strings(node, clean, _ITEM_KEYS)
    if unit.kind == "tool_def" and isinstance(node, dict):
        return _tool_def(node, clean)
    if unit.kind in ("other", "reasoning"):
        return strings(node, clean, _ITEM_KEYS)
    return copy.deepcopy(node)          # непрозрачный и удерживаемый — как есть


def contains_media(unit: Unit) -> bool:
    if unit.kind == "media":
        return True
    output = unit.node.get("output") if unit.kind == "tool_result" and isinstance(unit.node, dict) else None
    return isinstance(output, list) and any(_part_kind(part) == "media" for part in output)


def placeholder(unit: Unit, reason: str) -> object:
    """Пометка удержанного блока того же вида (7.4): у результата инструмента — его выводом."""
    text = ledger.placeholder(reason)
    node = unit.node if isinstance(unit.node, dict) else {}
    if unit.kind == "reasoning":
        return [{"type": "summary_text", "text": text}]
    if unit.kind == "tool_result":
        return dict(node, output=text)
    if unit.kind == "tool_use":
        if "arguments" in node:
            return dict(node, arguments=json.dumps({"cleaner": text}, ensure_ascii=False))
        if "input" in node:
            return dict(node, input=text)
        return dict(node, action={"type": "exec", "command": ["echo", text]})
    if unit.kind == "tool_def":
        return {**node, "description": text, **({"parameters": {"type": "object"}} if "parameters" in node else {}),
                **({"tools": []} if "tools" in node else {})}
    if node.get("type") == "text":                  # строкой: instructions, input, content
        return text_block(text)
    if unit.role == "params":
        return text
    if len(unit.path) == 2 and unit.path[0] == "input":            # незнакомый элемент input — сообщением
        return {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}
    return {"type": "output_text" if node.get("type") == "output_text" else "input_text", "text": text}


def model_kind(node: dict) -> str:
    if node.get("type") in OPAQUE:
        return "opaque"
    return "text" if node.get("type") == "output_text" else "tool_use"


def ledger_node(role: str, kind: str, node: object) -> object:
    """Текст ассистента для отпечатка журнала: строка content и часть output_text — один узел. Клиент присылает ответ
    модели то строкой, то частью; пустые annotations и logprobs части ничего не добавляют."""
    if role != "assistant" or kind != "text" or not isinstance(node, dict) or node.get("type") not in ("text", "output_text"):
        return node
    return {"type": "output_text", **{
        key: value for key, value in node.items() if key != "type" and value not in ([], None)
    }}


def rebuild(body: dict, replaced: dict) -> dict:
    replaced = dict(replaced)
    for path, node in replaced.items():
        if len(path) == 2 and path[0] == "input" and isinstance(node, dict) and node.get("type") in OPAQUE:
            old = body["input"][path[1]]
            if "content" in old and old["content"] is None:
                replaced[path] = dict(node, content=None)
        elif path[-1] == "content" and isinstance(node, dict) and node.get("type") == "output_text":
            # Часть из журнала на месте ответа строкой (ledger_node): строкой и уходит.
            replaced[path] = text_block(node["text"])
    return walk.rebuild(body, replaced, KEEP)


def add_instruction(body: dict, text: str) -> dict:
    """Служебная инструкция — сообщением developer перед первым сообщением пользователя (8.8)."""
    instruction = {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": text}]}
    items = body.get("input")
    if not isinstance(items, list):
        user = [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": items}]}] if isinstance(items, str) else []
        body["input"] = [instruction, *user]
        return body
    items = list(items)
    at = next((i for i, item in enumerate(items) if isinstance(item, dict) and item.get("role") == "user"), len(items))
    items.insert(at, instruction)
    body["input"] = items
    return body


def error_event(message: str) -> dict:
    return {"type": "error", "code": "server_error", "message": message, "param": None}


def usage(event: dict) -> dict[str, int]:
    """usage из response.completed (и incomplete) или ответа без потока."""
    response = event.get("response") if isinstance(event.get("response"), dict) else event
    return usage_numbers(response.get("usage"), _USAGE)


@dataclass
class _Part:
    restorer: DeltaRestorer
    output_index: object = None
    parts: list[str] = field(default_factory=list)      # текст модели
    shown: list[str] = field(default_factory=list)      # отданный агенту текст
    done: bool = False


class ResponsesStream:
    """События потока для агента. pairs — для каждой части текста и каждого вызова пара «как агент пришлёт в истории —
    как прислала модель» (журнал out, 7.2); узлы — как в responses_units."""

    def __init__(self, state: ChatState, settings: Settings):
        self.state = state
        self.settings = settings
        self.texts: dict[tuple, _Part] = {}             # ((id, output_index без id), content_index) → часть текста
        self.items: dict[tuple, dict] = {}              # id или output_index → восстановленный элемент
        self.inputs: dict[tuple, list[str]] = {}        # id или output_index → части arguments или input
        self.pairs: list[tuple[dict, dict]] = []
        self.budget = RestorationBudget()
        self._text: Callable[[str], str] | None = None
        self._exact: Callable[[str], str] | None = None

    def _restore_text(self, text: str) -> str:
        if self._text is None:
            self._text = self.budget.original(self.state, self.settings)
        return self._text(text)

    def _restore_exact(self, value: object) -> object:
        if self._exact is None:
            self._exact = self.budget.original(self.state, self.settings, exact=True)
        return map_strings(value, self._exact)

    def _arguments(self, raw: str) -> str:
        try:
            value = json.loads(raw)
        except ValueError:
            return raw                                   # незаконченный JSON — как пришёл
        return json.dumps(self._restore_exact(value), ensure_ascii=False)

    @staticmethod
    def finished(event: dict) -> bool:
        return event.get("type") in ("response.completed", "response.incomplete", "response.failed")

    def _slot(self, event: dict) -> tuple[tuple, _Part]:
        key = (self._item_key(event.get("item_id"), event.get("output_index")), event.get("content_index", 0))
        if key not in self.texts:
            self.texts[key] = _Part(DeltaRestorer(self.state, self.settings, self._restore_text), event.get("output_index"))
        return key, self.texts[key]

    def _delta(self, key: tuple, part: _Part, text: str) -> list[dict]:
        if not text:
            return []
        part.shown.append(text)
        return [{"type": "response.output_text.delta", "item_id": key[0][0], "output_index": part.output_index,
                 "content_index": key[1], "delta": text}]

    def _whole(self, event: dict, text: object) -> list[dict]:
        """Итоговый текст части: остаток после дельт; без дельт — весь текст одной дельтой."""
        key, part = self._slot(event)
        out = []
        if not part.parts and isinstance(text, str) and text:
            part.parts.append(text)
            out += self._delta(key, part, part.restorer.feed(text))
        if not part.done:
            part.done = True
            out += self._delta(key, part, part.restorer.finish())
        return out

    def _close(self, item_id: object = None, output_index: object = None) -> list[dict]:
        """Остатки текста открытых частей элемента (всех — без id и индекса) перед его итоговым объектом."""
        out = []
        for key, part in self.texts.items():
            if not part.done and ((item_id is None and output_index is None) or key[0] == self._item_key(item_id, output_index)):
                part.done = True
                out += self._delta(key, part, part.restorer.finish())
        return out

    def _pair(self, item: dict, restored: dict) -> None:
        self.pairs.append((_call_node(restored), _item_node(item)))

    @staticmethod
    def _item_key(item_id: object, output_index: object) -> tuple:
        return (item_id, None if item_id is not None else output_index)

    def _item(self, item: dict, output_index: object = None) -> dict:
        """Элемент ответа с восстановленным текстом, аргументами, патчем, командой; пары — в pairs, один раз."""
        item_id = item.get("id")
        key = self._item_key(item_id, output_index)
        if key in self.items:
            return self.items[key]
        kind = item.get("type")
        restored = item
        if kind == "message" and isinstance(item.get("content"), list):
            content = []
            for j, part in enumerate(item["content"]):
                if _part_kind(part) == "text" and part["type"] == "output_text":
                    streamed = self.texts.get((key, j))
                    text = "".join(streamed.shown) if streamed is not None else self._restore_text(part["text"])
                    content.append(dict(part, text=text))
                    self.pairs.append((dict(part, text=text), dict(part)))
                else:
                    content.append(part)
            restored = dict(item, content=content)
        elif kind == "function_call" and isinstance(item.get("arguments"), str):
            restored = dict(item, arguments=self._arguments(item["arguments"]))
            if isinstance(parsed_arguments(item["arguments"]), (dict, list)):      # незаконченный JSON — без пары
                self._pair(item, restored)
        elif kind == "custom_tool_call" and isinstance(item.get("input"), str):
            restored = dict(item, input=self._restore_exact(item["input"]))
            self._pair(item, restored)
        elif kind == "local_shell_call" and "action" in item:
            restored = dict(item, action=self._restore_exact(item["action"]))
            self._pair(item, restored)
        elif kind in OPAQUE:
            self.pairs.append((_opaque_node(item), dict(item)))
        if item_id is not None or output_index is not None:
            self.items[key] = restored
        return restored

    def feed(self, event: dict) -> list[dict]:
        type_ = event.get("type")
        item_id = event.get("item_id")
        key = self._item_key(item_id, event.get("output_index"))
        if type_ == "response.output_text.delta":
            key, part = self._slot(event)
            text = event.get("delta") or ""
            part.parts.append(text)
            return self._delta(key, part, part.restorer.feed(text))
        if type_ == "response.output_text.done":
            out = self._whole(event, event.get("text"))
            return out + [dict(event, text="".join(self._slot(event)[1].shown))]
        if type_ == "response.content_part.done" and isinstance(event.get("part"), dict) and event["part"].get("type") == "output_text":
            out = self._whole(event, event["part"].get("text"))
            return out + [dict(event, part=dict(event["part"], text="".join(self._slot(event)[1].shown)))]
        if type_ in ("response.function_call_arguments.delta", "response.custom_tool_call_input.delta"):
            self.inputs.setdefault(key, []).append(event.get("delta") or "")
            return []                                    # Codex их только показывает: копятся до done
        if type_ == "response.function_call_arguments.done":
            raw = event.get("arguments") if isinstance(event.get("arguments"), str) else "".join(self.inputs.get(key, ()))
            return [dict(event, arguments=self._arguments(raw))]
        if type_ == "response.custom_tool_call_input.done":
            raw = event.get("input") if isinstance(event.get("input"), str) else "".join(self.inputs.get(key, ()))
            restored = self._restore_exact(raw)
            delta = {"type": "response.custom_tool_call_input.delta", "item_id": item_id,
                     "output_index": event.get("output_index"), "delta": restored}
            return [delta, dict(event, input=restored)]  # одна дельта: предпросмотр патча не пустой
        if type_ == "response.output_item.added" and isinstance(event.get("item"), dict):
            item = event["item"]
            for name in ("arguments", "input"):          # присланное сразу — как дельты, а начало уходит пустым
                if isinstance(item.get(name), str) and item[name]:
                    self.inputs.setdefault(self._item_key(item.get("id"), event.get("output_index")), []).append(item[name])
                    return [dict(event, item=dict(item, **{name: ""}))]
            return [event]
        if type_ == "response.output_item.done" and isinstance(event.get("item"), dict):
            index = event.get("output_index")
            return self._close(event["item"].get("id"), index) + [dict(event, item=self._item(event["item"], index))]
        if type_ in ("response.completed", "response.incomplete") and isinstance(event.get("response"), dict):
            response = event["response"]
            out = self._close()
            if isinstance(response.get("output"), list):
                output = [self._item(item, i) if isinstance(item, dict) else item for i, item in enumerate(response["output"])]
                return out + [dict(event, response=dict(response, output=output))]
            return out + [event]
        if type_ == "error":
            return self.cut() + [event]
        return [event]

    def cut(self) -> list[dict]:
        """Поток оборвался: несколько знаков текста — как есть; незаконченные аргументы Codex и так не исполнит."""
        out = self._close()
        self.texts.clear()
        self.inputs.clear()
        return out

    def complete(self, body: dict) -> dict:
        """Ответ без потока: те же тексты и аргументы, что дал бы поток."""
        output = body.get("output")
        if not isinstance(output, list):
            return body
        return dict(body, output=[self._item(item, i) if isinstance(item, dict) else item for i, item in enumerate(output)])
