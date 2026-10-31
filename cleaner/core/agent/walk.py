"""Обход тела запроса Anthropic Messages (спецификация 2026-10-28, разделы 8.3 и 9.1): тело раскладывается на блоки —
единицы журнала отправленного. Каждый блок — текст (очищается), непрозрачный (уходит как есть), изображение или файл
(удерживается, 7.4) или незнакомый (очищается весь, кроме служебных ключей). Служебные строки — для проверки утечек."""
from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from cleaner.core.agent import ledger

Path = tuple[str | int, ...]

# Блок атрибуции Claude Code — первый блок system (проверка 18.1b); без CLAUDE_CODE_ATTRIBUTION_HEADER=0 он есть.
ATTRIBUTION = "x-anthropic-billing-header:"
# Рассуждения модели и блоки инструментов, которые исполняет провайдер, — как пришли (7.2.3).
OPAQUE = frozenset({"thinking", "redacted_thinking", "server_tool_use", "web_search_tool_result"})
MEDIA = frozenset({"image", "document", "file"})
# Параметры запроса — служебные строки: уходят как есть и проверяются на утечки (8.3). Поле не из этого списка и не
# system, messages, tools — незнакомое: очищается как текст.
PARAMS = frozenset({
    "metadata", "tool_choice", "max_tokens", "stream", "temperature", "top_p", "top_k", "stop_sequences", "thinking",
    "context_management", "output_config", "service_tier", "container",
})
# Значения этих ключей схемы инструмента — не текст: тип, формат, ссылка, имена обязательных свойств, адрес схемы.
SCHEMA_KEYS = frozenset({"type", "format", "$ref", "required", "$schema"})
OTHER_KEYS = frozenset({"type", "id", "cache_control"})


@dataclass(frozen=True)
class Unit:
    path: Path                 # где блок в теле; у строкового содержимого — путь самой строки
    role: str                  # system | user | assistant | tools | params
    kind: str                  # text | reasoning | tool_result | tool_use | tool_def | opaque | media | other
    node: object               # блок без cache_control; строковое содержимое — блок text с этой строкой


def bare(block: object) -> object:
    return {key: value for key, value in block.items() if key != "cache_control"} if isinstance(block, dict) else block


def is_media(block: object) -> bool:
    if not isinstance(block, dict):
        return False
    source = block.get("source")
    return block.get("type") in MEDIA or (isinstance(source, dict) and source.get("type") in ("base64", "url"))


def _kind(block: object) -> str:
    if is_media(block):
        return "media"
    type_ = block.get("type") if isinstance(block, dict) else None
    if type_ == "text" and isinstance(block.get("text"), str):
        return "text"
    if type_ in ("tool_result", "tool_use"):
        return type_
    return "opaque" if type_ in OPAQUE else "other"


def text_block(text: str) -> dict:
    return {"type": "text", "text": text}


def _content(units: list[Unit], path: Path, role: str, content: object) -> None:
    """Строка и список блоков — одинаковые единицы: агент пишет одно и то же сообщение то так, то так (18.1d)."""
    if isinstance(content, str):
        units.append(Unit(path, role, "text", text_block(content)))
    elif isinstance(content, list):
        units += [Unit((*path, i), role, _kind(block), bare(block)) for i, block in enumerate(content)]
    else:
        units.append(Unit(path, role, "other", content))


def anthropic_units(body: dict) -> list[Unit]:
    units: list[Unit] = []
    system = body.get("system")
    if isinstance(system, list):
        for i, block in enumerate(system):
            attribution = isinstance(block, dict) and str(block.get("text", "")).startswith(ATTRIBUTION)
            units.append(Unit(("system", i), "system", "opaque" if attribution else _kind(block), bare(block)))
    elif system is not None:
        _content(units, ("system",), "system", system)
    for i, message in enumerate(body.get("messages") or ()):
        if isinstance(message, dict):
            role = str(message.get("role", ""))
            _content(units, ("messages", i, "content"), role, message.get("content"))
            # Строка под незнакомым ключом сообщения — текст (8.3), как в Chat Completions и Responses.
            units += [Unit(("messages", i, key), role, "other", value) for key, value in message.items() if key not in ("role", "content")]
        else:
            units.append(Unit(("messages", i), "user", "other", message))
    units += [Unit(("tools", i), "tools", "tool_def", bare(tool)) for i, tool in enumerate(body.get("tools") or ())]
    units += [
        Unit((key,), "params", "other", value) for key, value in body.items()
        if key not in PARAMS and key not in ("model", "system", "messages", "tools")
    ]
    return units


def first_user(body: dict) -> object:
    """Первое сообщение пользователя — для отпечатка разговора (6.3): блоками, без cache_control у каждого."""
    for message in body.get("messages") or ():
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            blocks = [text_block(content)] if isinstance(content, str) else content if isinstance(content, list) else [content]
            return [bare(block) for block in blocks]
    return None


def strings_of(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings_of(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings_of(item)


def structural(body: dict) -> list[str]:
    """Служебные строки: модель, имена инструментов (в описаниях и в вызовах истории), параметры запроса. Уходят как
    есть — проверка утечек их видит (раздел 17, риск 3)."""
    out = [body["model"]] if isinstance(body.get("model"), str) else []
    out += [tool["name"] for tool in body.get("tools") or () if isinstance(tool, dict) and isinstance(tool.get("name"), str)]
    for message in body.get("messages") or ():
        content = message.get("content") if isinstance(message, dict) else None
        for block in content if isinstance(content, list) else ():
            if isinstance(block, dict) and block.get("type") == "tool_use" and isinstance(block.get("name"), str):
                out.append(block["name"])
    for key, value in body.items():
        if key in PARAMS:
            out += strings_of(value)
    return out


_UNCHECKED_SCHEMA_KEYS = frozenset({"required", "type"})


def checked_strings(kind: str, node: object) -> Iterator[str]:
    """Строки нового узла для проверки утечек. У описания инструмента — без имён обязательных свойств (required) и типов
    схемы: шлюз их, как и сами имена свойств, не очищает, а совпадение имени свойства с найденной сущностью (учётная
    запись «name» из примера пути «/Users/name/» в описании bash у OpenCode) отказывало бы каждому запросу агента.
    Остальные служебные значения схемы (format, $ref, $schema) уходят как есть и проверяются."""
    if kind != "tool_def":
        yield from strings_of(node)
    elif isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from checked_strings(kind, item)
    elif isinstance(node, dict):
        for key, item in node.items():
            if key not in _UNCHECKED_SCHEMA_KEYS or isinstance(item, dict):
                yield from checked_strings(kind, item)


def strings(value: object, clean: Callable[[str], str], skip: frozenset[str]) -> object:
    """Все строки на любой глубине через clean; ключи не трогаются, значения ключей skip — тоже (кроме объектов: свойство
    схемы по имени «type» — схема, и её описание — текст)."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, list):
        return [strings(item, clean, skip) for item in value]
    if isinstance(value, dict):
        return {
            key: item if key in skip and not isinstance(item, dict) else strings(item, clean, skip)
            for key, item in value.items()
        }
    return value


def _result_part(part: object, clean: Callable[[str], str]) -> object:
    if is_media(part):
        return text_block(ledger.placeholder(ledger.REASONS["media"]))       # снимок экрана в результате инструмента (7.4)
    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
        return dict(part, text=clean(part["text"]))
    return strings(part, clean, OTHER_KEYS)


def contains_media(unit: Unit) -> bool:
    """Изображение или файл в блоке — удержание с причиной media (7.4)."""
    if unit.kind == "media":
        return True
    content = unit.node.get("content") if unit.kind == "tool_result" and isinstance(unit.node, dict) else None
    return isinstance(content, list) and any(is_media(part) for part in content)


def sanitize_unit(unit: Unit, clean: Callable[[str], str]) -> object:
    """Новый узел с очищенным текстом; строение блока не меняется."""
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
    if unit.kind == "tool_use":
        return dict(node, input=strings(node["input"], clean, frozenset())) if "input" in node else dict(node)
    if unit.kind == "tool_def":
        return {
            key: value if key in ("name", "type") else strings(value, clean, SCHEMA_KEYS if key == "input_schema" else OTHER_KEYS)
            for key, value in node.items()
        }
    if unit.kind == "other":
        return strings(node, clean, OTHER_KEYS)
    return copy.deepcopy(node)          # непрозрачный и удерживаемый — как есть


def is_model_block(unit: Unit) -> bool:
    """Блок модели в истории — ищется в журнале out по тому, что шлюз отдал агенту (7.2.2)."""
    return unit.role == "assistant" and unit.kind in ("text", "tool_use", "reasoning")


def placeholder(unit: Unit, reason: str) -> object:
    """Пометка удержанного блока того же вида (7.4): у результата инструмента — его содержимым."""
    text = ledger.placeholder(reason)
    if unit.kind == "tool_result":
        return dict(unit.node, content=text)
    if unit.kind == "tool_use":
        return dict(unit.node, input={"cleaner": text})      # вызов остаётся вызовом: на его id ссылается результат
    if unit.kind == "tool_def":
        return dict(unit.node, description=text, input_schema={"type": "object"})
    return {"type": "text", "text": text}


def add_instruction(body: dict, text: str) -> dict:
    """Служебная инструкция — последним блоком system (8.8); строка system дополняется через пустую строку. body — уже
    новое тело (rebuild)."""
    system = body.get("system")
    if isinstance(system, list):
        body["system"] = [*system, {"type": "text", "text": text}]
    else:
        body["system"] = f"{system}\n\n{text}" if system else text
    return body


def parsed_arguments(raw: object) -> object:
    """Аргументы вызова из истории (строка JSON) разобранными — для отпечатка: агент пишет строку заново. Не объект и не
    список JSON — строка как есть (очищается как текст)."""
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except ValueError:
            return raw
        return value if isinstance(value, (dict, list)) else raw
    return raw


def rebuild(body: dict, replaced: dict[Path, object], keep: tuple[str, ...] = ("cache_control",)) -> dict:
    """Новое тело: узлы по путям заменены, у блоков — поля keep из присланного тела (cache_control); строковое
    содержимое остаётся строкой. Присланное тело не меняется: копируются только контейнеры на путях замен."""
    out = dict(body)
    copied = {id(out)}
    for path, node in replaced.items():
        parent: dict | list = out
        for step in path[:-1]:
            child = parent[step]
            if id(child) not in copied:
                child = list(child) if isinstance(child, list) else dict(child)
                parent[step] = child
                copied.add(id(child))
            parent = child
        old = parent[path[-1]]
        if isinstance(old, str) and isinstance(node, dict) and node.get("type") == "text":
            parent[path[-1]] = node["text"]
            continue
        new = dict(node) if isinstance(node, dict) else node
        if isinstance(old, dict) and isinstance(new, dict):
            new.update((key, old[key]) for key in keep if key in old)
        parent[path[-1]] = new
    return out
