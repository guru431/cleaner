"""Обход тела запроса Anthropic Messages (спецификация 2026-10-28, разделы 8.3 и 9.1): тело раскладывается на блоки —
единицы журнала отправленного. Каждый блок — текст (очищается), непрозрачный (уходит как есть), изображение или файл
(удерживается, 7.4) или незнакомый (очищается весь, кроме служебных ключей). Служебные строки — для проверки утечек."""
from __future__ import annotations

import copy
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
_SCHEMA_KEYS = frozenset({"type", "format", "$ref", "required", "$schema"})
_OTHER_KEYS = frozenset({"type", "id", "cache_control"})


@dataclass(frozen=True)
class Unit:
    path: Path                 # где блок в теле; у строкового содержимого — путь самой строки
    role: str                  # system | user | assistant | tools | params
    kind: str                  # text | tool_result | tool_use | tool_def | opaque | media | other
    node: object               # блок без cache_control; строковое содержимое — блок text с этой строкой


def _bare(block: object) -> object:
    return {key: value for key, value in block.items() if key != "cache_control"} if isinstance(block, dict) else block


def _media(block: object) -> bool:
    if not isinstance(block, dict):
        return False
    source = block.get("source")
    return block.get("type") in MEDIA or (isinstance(source, dict) and source.get("type") in ("base64", "url"))


def _kind(block: object) -> str:
    if _media(block):
        return "media"
    type_ = block.get("type") if isinstance(block, dict) else None
    if type_ == "text" and isinstance(block.get("text"), str):
        return "text"
    if type_ in ("tool_result", "tool_use"):
        return type_
    return "opaque" if type_ in OPAQUE else "other"


def _text(text: str) -> dict:
    return {"type": "text", "text": text}


def _content(units: list[Unit], path: Path, role: str, content: object) -> None:
    """Строка и список блоков — одинаковые единицы: агент пишет одно и то же сообщение то так, то так (18.1d)."""
    if isinstance(content, str):
        units.append(Unit(path, role, "text", _text(content)))
    elif isinstance(content, list):
        units += [Unit((*path, i), role, _kind(block), _bare(block)) for i, block in enumerate(content)]
    else:
        units.append(Unit(path, role, "other", content))


def anthropic_units(body: dict) -> list[Unit]:
    units: list[Unit] = []
    system = body.get("system")
    if isinstance(system, list):
        for i, block in enumerate(system):
            attribution = isinstance(block, dict) and str(block.get("text", "")).startswith(ATTRIBUTION)
            units.append(Unit(("system", i), "system", "opaque" if attribution else _kind(block), _bare(block)))
    elif system is not None:
        _content(units, ("system",), "system", system)
    for i, message in enumerate(body.get("messages") or ()):
        if isinstance(message, dict):
            _content(units, ("messages", i, "content"), str(message.get("role", "")), message.get("content"))
        else:
            units.append(Unit(("messages", i), "user", "other", message))
    units += [Unit(("tools", i), "tools", "tool_def", _bare(tool)) for i, tool in enumerate(body.get("tools") or ())]
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
            blocks = [_text(content)] if isinstance(content, str) else content if isinstance(content, list) else [content]
            return [_bare(block) for block in blocks]
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


def _strings(value: object, clean: Callable[[str], str], skip: frozenset[str]) -> object:
    """Все строки на любой глубине через clean; ключи не трогаются, значения ключей skip — тоже (кроме объектов: свойство
    схемы по имени «type» — схема, и её описание — текст)."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, list):
        return [_strings(item, clean, skip) for item in value]
    if isinstance(value, dict):
        return {
            key: item if key in skip and not isinstance(item, dict) else _strings(item, clean, skip)
            for key, item in value.items()
        }
    return value


def _result_part(part: object, clean: Callable[[str], str]) -> object:
    if _media(part):
        return _text(ledger.placeholder(ledger.REASONS["media"]))       # снимок экрана в результате инструмента (7.4)
    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
        return dict(part, text=clean(part["text"]))
    return _strings(part, clean, _OTHER_KEYS)


def contains_media(unit: Unit) -> bool:
    """Изображение или файл в блоке — удержание с причиной media (7.4)."""
    if unit.kind == "media":
        return True
    content = unit.node.get("content") if unit.kind == "tool_result" and isinstance(unit.node, dict) else None
    return isinstance(content, list) and any(_media(part) for part in content)


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
        return dict(node, input=_strings(node["input"], clean, frozenset())) if "input" in node else dict(node)
    if unit.kind == "tool_def":
        return {
            key: value if key in ("name", "type") else _strings(value, clean, _SCHEMA_KEYS if key == "input_schema" else _OTHER_KEYS)
            for key, value in node.items()
        }
    if unit.kind == "other":
        return _strings(node, clean, _OTHER_KEYS)
    return copy.deepcopy(node)          # непрозрачный и удерживаемый — как есть


def rebuild(body: dict, replaced: dict[Path, object]) -> dict:
    """Новое тело: узлы по путям заменены, у блоков — cache_control из присланного тела; строковое содержимое остаётся
    строкой. Присланное тело не меняется: копируются только контейнеры на путях замен."""
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
        if isinstance(old, dict) and "cache_control" in old and isinstance(new, dict):
            new["cache_control"] = old["cache_control"]
        parent[path[-1]] = new
    return out
