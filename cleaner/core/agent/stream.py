"""Восстановление потока ответа Anthropic для агента (спецификация 2026-10-28, раздел 10). Текст отдаётся по мере
прихода, без правила ссылок (терминал агента ссылок не загружает), секреты в нём — метками (FR-7.7). Аргументы вызова
инструмента копятся до конца блока и уходят одной дельтой, восстановленные точно (10.3): секреты — тоже. Рассуждения,
подписи, ping и незнакомые события — как пришли и сразу. Сам DeltaRestorer держит только неотданный хвост;
обработчики сохраняют исходные и восстановленные блоки для зашифрованного журнала. Их общий объём ограничен
egress: 32 МиБ ответа и 2 МиБ одной строки SSE, включая аргументы инструментов."""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from cleaner.core.restore import RestoreLimit, originals, safe_cut
from cleaner.core.types import ChatState, EntityType, Settings

_TYPES = "|".join(t.value.replace("_", r"\\?_") for t in sorted(EntityType, key=lambda t: -len(t.value)))
# Конец текста, который может оказаться началом искажённой записи метки (restore._TOLERANT): у неё пробелы бывают после
# открывающего знака, вокруг «_» и перед закрывающим («< EMAIL _ 1 >»). Граница по пробелу её бы разрезала — граница
# отступает перед ней. Записи без пробелов граница по пробелу не режет.
_LABEL_TAIL = re.compile(
    rf"(?:(?:\\?<|&lt;|\\?\[\\?\[)\s*(?:(?ai:{_TYPES})\s*(?:\\?_\s*(?:\d+\s*)?)?)?"
    rf"|(?<![\w<\[])(?ai:{_TYPES})\s*(?:\\?_\s*(?:\d+\s*)?)?)\Z"
)
RESTORED_BYTES = 32 * 1024 * 1024
ARGUMENT_BYTES = 2 * 1024 * 1024


class RestorationBudget:
    """Aggregate restored text and tool argument bytes, shared by all blocks and choices of one response."""

    def __init__(self):
        self.remaining = RESTORED_BYTES
        self.arguments = ARGUMENT_BYTES

    def original(self, state: ChatState, settings: Settings, *, exact: bool = False) -> Callable[[str], str]:
        restore = originals(state, settings, exact=exact, max_bytes=ARGUMENT_BYTES if exact else RESTORED_BYTES)

        def checked(value: str) -> str:
            result = restore(value)
            size = len(result.encode("utf-8"))
            if size > self.remaining or exact and size > self.arguments:
                raise RestoreLimit("response_expansion_limit")
            self.remaining -= size
            if exact:
                self.arguments -= size
            return result

        return checked


class DeltaRestorer:
    """Текст модели по частям: feed отдаёт прирост восстановленного текста до границы, где замена не может оборваться,
    finish — остаток. Склейка отданного равна восстановлению всего текста одним куском."""

    def __init__(self, state: ChatState, settings: Settings, original: Callable[[str], str] | None = None):
        self.original = original or originals(state, settings)
        self.text = ""

    def feed(self, chunk: str) -> str:
        self.text += chunk
        cut = safe_cut(self.text)
        # Пробелы внутри допустимой метки не ограничены фиксированным окном: её начало нужно удержать,
        # даже когда модель разделяет тип и номер сотнями пробелов и разрывами дельт.
        tail = _LABEL_TAIL.search(self.text, 0, cut)
        if tail is not None:
            cut = tail.start()
        if not cut:
            return ""
        piece, self.text = self.text[:cut], self.text[cut:]
        return self.original(piece)

    def finish(self) -> str:
        piece, self.text = self.text, ""
        return self.original(piece) if piece else ""


def usage_numbers(usage: object, names: Mapping[str, str]) -> dict[str, int]:
    """Числа usage провайдера под короткими именами журнала; имя вида «a.b» — вложенное поле. Строки и прочее — прочь:
    в журнал событий идут только числа."""
    out = {}
    for name, short in names.items():
        value = usage
        for step in name.split("."):
            value = value.get(step) if isinstance(value, dict) else None
        if isinstance(value, int) and not isinstance(value, bool):
            out[short] = value
    return out


_ANTHROPIC_USAGE = {
    "input_tokens": "input", "output_tokens": "output", "cache_read_input_tokens": "cache_read",
    "cache_creation_input_tokens": "cache_write",
}


def anthropic_usage(event: dict) -> dict[str, int]:
    """usage из message_start, message_delta (нарастающий итог) или ответа без потока."""
    message = event.get("message")
    found = event.get("usage") or (message.get("usage") if isinstance(message, dict) else None)
    return usage_numbers(found, _ANTHROPIC_USAGE)


def named_sse(event: dict) -> bytes:
    """Событие с именем — «event: <type>» и «data: …» (Anthropic, Responses)."""
    data = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    return f"event: {event.get('type', 'message')}\ndata: {data}\n\n".encode("utf-8")


def anthropic_error(message: str) -> dict:
    return {"type": "error", "error": {"type": "api_error", "message": message}}


def map_strings(value: object, fn: Callable[[str], str]) -> object:
    """Строки на любой глубине через fn; ключи объектов не трогаются."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [map_strings(item, fn) for item in value]
    if isinstance(value, dict):
        return {key: map_strings(item, fn) for key, item in value.items()}
    return value


@dataclass
class _Block:
    kind: str                                           # text | tool_use
    start: dict                                         # content_block из content_block_start
    parts: list[str] = field(default_factory=list)      # текст модели или части JSON аргументов
    shown: list[str] = field(default_factory=list)      # отданный агенту текст
    restorer: DeltaRestorer | None = None


class AnthropicStream:
    """События потока для агента. pairs — для каждого законченного блока text и tool_use пара «блок, как агент пришлёт
    его в истории — блок, как его прислала модель» (журнал out, 7.2)."""

    def __init__(self, state: ChatState, settings: Settings):
        self.state = state
        self.settings = settings
        self.blocks: dict[int, _Block] = {}
        self.pairs: list[tuple[dict, dict]] = []
        self.budget = RestorationBudget()
        self._text: Callable[[str], str] | None = None
        self._exact: Callable[[str], str] | None = None

    def _restore_text(self, text: str) -> str:
        if self._text is None:
            self._text = self.budget.original(self.state, self.settings)
        return self._text(text)

    def _restore_input(self, value: object) -> object:
        if self._exact is None:
            self._exact = self.budget.original(self.state, self.settings, exact=True)
        return map_strings(value, self._exact)

    @staticmethod
    def finished(event: dict) -> bool:
        return event.get("type") == "message_stop"

    def feed(self, event: dict) -> list[dict]:
        type_ = event.get("type")
        index = event.get("index")
        if type_ == "content_block_start":
            # Совместимый провайдер присылает текст и аргументы вызова и в самом начале блока: агенту начало уходит
            # пустым, а присланное — как дельты, восстановленными (аргументы — в конце блока, _close).
            block = event.get("content_block") or {}
            if block.get("type") == "text":
                opened = _Block("text", block, restorer=DeltaRestorer(self.state, self.settings, self._restore_text))
                self.blocks[index] = opened
                initial = block.get("text") or ""
                start = dict(event, content_block=dict(block, text="")) if initial else event
                opened.parts.append(initial)
                return [start, *self._text_delta(opened, index, opened.restorer.feed(initial))]
            if block.get("type") == "tool_use":
                self.blocks[index] = _Block("tool_use", block)
                return [dict(event, content_block=dict(block, input={}))] if block.get("input") else [event]
            from cleaner.core.agent.walk import OPAQUE
            if block.get("type") in OPAQUE:
                self.blocks[index] = _Block("opaque", dict(block))
            return [event]
        block = self.blocks.get(index) if type_ in ("content_block_delta", "content_block_stop") else None
        if block is None:
            return self.cut() + [event] if type_ == "error" else [event]
        if type_ == "content_block_delta":
            delta = event.get("delta") or {}
            if block.kind == "opaque":
                for key in ("thinking", "signature"):
                    if isinstance(delta.get(key), str):
                        block.start[key] = block.start.get(key, "") + delta[key]
                return [event]
            if block.kind == "text" and delta.get("type") == "text_delta":
                block.parts.append(delta.get("text", ""))
                return self._text_delta(block, index, block.restorer.feed(delta.get("text", "")))
            if block.kind == "tool_use" and delta.get("type") == "input_json_delta":
                block.parts.append(delta.get("partial_json", ""))
                return []
            return [event]
        del self.blocks[index]
        return self._close(block, index) + [event]

    def _text_delta(self, block: _Block, index: int, text: str) -> list[dict]:
        if not text:
            return []
        block.shown.append(text)
        return [{"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text}}]

    def _close(self, block: _Block, index: int) -> list[dict]:
        """Конец блока: остаток текста или аргументы целиком; пара — в pairs."""
        if block.kind == "opaque":
            self.pairs.append((dict(block.start), dict(block.start)))
            return []
        if block.kind == "text":
            out = self._text_delta(block, index, block.restorer.finish())
            self.pairs.append(({"type": "text", "text": "".join(block.shown)}, {"type": "text", "text": "".join(block.parts)}))
            return out
        raw = "".join(block.parts)
        if not raw:
            arguments = block.start.get("input") or {}
            restored = self._restore_input(arguments)
            out = [self._json_delta(index, json.dumps(restored, ensure_ascii=False))] if arguments else []
        else:
            try:
                arguments = json.loads(raw)
            except ValueError:
                return [self._json_delta(index, raw)]       # незаконченный JSON — как пришёл, без пары
            restored = self._restore_input(arguments)
            out = [self._json_delta(index, json.dumps(restored, ensure_ascii=False))]
        head = {"type": "tool_use", "id": block.start.get("id"), "name": block.start.get("name")}
        self.pairs.append((dict(head, input=restored), dict(head, input=arguments)))
        return out

    @staticmethod
    def _json_delta(index: int, partial: str) -> dict:
        return {"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": partial}}

    def cut(self) -> list[dict]:
        """Поток оборвался: несколько знаков текста и незаконченные аргументы — как пришли; пар у этих блоков нет."""
        out = []
        for index, block in self.blocks.items():
            if block.kind == "text":
                out += self._text_delta(block, index, block.restorer.finish())
            elif block.parts:
                out.append(self._json_delta(index, "".join(block.parts)))
        self.blocks.clear()
        return out

    def complete(self, message: dict) -> dict:
        """Ответ без потока: тот же текст, что дала бы склейка дельт, и те же аргументы."""
        content = []
        for block in message.get("content") or ():
            kind = block.get("type") if isinstance(block, dict) else None
            if kind == "text":
                restored = dict(block, text=self._restore_text(block.get("text", "")))
                self.pairs.append(({"type": "text", "text": restored["text"]}, {"type": "text", "text": block.get("text", "")}))
            elif kind == "tool_use":
                restored = dict(block, input=self._restore_input(block.get("input", {})))
                head = {"type": "tool_use", "id": block.get("id"), "name": block.get("name")}
                self.pairs.append((dict(head, input=restored["input"]), dict(head, input=block.get("input", {}))))
            else:
                restored = block
                from cleaner.core.agent.walk import OPAQUE
                if kind in OPAQUE:
                    self.pairs.append((dict(block), dict(block)))
            content.append(restored)
        return dict(message, content=content)
