"""Словарь организации, известные значения чата, правила пользователя и его шаблоны."""
from __future__ import annotations

import threading

import regex

from cleaner.core.detect.base import DetectContext, DetectorError
from cleaner.core.match import Forms
from cleaner.core.types import STRICT_TYPES, EntityType, Span

name = "dict"

PATTERN_TIMEOUT = 1.0   # секунд на один пользовательский шаблон
_CACHE = 8              # таблиц написаний в памяти (_compiled)
_Key = tuple[tuple[str, ...], tuple[str, ...], tuple[int, ...]]    # написания, режимы, номера нагрузок
_cache: list[tuple[_Key, Forms[int]]] = []
_cache_lock = threading.Lock()
# Нагрузка написания — номер пары (тип, источник): кортежи и таблицы из строк и чисел сборщик мусора не обходит.
_PAYLOADS = [(type_, source) for type_ in EntityType for source in (name, "manual")]
_PAYLOAD = {payload: number for number, payload in enumerate(_PAYLOADS)}


def _mode(type_: EntityType) -> str:
    return "strict" if type_ in STRICT_TYPES else "letters"


def _compiled(forms: _Key) -> Forms[int]:
    """Таблица написаний — прежняя, если написания те же, в том же порядке: сборка на тысячах сущностей чата стоила
    десятки миллисекунд на каждый проход очистки каждой строки. Ключ — сами написания (сравнение, а не хэш). Прежние
    написания — начало новых (новые сущности чата) — к прежней таблице добавляются остальные, как при сборке с начала."""
    count = len(forms[0])
    with _cache_lock:
        for i, (key, compiled) in enumerate(_cache):
            if key == forms:
                _cache.append(_cache.pop(i))
                return compiled
        prefixes = [(key, compiled) for key, compiled in _cache if len(key[0]) < count]
    start = max(
        (key for key, _ in prefixes if all(now[:len(was)] == was for now, was in zip(forms, key))),
        key=lambda key: len(key[0]), default=None,
    )
    if start is None:
        compiled = Forms(zip(*forms))
    else:
        done = len(start[0])
        before = next(compiled for key, compiled in prefixes if key is start)
        compiled = before.extended(zip(*(now[done:] for now in forms)))
    with _cache_lock:
        _cache.append((forms, compiled))
        del _cache[:-_CACHE]
    return compiled


def detect(text: str, ctx: DetectContext) -> list[Span]:
    # Написания, режимы и нагрузки — тремя кортежами (_Key), а не кортежем на написание: ключи таблиц в памяти не
    # удлиняют каждую полную сборку мусора.
    always = [(form, entry.type) for entry in ctx.settings.always for form in (entry.value, *entry.aliases)]
    # Пользователь выделил фрагмент сам — ищем его везде, без оглядки на границы слов; правило смены типа —
    # с границами, с которыми искались написания до неё.
    forms: _Key = (
        tuple([form for form, _ in always] + [form for form, _ in ctx.known] + [form for form, _, _ in ctx.manual]),
        tuple([_mode(type_) for _, type_ in always] + [_mode(type_) for _, type_ in ctx.known]
              + [bounds for _, _, bounds in ctx.manual]),
        tuple([_PAYLOAD[type_, name] for _, type_ in always] + [_PAYLOAD[type_, name] for _, type_ in ctx.known]
              + [_PAYLOAD[type_, "manual"] for _, type_, _ in ctx.manual]),
    )
    spans = [Span(start, end, *_PAYLOADS[payload]) for start, end, payload in _compiled(forms).find(text)]
    for pattern in ctx.settings.patterns:
        try:
            for m in regex.finditer(pattern.regex, text, timeout=PATTERN_TIMEOUT):
                if m.end() > m.start():
                    spans.append(Span(m.start(), m.end(), pattern.type, name))
        except TimeoutError as exc:
            raise DetectorError(f"шаблон «{pattern.name}» выполняется слишком долго") from exc
    return spans
