"""Словарь организации, известные значения чата, правила пользователя и его шаблоны."""
from __future__ import annotations

import regex

from cleaner.core.detect.base import DetectContext, DetectorError
from cleaner.core.match import find_forms
from cleaner.core.types import STRICT_TYPES, EntityType, Span

name = "dict"

PATTERN_TIMEOUT = 1.0   # секунд на один пользовательский шаблон


def _mode(type_: EntityType) -> str:
    return "strict" if type_ in STRICT_TYPES else "letters"


def detect(text: str, ctx: DetectContext) -> list[Span]:
    forms: list[tuple[str, str, tuple[EntityType, str]]] = []
    for entry in ctx.settings.always:
        for form in (entry.value, *entry.aliases):
            forms.append((form, _mode(entry.type), (entry.type, name)))
    forms += [(form, _mode(type_), (type_, name)) for form, type_ in ctx.known]
    # Пользователь выделил фрагмент сам — ищем его везде, без оглядки на границы слов; правило смены типа —
    # с границами, с которыми искались написания до неё.
    forms += [(form, bounds, (type_, "manual")) for form, type_, bounds in ctx.manual]
    spans = [Span(start, end, type_, source) for start, end, (type_, source) in find_forms(text, forms)]
    for pattern in ctx.settings.patterns:
        try:
            for m in regex.finditer(pattern.regex, text, timeout=PATTERN_TIMEOUT):
                if m.end() > m.start():
                    spans.append(Span(m.start(), m.end(), pattern.type, name))
        except TimeoutError as exc:
            raise DetectorError(f"шаблон «{pattern.name}» выполняется слишком долго") from exc
    return spans
