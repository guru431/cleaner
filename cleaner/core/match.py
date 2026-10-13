"""Поиск известных написаний в тексте."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TypeVar

T = TypeVar("T")
_TOKEN = re.compile(r"[^\W\d_]+|\d+")


def _lower(text: str) -> str:
    """Нижний регистр без изменения длины строки (позиции должны совпадать с оригиналом)."""
    lowered = text.lower()
    if len(lowered) == len(text):
        return lowered
    return "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in text)


def _bounded(text: str, start: int, end: int, mode: str) -> bool:
    if mode == "none":
        return True
    before = text[start - 1] if start else ""
    after = text[end] if end < len(text) else ""
    first, last = text[start], text[end - 1]
    if (before.isdigit() and first.isdigit()) or (after.isdigit() and last.isdigit()):
        return False        # число не вырезается из более длинного числа
    if mode == "letters":
        return not (before.isalpha() or after.isalpha())
    if before.isalnum() or before in ("_", "-") or after.isalnum() or after in ("_", "-"):
        return False
    if last.isdigit() and after == "." and text[end + 1:end + 2].isdigit():
        return False        # 10.1.2.3 внутри 10.1.2.3.4
    if first.isdigit() and before == "." and text[start - 2:start - 1].isdigit():
        return False
    return True


def find_forms(text: str, forms: Iterable[tuple[str, str, T]]) -> list[tuple[int, int, T]]:
    """Все вхождения написаний без учёта регистра.

    forms — тройки (написание, режим границ, полезная нагрузка). Режимы:
    strict — рядом нет букв, цифр, «_» и «-»; letters — рядом нет букв; none — где угодно.
    """
    lowered = _lower(text)
    # первое слово написания -> длина написания -> написание -> [(режим, нагрузка)].
    # Группировка по длине нужна, чтобы тысячи логинов с общим началом («user00001», «i.ivanov»)
    # проверялись одним обращением к словарю, а не перебором.
    index: dict[str, dict[int, dict[str, list[tuple[str, T]]]]] = {}
    loose: list[tuple[str, str, T]] = []
    for form, mode, payload in forms:
        needle = _lower(form)
        if not needle:
            continue
        head = _TOKEN.match(needle)
        if head and mode != "none":
            by_length = index.setdefault(head.group(), {})
            by_length.setdefault(len(needle), {}).setdefault(needle, []).append((mode, payload))
        else:
            loose.append((needle, mode, payload))
    hits: list[tuple[int, int, T]] = []
    for token in _TOKEN.finditer(lowered):
        start = token.start()
        for length, table in index.get(token.group(), {}).items():
            for mode, payload in table.get(lowered[start:start + length], ()):
                if _bounded(lowered, start, start + length, mode):
                    hits.append((start, start + length, payload))
    for needle, mode, payload in loose:
        position = lowered.find(needle)
        while position != -1:
            end = position + len(needle)
            if _bounded(lowered, position, end, mode):
                hits.append((position, end, payload))
            position = lowered.find(needle, position + 1)
    return hits
