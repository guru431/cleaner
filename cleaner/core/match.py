"""Поиск известных написаний в тексте."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from typing import TypeVar

import regex

T = TypeVar("T")
_TOKEN = re.compile(r"[^\W\d_]+|\d+")
_PREFIX = 64        # написание длиннее ищется по началу такой длины (find_forms)
_SPACE_RUN = re.compile(r"\s+")
# Невидимые знаки: форматирующие (мягкий перенос, пробел нулевой ширины, метки направления) и знак
# ударения. Ударение выпадает, только если не вошло в букву при сборке NFC: у русских гласных букв
# с ударением нет, а «é» — одна буква и остаётся собой.
_STRESS = "\N{COMBINING ACUTE ACCENT}"
_FORMAT = regex.compile(r"\p{Cf}+")
_FORMAT_OR_STRESS = regex.compile(r"[\p{Cf}" + _STRESS + "]+")
# «\.» — точка: имя в регулярном выражении, шаблоне grep, настройке nginx («^srv01\.contoso\.ru$») — то же имя.
# Экранированная обратная косая («\\.») точку не экранирует.
_ESCAPED_DOT = re.compile(r"(?<!\\)\\(?=\.)")


def _lower(text: str) -> str:
    """Нижний регистр без изменения длины строки."""
    lowered = text.lower()
    if len(lowered) == len(text):
        return lowered
    return "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in text)


def _fold(char: str) -> str:
    low = char.lower()
    low = low if len(low) == 1 else char
    return "е" if low == "ё" else low


def _normalize_decomposed(text: str) -> tuple[str, list[int], list[int]]:
    """Медленный путь для текста не в NFC: буква с комбинирующими знаками собирается в одну.

    Ударение, которое в букву не вошло, выпадает, а буква накрывает его в исходном тексте.
    """
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            j = i + 1
            while j < n and text[j].isspace():
                j += 1
            chars.append(" ")
            starts.append(i)
            ends.append(j)
            i = j
            continue
        j = i + 1
        while j < n and unicodedata.combining(text[j]):
            j += 1
        for char in unicodedata.normalize("NFC", text[i:j]):
            if char != _STRESS:
                chars.append(_fold(char))
                starts.append(i)
                ends.append(j)
        i = j
    return "".join(chars), starts, ends


def _without(text: str, invisible: regex.Pattern[str]) -> tuple[str, list[int], list[int]]:
    """Нормализация текста без невидимых знаков; позиции — в исходном тексте.

    Знаки вырезаются одним проходом выражения, остальное идёт обычным путём. Знак накрывает и
    невидимые знаки за ним: ударение на последней букве уходит под замену вместе с ней.
    """
    pieces: list[str] = []
    origin: list[int] = []          # позиция каждого оставшегося знака в исходном тексте и конец текста
    position = 0
    for m in invisible.finditer(text):
        pieces.append(text[position:m.start()])
        origin.extend(range(position, m.start()))
        position = m.end()
    pieces.append(text[position:])
    origin.extend(range(position, len(text) + 1))
    lowered, starts, ends = _normalize("".join(pieces))
    return lowered, [origin[s] for s in starts], [origin[e] for e in ends]


def _normalize(text: str) -> tuple[str, list[int], list[int]]:
    """Текст для сравнения и границы каждого его знака в исходном тексте.

    Нижний регистр, «ё» как «е», буквы в NFC, любая цепочка пробельных знаков (в том числе
    неразрывный пробел и перевод строки) — один пробел, невидимых знаков и отдельного ударения нет.
    """
    nfc = unicodedata.is_normalized("NFC", text)
    # В тексте NFC отдельное ударение в букву уже не вошло; в остальном оно выпадает после сборки
    # букв медленным путём — иначе «e» с ударением перестала бы быть «é».
    invisible = _FORMAT_OR_STRESS if nfc else _FORMAT
    if invisible.search(text):
        return _without(text, invisible)
    if not nfc:
        return _normalize_decomposed(text)
    lowered = _lower(text).replace("ё", "е")
    pieces: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    position = 0
    for m in _SPACE_RUN.finditer(lowered):
        start, end = m.span()
        if start > position:
            pieces.append(lowered[position:start])
            starts.extend(range(position, start))
            ends.extend(range(position + 1, start + 1))
        pieces.append(" ")
        starts.append(start)
        ends.append(end)
        position = end
    if position < len(lowered):
        pieces.append(lowered[position:])
        starts.extend(range(position, len(lowered)))
        ends.extend(range(position + 1, len(lowered) + 1))
    return "".join(pieces), starts, ends


def normalize(text: str) -> str:
    """Та же нормализация, что при поиске, — для ключей сопоставления написаний."""
    return _normalize(text)[0].strip()


def has_invisible(text: str) -> bool:
    """Есть ли в тексте невидимые знаки или ударение, которые нормализация выбрасывает (с 15.10.2026)."""
    return _FORMAT_OR_STRESS.search(text) is not None


def _unescaped(lowered: str, starts: list[int], ends: list[int]) -> tuple[str, list[int], list[int]]:
    """Нормализованный текст, в котором «\\.» — точка (_ESCAPED_DOT): обратная косая выпадает, точка накрывает и её."""
    pieces: list[str] = []
    kept_starts: list[int] = []
    kept_ends: list[int] = []
    position = 0
    for m in _ESCAPED_DOT.finditer(lowered):
        slash = m.start()
        pieces += [lowered[position:slash], "."]
        kept_starts += [*starts[position:slash], starts[slash]]
        kept_ends += [*ends[position:slash], ends[slash + 1]]
        position = slash + 2
    pieces.append(lowered[position:])
    return "".join(pieces), kept_starts + starts[position:], kept_ends + ends[position:]


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
    """Все вхождения написаний без учёта регистра, «ё/е», вида пробелов и формы записи букв; «\\.» — точка.

    forms — тройки (написание, режим границ, полезная нагрузка). Режимы:
    strict — рядом нет букв, цифр, «_» и «-»; letters — рядом нет букв; none — где угодно.
    Позиции возвращаются в исходном тексте.
    """
    lowered, starts, ends = _normalize(text)
    if "\\." in lowered:
        lowered, starts, ends = _unescaped(lowered, starts, ends)
    # первое слово написания -> длина написания -> написание -> [(режим, нагрузка)].
    # Группировка по длине нужна, чтобы тысячи логинов с общим началом («user00001», «i.ivanov»)
    # проверялись одним обращением к словарю, а не перебором. Написание длиннее _PREFIX — по своему началу:
    # срез длиной в написание с каждого вхождения первого слова был бы квадратичным («a@bbb…b.ru» и тысячи «a»
    # в тексте), а сравнение с началом текста кончается на первом несовпавшем знаке.
    index: dict[str, dict[int, dict[str, list[tuple[str, T]]]]] = {}
    long: dict[str, dict[str, list[tuple[str, str, T]]]] = {}
    loose: list[tuple[str, str, T]] = []
    for form, mode, payload in forms:
        needle = _ESCAPED_DOT.sub("", _normalize(form)[0])
        if not needle.strip():
            continue
        head = _TOKEN.match(needle)
        if head and mode != "none" and len(needle) > _PREFIX:
            long.setdefault(head.group(), {}).setdefault(needle[:_PREFIX], []).append((needle, mode, payload))
        elif head and mode != "none":
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
                    hits.append((starts[start], ends[start + length - 1], payload))
        prefixes = long.get(token.group())
        for needle, mode, payload in prefixes.get(lowered[start:start + _PREFIX], ()) if prefixes else ():
            end = start + len(needle)
            if lowered.startswith(needle, start) and _bounded(lowered, start, end, mode):
                hits.append((starts[start], ends[end - 1], payload))
    for needle, mode, payload in loose:
        position = lowered.find(needle)
        while position != -1:
            end = position + len(needle)
            if _bounded(lowered, position, end, mode):
                hits.append((starts[position], ends[end - 1], payload))
            position = lowered.find(needle, position + 1)
    return hits
