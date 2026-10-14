"""Кодировка текстовых файлов (FR-2.4): метка порядка байтов, UTF-16 без метки, UTF-8, Windows-1251 или CP866."""
from __future__ import annotations

import codecs
import re

_BOMS = ((codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"))
# Старшие байты UTF-16 у латиницы, кириллицы, тире и «№»: других в журналах и конфигурациях не бывает.
_UTF16_HIGH = frozenset({0x00, 0x04, 0x20, 0x21})
_RUSSIAN = re.compile(r"[А-Яа-яЁё]")
_SAMPLE = 4096


class NotText(ValueError):
    """Файл не текстовый или его кодировку определить нельзя."""


def _utf16_without_bom(data: bytes) -> str | None:
    """В UTF-16 без метки каждый второй байт — один из немногих старших (0x00 у латиницы, 0x04 у кириллицы)."""
    sample = data[:_SAMPLE]
    if len(sample) < 8 or len(sample) % 2:
        return None
    for codec, high in (("utf-16-le", sample[1::2]), ("utf-16-be", sample[0::2])):
        if set(high) <= _UTF16_HIGH and high.count(0x00) + high.count(0x04) >= len(high) // 2:
            return codec
    return None


def _printable(text: str) -> bool:
    sample = text[:_SAMPLE]
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in sample) >= 0.95 * len(sample)


def _russian_share(text: str) -> float:
    rare = [ch for ch in text if ord(ch) > 127 and not ch.isspace()]
    return sum(1 for ch in rare if _RUSSIAN.match(ch)) / len(rare) if rare else 1.0


def decode(data: bytes) -> str:
    """Текст файла. NotText — для двоичного файла."""
    for bom, codec in _BOMS:
        if data.startswith(bom):
            try:
                return data.decode(codec)
            except UnicodeDecodeError:
                raise NotText("файл с меткой кодировки не декодируется") from None
    utf16 = _utf16_without_bom(data)
    if utf16:
        try:
            text = data.decode(utf16)
        except UnicodeDecodeError:
            text = ""
        if text and _printable(text):
            return text
    if b"\x00" in data[:_SAMPLE]:
        raise NotText("это двоичный файл")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.reason == "unexpected end of data":
            return data[:exc.start].decode("utf-8")      # файл обрезан посреди знака: последний знак неполный
    mixed = _utf8_with_foreign_lines(data)
    if mixed is not None:
        return mixed
    return _single_byte(data)[1]


def _single_byte(data: bytes) -> tuple[str, str]:
    """Однобайтовые кодировки декодируют любой файл: выбирает доля русских букв среди не-ASCII знаков."""
    candidates = []
    for codec in ("cp1251", "cp866"):
        try:
            text = data.decode(codec)
        except UnicodeDecodeError:
            continue
        candidates.append((_russian_share(text), codec == "cp1251", codec, text))
    if not candidates:
        raise NotText("кодировку определить не удалось")
    _, _, codec, text = max(candidates)
    return codec, text


def _utf8_with_foreign_lines(data: bytes) -> str | None:
    """Журнал в UTF-8, в который дописаны строки в Windows-1251 или CP866: каждая такая строка — своей кодировкой.

    Иначе одна чужая строка сделала бы однобайтовым весь файл, и русские слова остальных строк стали бы
    «кракозябрами», которых не находит ни один слой. None — строк UTF-8 с не-ASCII знаками нет.
    """
    lines = data.splitlines(keepends=True)
    decoded: list[str | None] = []
    utf8_seen = False
    for line in lines:
        try:
            decoded.append(line.decode("utf-8"))
        except UnicodeDecodeError:
            decoded.append(None)
            continue
        utf8_seen = utf8_seen or not line.isascii()
    if not utf8_seen:
        return None
    codec, _ = _single_byte(b"".join(line for line, text in zip(lines, decoded) if text is None))
    return "".join(text if text is not None else line.decode(codec, "replace") for line, text in zip(lines, decoded))
