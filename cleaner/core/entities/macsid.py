"""Подмены MAC-адресов и SID."""
from __future__ import annotations

import re

SID = re.compile(r"S-1-5-21-(\d+-\d+-\d+)(?:-(\d+))?")


def mac_key(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value).lower()


def style_of(value: str) -> str:
    """Вид записи: разделитель и регистр, например ':U' или '-l'."""
    separator = "." if "." in value else ":" if ":" in value else "-" if "-" in value else ""
    return separator + ("U" if any(char in "ABCDEF" for char in value) else "l")


def fake_mac(number: int, style: str) -> str:
    """Адрес из локально администрируемого диапазона в заданном виде записи."""
    digits = f"020000{number:06x}"
    separator = style[:-1]
    step = 4 if separator == "." else 2
    text = separator.join(digits[i:i + step] for i in range(0, 12, step))
    return text.upper() if style.endswith("U") else text


def fake_sid_prefix(number: int) -> str:
    return f"S-1-5-21-1111111111-2222222222-{3333333330 + number}"
