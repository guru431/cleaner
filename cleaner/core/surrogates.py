"""Поиск выданных замен в тексте."""
from __future__ import annotations

import re

from cleaner.core.types import ChatState, Surrogate

# Что не может стоять вплотную к замене данного вида.
_BOUNDS = {
    "label": ("", ""),
    "ip": (r"(?<![\w.])", r"(?!\w|\.\d)"),
    "ip6": (r"(?<![\w:])", r"(?![\w:])"),
    "host": (r"(?<![\w-])", r"(?![\w-])"),
    "mac": (r"(?<![\w:.-])", r"(?![\w:-])"),
    "sid": (r"(?<![\w-])", r"(?!\d)"),
}
_CASELESS = frozenset({"host", "mac", "ip6"})


def build_pattern(state: ChatState) -> re.Pattern[str] | None:
    """Одно выражение на все замены чата: длинные раньше коротких, у подмен — границы."""
    if not state.surrogates:
        return None
    parts = []
    for text, surrogate in sorted(state.surrogates.items(), key=lambda item: -len(item[0])):
        before, after = _BOUNDS[surrogate.kind]
        body = re.escape(text)
        if surrogate.kind in _CASELESS:
            body = f"(?i:{body})"
        parts.append(f"{before}{body}{after}")
    return re.compile("|".join(parts))


def caseless(state: ChatState) -> dict[str, Surrogate]:
    """Замены, которые ищутся без учёта регистра, по ключу в нижнем регистре."""
    return {text.lower(): s for text, s in state.surrogates.items() if s.kind in _CASELESS}


def find(state: ChatState, text: str) -> list[tuple[int, int]]:
    pattern = build_pattern(state)
    return [m.span() for m in pattern.finditer(text)] if pattern else []
