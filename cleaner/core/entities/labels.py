"""Вид меток."""
from __future__ import annotations

import re

from cleaner.core.types import EntityType

_STYLES = {"angle": ("<", ">"), "square": ("[[", "]]")}

# Любая строка, оформленная как метка, — в том числе пришедшая извне.
SHAPE = re.compile(r"<[A-Z]+(?:_[A-Z]+)*_\d+>|\[\[[A-Z]+(?:_[A-Z]+)*_\d+\]\]")


def format_label(style: str, type_: EntityType, number: int) -> str:
    left, right = _STYLES[style]
    return f"{left}{type_.value}_{number}{right}"
