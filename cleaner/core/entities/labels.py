"""Вид меток."""
from __future__ import annotations

import re
from functools import lru_cache

from cleaner.core.detect.base import load_builtin
from cleaner.core.entities import hostmap
from cleaner.core.types import ChatState, EntityType

_STYLES = {"angle": ("<", ">"), "square": ("[[", "]]")}

# Любая строка, оформленная как метка, — в том числе пришедшая извне.
SHAPE = re.compile(r"<[A-Z]+(?:_[A-Z]+)*_\d+>|\[\[[A-Z]+(?:_[A-Z]+)*_\d+\]\]")
_DOMAIN_NAME = re.compile(r"[\w-]+(?:\.[\w-]+)+")


def format_label(style: str, type_: EntityType, number: int) -> str:
    left, right = _STYLES[style]
    return f"{left}{type_.value}_{number}{right}"


@lru_cache(maxsize=65536)
def _domain_name(value: str) -> bool:
    """Значение метки — доменное имя (domain_labels). Ответ для значения не меняется, а спрашивают его при каждой сборке
    восстановления, и поток ответа собирает её на каждом куске (hostmap.has_known_suffix)."""
    return bool(_DOMAIN_NAME.fullmatch(value)) and hostmap.has_known_suffix(value) and not hostmap.code_like(
        value, load_builtin().ambiguous_suffixes
    )


def domain_labels(state: ChatState) -> set[str]:
    """Метки, которые стоят вместо доменного имени, — как выданы. Значение сущности — имя с точкой и известным суффиксом,
    которое слой 3 взял бы именем и в тексте (кусок имени, который задело выделение, — <TERM_1> из host-1.<TERM_1>; домен,
    которому дали другой тип, — <ORG_1> из host-1.<ORG_1>), а не файл или код (hostmap.code_like: deploy.sh, setup.py —
    .sh и .py тоже домены верхнего уровня), или метка кончает записанное имя (домен с неизвестным суффиксом из адреса
    ссылки). Доменом их считают и конвейер — имя рядом с меткой и адрес e-mail (5.4, 5.10), — и восстановление — хост
    ссылки (7)."""
    domains = set()
    for fake, surrogate in state.surrogates.items():
        if surrogate.kind == "label":
            if _domain_name(state.entities[surrogate.entity_id].restore_value):
                domains.add(fake)
        elif surrogate.kind == "host":
            last = fake.rsplit(".", 1)[-1]
            if last != fake and SHAPE.fullmatch(last):
                domains.add(last)
    return domains
