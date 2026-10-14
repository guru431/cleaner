"""Проверка утечек: нет ли в тексте, который уходит наружу, известных оригиналов."""
from __future__ import annotations

from dataclasses import dataclass

from cleaner.core import surrogates
from cleaner.core.match import find_forms
from cleaner.core.types import STRICT_TYPES, ChatState, EntityType, Policy, Settings


@dataclass(frozen=True)
class Leak:
    start: int
    end: int
    entity_id: str | None      # None — значение из словаря организации


def _mode(type_: EntityType) -> str:
    return "strict" if type_ in STRICT_TYPES else "letters"


def check(text: str, state: ChatState, settings: Settings) -> list[Leak]:
    # Выданные замены вырезаются: подмена может случайно совпасть с настоящим значением.
    chars = list(text)
    for start, end in surrogates.find(state, text):
        chars[start:end] = " " * (end - start)
    open_values = settings.never | {r.value.lower() for r in state.rules if r.action == "unmask"}
    # Открытые значения тоже вырезаются: внутри открытого «srv-dc01.corp.contoso.ru» части
    # «srv-dc01» и «contoso.ru» — не утечка, их показали намеренно.
    for start, end, _ in find_forms("".join(chars), [(value, "none", None) for value in open_values]):
        chars[start:end] = " " * (end - start)
    forms: list[tuple[str, str, str | None]] = []
    for entity in state.entities.values():
        if settings.policies.get(entity.type) is Policy.OFF:
            continue
        forms += [(f, _mode(entity.type), entity.id) for f in entity.forms if f.lower() not in open_values]
    for entry in settings.always:
        if settings.policies.get(entry.type) is Policy.OFF:
            continue
        for form in (entry.value, *entry.aliases):
            if form.lower() not in open_values:
                forms.append((form, _mode(entry.type), None))
    found = {Leak(start, end, payload) for start, end, payload in find_forms("".join(chars), forms)}
    return sorted(found, key=lambda leak: (leak.start, leak.end))
