"""Правки пользователя над состоянием чата. Действуют при следующей очистке."""
from __future__ import annotations

from cleaner.core.types import ChatRule, ChatState, EntityType


def _forget(state: ChatState, value: str) -> None:
    state.rules[:] = [rule for rule in state.rules if rule.value.lower() != value.lower()]


def mask(state: ChatState, value: str, type_: EntityType) -> None:
    """Скрывать значение во всех текстах чата."""
    _forget(state, value)
    state.rules.append(ChatRule("mask", value, type_))


def unmask(state: ChatState, value: str) -> None:
    """Снять замену со значения во всех текстах чата. Прежняя замена остаётся восстановимой."""
    _forget(state, value)
    state.rules.append(ChatRule("unmask", value))


def set_restore_value(state: ChatState, entity_id: str, value: str) -> None:
    state.entities[entity_id].restore_value = value


def retype(state: ChatState, entity_id: str, new_type: EntityType) -> None:
    """Сменить тип: написания переходят в правила с новым типом, старая метка остаётся в таблице."""
    entity = state.entities[entity_id]
    for form in entity.forms:
        mask(state, form, new_type)
    entity.forms = []


def merge_entities(state: ChatState, keep_id: str, drop_id: str) -> None:
    """Дальше оба значения получают замену сущности keep."""
    keep, drop = state.entities[keep_id], state.entities[drop_id]
    if keep.type is not drop.type:
        raise ValueError("объединять можно только сущности одного типа")
    keep.forms += [form for form in drop.forms if form not in keep.forms]
    drop.forms = []
    state.key_alias[f"{drop.type.value}:{drop.key}"] = keep.id
