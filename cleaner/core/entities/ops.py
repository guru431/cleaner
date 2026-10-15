"""Правки пользователя над состоянием чата. Действуют при следующей очистке."""
from __future__ import annotations

from cleaner.core.entities.names import FIXED_RANK
from cleaner.core.types import STRICT_TYPES, ChatRule, ChatState, Entity, EntityType


def _forget(state: ChatState, value: str) -> None:
    state.rules[:] = [rule for rule in state.rules if rule.value.lower() != value.lower()]


def mask(state: ChatState, value: str, type_: EntityType, bounds: str = "none") -> None:
    """Скрывать значение во всех текстах чата. Выделенное пользователем ищется где угодно (5.4)."""
    _forget(state, value)
    state.rules.append(ChatRule("mask", value, type_, bounds))


def unmask(state: ChatState, value: str) -> None:
    """Снять замену со значения во всех текстах чата. Прежняя замена остаётся восстановимой."""
    _forget(state, value)
    state.rules.append(ChatRule("unmask", value))


def set_restore_value(state: ChatState, entity_id: str, value: str) -> None:
    entity = state.entities[entity_id]
    entity.restore_value = value
    entity.restore_rank = FIXED_RANK        # разбор имён больше не меняет значение, заданное пользователем


def _original(state: ChatState, entity: Entity) -> str:
    """Значение из текста, которому выдана подмена сущности. Значение для восстановления мог задать пользователь."""
    for slot, fake in state.issued.items():
        surrogate = state.surrogates.get(fake)
        if slot.startswith(f"{entity.id}|") and surrogate is not None and surrogate.original:
            return surrogate.original
    return entity.restore_value


def retype(state: ChatState, entity_id: str, new_type: EntityType) -> None:
    """Сменить тип: написания переходят в правила с новым типом, старая метка остаётся в таблице.
    У средней части имени узла написаний нет (отдельно она не ищется) — в правило идёт её значение из текста."""
    entity = state.entities[entity_id]
    # Правило ищет то же, что искали до смены типа: значение правила — как прежде (выделенное — где угодно),
    # остальное — с границами известных значений прежнего типа. Без границ часть имени «corp» скрывала бы
    # «Corporate», а «db-corp-02.contoso.ru» поглощала целиком (5.4).
    kept = {rule.value.lower(): rule.bounds for rule in state.rules if rule.action == "mask"}
    bounds = "strict" if entity.type in STRICT_TYPES else "letters"
    for form in entity.forms or [_original(state, entity)]:
        mask(state, form, new_type, kept.get(form.lower(), bounds))
    entity.forms = []


def _final(state: ChatState, entity: Entity) -> Entity:
    """Сущность, в которую entity уже влита прежними объединениями, или она сама."""
    for _ in range(len(state.key_alias)):       # петля в таблице не зациклит
        target = state.entities.get(state.key_alias.get(f"{entity.type.value}:{entity.key}", ""))
        if target is None or target is entity:
            break
        entity = target
    return entity


def merge_entities(state: ChatState, keep_id: str, drop_id: str) -> None:
    """Дальше оба значения получают замену сущности keep."""
    keep, drop = state.entities[keep_id], state.entities[drop_id]
    if keep.type is not drop.type:
        raise ValueError("объединять можно только сущности одного типа")
    # Уже влитая сущность своей замены не выдаёт: объединение идёт с той, куда её влили, иначе
    # цепочка merge(a, b), merge(b, c) оставила бы c под меткой b, которой в тексте уже нет.
    keep, drop = _final(state, keep), _final(state, drop)
    if keep is drop:
        return
    keep.forms += [form for form in drop.forms if form not in keep.forms]
    drop.forms = []
    for value in [*drop.parts.values(), *drop.words]:
        if value not in keep.words and value not in keep.parts.values():
            keep.words.append(value)        # упоминания обоих написаний находят оставленную сущность (5.9)
    for key, target in state.key_alias.items():
        if target == drop.id:
            state.key_alias[key] = keep.id      # прежние объединения ведут туда же
    state.key_alias[f"{drop.type.value}:{drop.key}"] = keep.id
