import pytest

from cleaner.core.entities import ops
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import restore
from cleaner.core.types import EntityType as T


def test_unmask_then_mask_again(state, settings):
    sanitize(state, "узел 10.1.2.5", settings)
    ops.unmask(state, "10.1.2.5")
    assert sanitize(state, "узел 10.1.2.5", settings).sanitized == "узел 10.1.2.5"
    ops.mask(state, "10.1.2.5", T.IP)
    assert sanitize(state, "узел 10.1.2.5", settings).sanitized != "узел 10.1.2.5"
    assert [rule.action for rule in state.rules] == ["mask"]


def test_manual_mask_applies_to_every_occurrence_and_to_later_texts(state, settings):
    ops.mask(state, "Заря", T.TERM)
    first = sanitize(state, "Проект Заря. Сервер Заря-2.", settings)
    assert first.sanitized == "Проект <TERM_1>. Сервер <TERM_1>-2."
    assert sanitize(state, "снова Заря", settings).sanitized == "снова <TERM_1>"


def test_retype_gives_a_label_of_the_new_type_and_keeps_the_old_one_restorable(state, settings):
    ops.mask(state, "Ромашка", T.ORG)
    sanitize(state, "клиент Ромашка", settings)
    organisation = next(iter(state.entities.values()))
    ops.retype(state, organisation.id, T.PERSON)
    assert sanitize(state, "клиент Ромашка", settings).sanitized == "клиент <PERSON_1>"
    assert restore(state, "<ORG_1>", settings).text == "Ромашка"


def test_merged_entities_share_one_label(state, settings):
    ops.mask(state, "Иванов", T.PERSON)
    ops.mask(state, "Ivanov", T.PERSON)
    sanitize(state, "Иванов и Ivanov", settings)
    keep, drop = sorted(state.entities.values(), key=lambda entity: entity.number)
    ops.merge_entities(state, keep.id, drop.id)
    assert sanitize(state, "Иванов и Ivanov", settings).sanitized == "<PERSON_1> и <PERSON_1>"


def test_chained_merges_end_in_one_label(state, settings):
    """Обзор 1А, P2: после второго объединения все три написания ведут к одной сущности."""
    for name in ("Иванов", "Ivanov", "Сидоров"):
        ops.mask(state, name, T.PERSON)
    sanitize(state, "Иванов, Ivanov, Сидоров", settings)
    first, second, third = sorted(state.entities.values(), key=lambda entity: entity.number)
    ops.merge_entities(state, first.id, second.id)
    ops.merge_entities(state, third.id, first.id)
    result = sanitize(state, "Иванов, Ivanov, Сидоров", settings)
    assert result.sanitized == "<PERSON_3>, <PERSON_3>, <PERSON_3>"


def test_merging_into_an_already_merged_entity_joins_all_three(state, settings):
    """Находка «Merge chains»: объединение со влитой сущностью идёт в ту, куда её уже влили."""
    text = "a@x.example b@x.example c@x.example"
    sanitize(state, text, settings)
    a, b, c = sorted(state.entities.values(), key=lambda entity: entity.number)
    ops.merge_entities(state, a.id, b.id)
    ops.merge_entities(state, b.id, c.id)
    assert sanitize(state, text, settings).sanitized == "<EMAIL_1> <EMAIL_1> <EMAIL_1>"


def test_dropping_an_already_merged_entity_moves_its_whole_group(state, settings):
    text = "a@x.example b@x.example c@x.example"
    sanitize(state, text, settings)
    a, b, c = sorted(state.entities.values(), key=lambda entity: entity.number)
    ops.merge_entities(state, a.id, b.id)
    ops.merge_entities(state, c.id, b.id)
    assert sanitize(state, text, settings).sanitized == "<EMAIL_3> <EMAIL_3> <EMAIL_3>"


def test_merging_two_parts_of_one_group_changes_nothing(state, settings):
    """Сущность не вливается сама в себя: её написания не теряются."""
    text = "a@x.example b@x.example"
    sanitize(state, text, settings)
    a, b = sorted(state.entities.values(), key=lambda entity: entity.number)
    ops.merge_entities(state, a.id, b.id)
    ops.merge_entities(state, b.id, a.id)
    assert a.forms == ["a@x.example", "b@x.example"]
    assert sanitize(state, text, settings).sanitized == "<EMAIL_1> <EMAIL_1>"


def test_merging_different_types_is_refused(state, settings):
    ops.mask(state, "Заря", T.TERM)
    ops.mask(state, "Иванов", T.PERSON)
    sanitize(state, "Заря Иванов", settings)
    first, second = state.entities.values()
    with pytest.raises(ValueError):
        ops.merge_entities(state, first.id, second.id)


def test_restore_value_can_be_edited(state, settings):
    ops.mask(state, "Иванову", T.PERSON)
    result = sanitize(state, "передать Иванову", settings)
    ops.set_restore_value(state, result.spans[0].entity_id, "Иванов")
    assert restore(state, "<PERSON_1> ответит", settings).text == "Иванов ответит"
