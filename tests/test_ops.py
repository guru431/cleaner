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


@pytest.mark.parametrize("text, expected", [
    ("узел srv01.contoso.ru и srv01", "узел <TERM_1>.domain-1.example и <TERM_1>"),
    ("узел srv01.corp.contoso.ru и srv01", "узел <TERM_1>.sub-2.domain-1.example и <TERM_1>"),
], ids=["host-domain", "host-sub-domain"])
def test_retyping_a_host_part_keeps_the_rest_of_the_name(state, settings, text, expected):
    """Решение владельца 15.10.2026: тип меняется только у части, строение полного имени остаётся (5.7)."""
    sanitize(state, text, settings)
    host = next(e for e in state.entities.values() if e.key == "srv01")
    ops.retype(state, host.id, T.TERM)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    assert sanitize(state, text, settings).sanitized == expected          # тот же оригинал — тот же результат
    assert sanitize(state, expected, settings).sanitized == expected      # повторная вставка (5.10)
    restored = restore(state, expected.split()[1], settings)
    assert (restored.text, [s.kind for s in restored.segments]) == (text.split()[1], ["restored"])  # имя из запроса
    assert restore(state, "<TERM_1>", settings).text == "srv01"


def test_retyping_a_middle_part_of_a_name_takes_effect(state, settings):
    """Средняя часть отдельно не ищется и написаний не имеет: в правило идёт её значение для восстановления."""
    text = "узел srv-01.msk.contoso.ru"
    sanitize(state, text, settings)
    part = next(e for e in state.entities.values() if e.key == "msk")
    ops.retype(state, part.id, T.TERM)
    result = sanitize(state, text, settings)
    assert result.sanitized == "узел host-1.<TERM_1>.domain-1.example" and result.deliverable
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert restore(state, "host-1.<TERM_1>.domain-1.example", settings).text == "srv-01.msk.contoso.ru"
    term = next(e for e in state.entities.values() if e.type is T.TERM)
    ops.set_restore_value(state, term.id, "spb")         # имя целиком — с заданным значением части
    assert restore(state, "host-1.<TERM_1>.domain-1.example", settings).text == "srv-01.spb.contoso.ru"


def test_retyping_a_part_after_editing_its_restore_value_takes_the_value_from_the_text(state, settings):
    """Обзор, Minor 5: значение для восстановления мог задать пользователь. Правило на него оставило бы часть
    своей подменой, а заданное значение скрывалось бы во всём чате."""
    text = "узел srv-01.msk.contoso.ru, офис spb"
    sanitize(state, text, settings)
    part = next(e for e in state.entities.values() if e.key == "msk")
    ops.set_restore_value(state, part.id, "spb")
    ops.retype(state, part.id, T.TERM)
    assert sanitize(state, text, settings).sanitized == "узел host-1.<TERM_1>.domain-1.example, офис spb"


@pytest.mark.parametrize("text, key, probe, expected", [
    ("узел srv01.corp.contoso.ru", "corp",
     "узел srv01.corp.contoso.ru, corp wiki, Corporate policy, узел db-corp-02.contoso.ru",
     "узел host-1.<TERM_1>.domain-1.example, <TERM_1> wiki, Corporate policy, узел host-3.domain-1.example"),
    ("портал intranet.contoso.ru", "intranet",
     "Open the intranet, then the intranets page, intranet.contoso.ru",
     "Open the <TERM_1>, then the intranets page, <TERM_1>.domain-1.example"),
    ("узел srv-01.msk.contoso.ru", "msk",
     "Tomsk, msk, srv-01.msk.contoso.ru", "Tomsk, <TERM_1>, host-1.<TERM_1>.domain-1.example"),
], ids=["middle-part", "leading-part", "short-part"])
def test_a_rule_from_retyping_a_name_part_is_searched_within_bounds(state, settings, text, key, probe, expected):
    """Обзор, Minor 6: правило смены типа ищется с границами имени узла (5.4) — часть находится внутри полного
    имени и отдельно, но не внутри чужого слова и другого имени."""
    sanitize(state, text, settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == key).id, T.TERM)
    result = sanitize(state, probe, settings)
    assert result.sanitized == expected and result.deliverable


def test_a_rule_from_retyping_keeps_the_bounds_its_values_were_searched_with(state, settings):
    """Написания, найденные выделением, и после смены типа ищутся где угодно; найденные как известные значения —
    с границами своего типа: логин — рядом нет букв (5.4)."""
    ops.mask(state, "Заря", T.ORG)
    sanitize(state, "проект Заря, вход CONTOSO\\ivanov", settings)
    for entity in list(state.entities.values()):
        if entity.type in (T.ORG, T.ACCOUNT):
            ops.retype(state, entity.id, T.TERM)
    result = sanitize(state, "Зарядка, ivanov_backup, ivanova", settings)
    assert result.sanitized == "<TERM_1>дка, <TERM_2>_backup, ivanova"


def test_a_rule_from_a_selection_is_searched_anywhere(state, settings):
    """Выделенное пользователем скрывается и внутри слова (5.4), в отличие от правила смены типа."""
    ops.mask(state, "corp", T.TERM)
    assert sanitize(state, "Corporate policy", settings).sanitized == "<TERM_1>orate policy"


def test_retyping_the_domain_of_a_name_keeps_its_host_part(state, settings):
    text = "узел srv01.contoso.ru и srv01, сайт contoso.ru"
    sanitize(state, text, settings)
    domain = next(e for e in state.entities.values() if e.type is T.DOMAIN)
    ops.retype(state, domain.id, T.ORG)
    result = sanitize(state, text, settings)
    assert result.sanitized == "узел host-1.<ORG_1> и host-1, сайт <ORG_1>" and result.deliverable
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert restore(state, "host-1.<ORG_1>", settings).text == "srv01.contoso.ru"


@pytest.mark.parametrize("value", ["srv0", "contoso", "srv01.contoso", "srv01.contoso.ru"],
                         ids=["inside-part", "half-domain", "two-parts", "whole"])
def test_rule_off_the_part_boundaries_still_takes_the_whole_name(state, settings, value):
    """Не целая часть имени — как прежде: старший тип правила поглощает имя целиком (FR-3.3)."""
    ops.mask(state, value, T.TERM)
    assert sanitize(state, "узел srv01.contoso.ru", settings).sanitized == "узел <TERM_1>"


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
