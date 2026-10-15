import pytest

from cleaner.core.entities import ops
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import restore
from cleaner.core.types import Policy, Settings, default_policies
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


def test_retyping_the_domain_of_a_name_keeps_its_host_part(state, settings):
    text = "узел srv01.contoso.ru и srv01, сайт contoso.ru"
    sanitize(state, text, settings)
    domain = next(e for e in state.entities.values() if e.type is T.DOMAIN)
    ops.retype(state, domain.id, T.ORG)
    result = sanitize(state, text, settings)
    assert result.sanitized == "узел host-1.<ORG_1> и host-1, сайт <ORG_1>" and result.deliverable
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert restore(state, "host-1.<ORG_1>", settings).text == "srv01.contoso.ru"


# Часть имени, которой дан другой тип: первая, средняя, домен — и имя, которое получается после смены типа.
_RETYPED_PARTS = [
    ("узел srv01.contoso.ru", "srv01", "<{}_1>.domain-1.example"),
    ("узел srv-01.msk.contoso.ru", "msk", "host-1.<{}_1>.domain-1.example"),
    ("узел srv01.contoso.ru", "contoso.ru", "host-1.<{}_1>"),
]


def _retype_part(state, settings, text, key, type_):
    sanitize(state, text, settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == key).id, type_)
    return sanitize(state, text, settings)


@pytest.mark.parametrize("text, key, name", _RETYPED_PARTS, ids=["first", "middle", "domain"])
def test_hidden_part_keeps_the_whole_name_a_surrogate(state, settings, text, key, name):
    """Ревью 15.10.2026: часть с политикой «скрывать без восстановления» не восстанавливается и в составном имени,
    в каком бы месте она ни стояла (FR-7.7); имя остаётся заменой целиком, как отдельная метка."""
    name = name.format("SECRET")
    assert _retype_part(state, settings, text, key, T.SECRET).sanitized == f"узел {name}"
    result = restore(state, f"узел {name}", settings)
    assert (result.text, [s.kind for s in result.segments], result.counters["kept"]) == (
        f"узел {name}", ["kept_by_policy"], 1,
    )
    shown = Settings(policies={**default_policies(), T.SECRET: Policy.MASK})
    assert restore(state, f"узел {name}", shown).text == text           # без политики — имя из запроса


@pytest.mark.parametrize("text, key, name", _RETYPED_PARTS, ids=["first", "middle", "domain"])
def test_blocked_part_blocks_the_whole_name(state, text, key, name):
    """Ревью 15.10.2026: часть с политикой «блокировать» блокирует выдачу и в составном имени (FR-7.7), а сущность
    фрагмента — она: по ней блокировку показывает экран чата."""
    blocking = Settings(policies={**default_policies(), T.TERM: Policy.BLOCK})
    result = _retype_part(state, blocking, text, key, T.TERM)
    assert result.sanitized == f"узел {name.format('TERM')}" and not result.deliverable
    assert [state.entities[span.entity_id].type for span in result.blocked] == [T.TERM]
    assert sanitize(state, text, Settings()).deliverable


def test_values_set_by_the_user_apply_to_each_part_of_a_name_with_a_labelled_domain(state, settings):
    """Ревью 15.10.2026: имя с доменом-меткой (host-1.<ORG_1>) тоже собирается по частям — значение, заданное
    пользователем у части или у домена, меняет только её."""
    text = "узел srv01.contoso.ru и srv01, узел srv02.msk.contoso.ru, сайт contoso.ru"
    sanitize(state, text, settings)
    ops.retype(state, next(e for e in state.entities.values() if e.type is T.DOMAIN).id, T.ORG)
    result = sanitize(state, text, settings)
    assert result.sanitized == "узел host-1.<ORG_1> и host-1, узел host-2.sub-3.<ORG_1>, сайт <ORG_1>"
    answer = "host-1.<ORG_1>, host-2.sub-3.<ORG_1>"
    assert restore(state, answer, settings).text == "srv01.contoso.ru, srv02.msk.contoso.ru"
    entity = {e.key: e for e in state.entities.values()}
    ops.set_restore_value(state, entity["srv01"].id, "srv99")
    ops.set_restore_value(state, entity["msk"].id, "spb")
    assert restore(state, answer, settings).text == "srv99.contoso.ru, srv02.spb.contoso.ru"
    ops.set_restore_value(state, next(e for e in state.entities.values() if e.type is T.ORG).id, "fabrikam.ru")
    assert restore(state, answer, settings).text == "srv99.fabrikam.ru, srv02.spb.fabrikam.ru"
    assert restore(state, "<ORG_1>", settings).text == "fabrikam.ru"


def test_label_of_a_part_inside_a_foreign_name_is_derived(state, settings):
    """Ревью 15.10.2026: метка части в имени, которого не было в запросе, — выведенное имя, как host-1.evil.com;
    имя из запроса и отдельная метка — восстановленные."""
    _retype_part(state, settings, "узел srv01.contoso.ru и srv01", "srv01", T.TERM)
    for answer, expected in (
        ("<TERM_1>.evil.com", ("srv01.evil.com", ["derived"])),
        ("host-1.evil.com", ("srv01.evil.com", ["derived"])),
        ("<TERM_1>.domain-1.example", ("srv01.contoso.ru", ["restored"])),
        ("на <TERM_1>. Затем", ("на srv01. Затем", ["restored"])),
    ):
        result = restore(state, answer, settings)
        assert (result.text, [s.kind for s in result.segments]) == expected, answer


@pytest.mark.parametrize("value",["srv0", "contoso", "srv01.contoso", "srv01.contoso.ru"],
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
