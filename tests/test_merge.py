import re

from cleaner.core.detect.base import DetectContext
from cleaner.core.detect.merge import MergedSpan, merge
from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy, Settings, Span, default_policies

CTX = DetectContext(Settings())


def test_overlapping_fragments_become_one_with_the_senior_type():
    spans = [
        Span(0, 19, T.EMAIL, "rules", validated=True),
        Span(9, 19, T.DOMAIN, "infra"),
        Span(2, 8, T.ACCOUNT, "dict"),
    ]
    assert merge("i.ivanov@contoso.ru", spans, CTX) == [MergedSpan(0, 19, T.EMAIL, ("rules", "dict", "infra"))]


def test_secret_outranks_everything_except_a_manual_rule():
    spans = [Span(6, 15, T.SECRET, "secrets"), Span(6, 15, T.TERM, "dict")]
    assert merge("token=abc123def", spans, CTX)[0].type is T.SECRET
    spans.append(Span(6, 15, T.TERM, "manual"))
    assert merge("token=abc123def", spans, CTX)[0].type is T.TERM


def test_manual_rule_on_a_whole_part_of_a_name_keeps_the_name_type():
    """Правило на целой части имени узла режет его при подмене (resolve), а не поглощает (5.7, шаг 4)."""
    text = "srv01.corp.contoso.ru"
    for manual, expected in (
        ((0, 5), T.HOST), ((6, 10), T.HOST), ((11, 21), T.HOST),         # первая, средняя часть, домен
        ((0, 4), T.TERM), ((11, 18), T.TERM), ((0, 10), T.TERM),         # не целая часть — как прежде
    ):
        spans = [Span(0, 21, T.HOST, "infra"), Span(*manual, T.TERM, "manual")]
        assert merge(text, spans, CTX)[0].type is expected, manual


def test_manual_rule_on_a_whole_part_of_an_email_domain_keeps_the_email():
    """Имя после «@» — тоже имя (5.7, шаг 4): правило на его целой части адрес не поглощает, а на части имени входа
    или не на целой части — поглощает, как прежде."""
    text = "ivanov@srv01.contoso.ru"
    for manual, expected in (((7, 12), T.EMAIL), ((13, 23), T.EMAIL), ((7, 11), T.TERM), ((0, 6), T.TERM)):
        spans = [Span(0, 23, T.EMAIL, "rules", validated=True), Span(*manual, T.TERM, "manual")]
        assert merge(text, spans, CTX)[0].type is expected, manual


def test_rule_on_a_part_of_an_email_with_a_stricter_policy_swallows_the_email():
    """Обзор пакета, Important: адрес, оставшийся адресом при правиле на целой части имени, терял политику этой части —
    метка EMAIL не блокировала выдачу и восстанавливалась целиком. Правило типа со строже политикой адрес поглощает,
    как прежде; с той же или мягче — адрес остаётся адресом (5.7, шаг 4)."""
    text = "ivanov@srv01.contoso.ru"
    strict = default_policies() | {T.SECRET: Policy.BLOCK}
    for rule, policies, expected in (
        (T.SECRET, default_policies(), T.SECRET), (T.SECRET, strict, T.SECRET), (T.TERM, strict, T.EMAIL),
        (T.SECRET, default_policies() | {T.EMAIL: Policy.HIDE}, T.EMAIL),
        (T.SECRET, strict | {T.EMAIL: Policy.BLOCK}, T.EMAIL),
    ):
        spans = [Span(0, 23, T.EMAIL, "rules", validated=True), Span(7, 12, rule, "manual")]
        assert merge(text, spans, DetectContext(Settings(policies=policies)))[0].type is expected, (rule, policies)


def test_rule_swallowing_a_name_records_where_it_lies():
    """Конвейер оставит выданную замену в имени и отдаст правилу только задетые им части (5.10)."""
    [merged] = merge("host-1.fabrikam.ru", [Span(0, 18, T.HOST, "infra"), Span(7, 15, T.TERM, "manual")], CTX)
    assert (merged.type, merged.ruled) == (T.TERM, ((7, 15, T.TERM),))
    [kept] = merge("srv01.contoso.ru", [Span(0, 16, T.HOST, "infra"), Span(0, 5, T.TERM, "manual")], CTX)
    assert (kept.type, kept.ruled) == (T.HOST, ())
    [alone] = merge("Проект Заря", [Span(7, 11, T.TERM, "manual")], CTX)
    assert (alone.type, alone.ruled) == (T.TERM, ())
    # Адрес e-mail — так же; конвейер поделит его по «@» на имя входа и части имени.
    email = [Span(0, 25, T.EMAIL, "rules", validated=True), Span(14, 22, T.TERM, "manual")]
    [mail] = merge("ivanov@host-1.fabrikam.ru", email, CTX)
    assert (mail.type, mail.ruled, mail.mail, merged.mail) == (T.TERM, ((14, 22, T.TERM),), True, False)


def test_rule_off_whole_parts_keeps_the_stricter_policy_of_the_record_it_swallows():
    """Второе ревью, Minor: правило не на целых частях поглощало адрес или имя и давало ему свой тип — «contoso» (TERM) в
    ivanov@srv.contoso.ru при EMAIL=BLOCK давал <TERM_1>, и выдача не блокировалась, а при EMAIL=HIDE метка
    восстанавливалась целиком. Фрагмент берёт тип того из двух — записи или правила, — чья политика строже; при равных —
    правила, как прежде. Где лежат правила и их типы, фрагмент помнит: части рядом с выданной заменой получат тип правила."""
    for text, record, rule_at in (("ivanov@srv.contoso.ru", T.EMAIL, (11, 18)), ("srv.contoso.ru", T.HOST, (4, 11))):
        for changed, expected in (
            ({}, T.TERM), ({record: Policy.BLOCK}, record), ({record: Policy.HIDE}, record),
            ({record: Policy.HIDE, T.TERM: Policy.BLOCK}, T.TERM), ({record: Policy.HIDE, T.TERM: Policy.HIDE}, T.TERM),
        ):
            spans = [Span(0, len(text), record, "rules", validated=True), Span(*rule_at, T.TERM, "manual")]
            [merged] = merge(text, spans, DetectContext(Settings(policies=default_policies() | changed)))
            assert (merged.type, merged.ruled, merged.mail) == (expected, ((*rule_at, T.TERM),), record is T.EMAIL), changed
    # Цена: смена типа всей записи при строже политике записи ничего не меняет.
    spans = [Span(0, 14, T.HOST, "infra"), Span(0, 14, T.TERM, "manual")]
    blocked = DetectContext(Settings(policies=default_policies() | {T.HOST: Policy.BLOCK}))
    assert merge("srv.contoso.ru", spans, blocked)[0].type is T.HOST


def test_partial_overlap_covers_the_union():
    spans = [Span(0, 10, T.PHONE, "rules"), Span(5, 16, T.CARD, "rules", validated=True)]
    assert merge("0123456789abcdef", spans, CTX) == [
        MergedSpan(0, 16, T.CARD, ("rules",), searchable=False, forms=("56789abcdef",)),
    ]


def test_union_of_findings_none_of_which_covers_it_keeps_their_spellings():
    """Наблюдение раунда имён узлов, P2: пересекающиеся известные значения («Иван Иван» в «Иван Иван Иван …», правило
    «la la» в «la la la …») сливались в один фрагмент, и его текст становился искомым написанием длиной в цепочку. Он
    скрыт одной заменой, а искомы написания находок; находка на весь фрагмент — как прежде."""
    text = "Иван Иван Иван Иван"
    spans = [Span(start, start + 9, T.PERSON, "dict") for start in (0, 5, 10)]
    assert merge(text, spans, CTX) == [MergedSpan(0, 19, T.PERSON, ("dict",), searchable=False, forms=("Иван Иван",))]
    spans.append(Span(0, 19, T.ORG, "ner"))
    assert merge(text, spans, CTX) == [MergedSpan(0, 19, T.PERSON, ("ner", "dict"))]
    # Искомы только находки старшего типа, которые были бы искомыми и сами.
    spans = [Span(0, 9, T.SECRET, "secrets", searchable=False), Span(5, 14, T.SECRET, "secrets"), Span(8, 19, T.IP, "infra")]
    assert merge(text, spans, CTX) == [
        MergedSpan(0, 19, T.SECRET, ("secrets", "infra"), searchable=False, forms=("Иван Иван",)),
    ]


def test_touching_fragments_stay_separate():
    spans = [Span(0, 7, T.DOMAIN, "infra"), Span(8, 14, T.ACCOUNT, "infra")]
    assert [(m.start, m.end) for m in merge(r"CONTOSO\ivanov", spans, CTX)] == [(0, 7), (8, 14)]


def test_never_list_and_unmask_rule_drop_exact_values_only():
    text = "microsoft.com и srv.microsoft.com и contoso.ru"
    spans = [Span(0, 13, T.DOMAIN, "infra"), Span(16, 33, T.HOST, "infra"), Span(36, 46, T.DOMAIN, "infra")]
    ctx = DetectContext(Settings(never=frozenset({"microsoft.com"})), unmask=frozenset({"contoso.ru"}))
    assert [(m.start, m.end) for m in merge(text, spans, ctx)] == [(16, 33)]


def test_manual_rule_survives_the_never_list():
    ctx = DetectContext(Settings(never=frozenset({"contoso.ru"})))
    assert len(merge("contoso.ru", [Span(0, 10, T.DOMAIN, "manual")], ctx)) == 1


def test_types_switched_off_are_dropped():
    ctx = DetectContext(Settings(policies=default_policies() | {T.MAC: Policy.OFF}))
    assert merge("00:1A:2B:3C:4D:5E", [Span(0, 17, T.MAC, "infra")], ctx) == []


def test_name_parts_side_by_side_become_one_person():
    text = "Иванов Иван Иванович"
    spans = [Span(0, 6, T.PERSON, "ner"), Span(7, 11, T.PERSON, "ner"), Span(12, 20, T.PERSON, "dict")]
    assert merge(text, spans, CTX) == [MergedSpan(0, 20, T.PERSON, ("ner", "dict"))]


def test_run_of_names_longer_than_four_words_is_not_joined():
    """Наблюдение раунда имён узлов, P2: ряд фамилий через пробел («Иванов Петров Сидоров …») сливался в один PERSON
    длиной в ряд, и его текст становился искомым написанием. Имя — до четырёх слов («Ильхам Гейдар оглы Алиев»,
    «Иванов И. И.»); ряд длиннее — список людей, и части остаются как найдены."""
    def joined(text):
        spans = [Span(m.start(), m.end(), T.PERSON, "ner") for m in re.finditer(r"[^\W\d_]{2,}", text)]
        return [text[m.start:m.end] for m in merge(text, spans, CTX)]

    assert joined("Ильхам Гейдар оглы Алиев") == ["Ильхам Гейдар оглы Алиев"]
    assert joined("Иванов Петров Сидоров Козлов Морозов") == ["Иванов", "Петров", "Сидоров", "Козлов", "Морозов"]
    assert joined("Иванов И. И. Петров П. П.") == ["Иванов И. И.", "Петров П. П."]
    assert joined("Иванов Петров, Сидоров Козлов Морозов Волков Зайцев.") == [
        "Иванов Петров", "Сидоров", "Козлов", "Морозов", "Волков", "Зайцев",
    ]
    # Ряд, в котором часть — слияние пересекающихся находок: она не искома, и слитое имя хранит её написания.
    text = "Иван Иван Иван Петров"
    spans = [Span(0, 9, T.PERSON, "dict"), Span(5, 14, T.PERSON, "dict"), Span(15, 21, T.PERSON, "ner")]
    assert merge(text, spans, CTX) == [
        MergedSpan(0, 21, T.PERSON, ("dict", "ner"), searchable=False, forms=("Иван Иван", "Петров")),
    ]


def test_initials_next_to_a_name_join_it():
    for text, span, expected in (
        ("Иванов И.И. пришёл", Span(0, 6, T.PERSON, "ner"), (0, 11)),
        ("Иванов И. И. пришёл", Span(0, 6, T.PERSON, "ner"), (0, 12)),
        ("пришёл И.И. Иванов", Span(12, 18, T.PERSON, "ner"), (7, 18)),
        ("от J. Smith", Span(6, 11, T.PERSON, "ner"), (3, 11)),
    ):
        [merged] = merge(text, [span], CTX)
        assert (merged.start, merged.end) == expected, text


def test_initial_marked_without_its_dot_joins_the_surname():
    text = "И. Иванов пришёл"
    assert merge(text, [Span(0, 1, T.PERSON, "ner"), Span(3, 9, T.PERSON, "ner")], CTX) == [MergedSpan(0, 9, T.PERSON, ("ner",))]


def test_sentence_end_list_and_other_types_are_not_joined():
    text = "Ответил Иванов. В итоге a@x.example"
    spans = [Span(8, 14, T.PERSON, "ner"), Span(24, 35, T.EMAIL, "rules", validated=True)]
    assert [(m.start, m.end) for m in merge(text, spans, CTX)] == [(8, 14), (24, 35)]
    text = "Иванову и Петрову"
    spans = [Span(0, 7, T.PERSON, "ner"), Span(10, 17, T.PERSON, "ner")]
    assert [(m.start, m.end) for m in merge(text, spans, CTX)] == [(0, 7), (10, 17)]
    text = "Писал Петров Сергей. Иванов Иван согласен"
    spans = [Span(6, 19, T.PERSON, "ner"), Span(21, 32, T.PERSON, "ner")]
    assert [(m.start, m.end) for m in merge(text, spans, CTX)] == [(6, 19), (21, 32)]
