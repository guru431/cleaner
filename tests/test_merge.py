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


def test_partial_overlap_covers_the_union():
    spans = [Span(0, 10, T.PHONE, "rules"), Span(5, 16, T.CARD, "rules", validated=True)]
    assert merge("0123456789abcdef", spans, CTX) == [MergedSpan(0, 16, T.CARD, ("rules",))]


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
