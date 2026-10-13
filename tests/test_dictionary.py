import pytest

from cleaner.core.detect import dictionary
from cleaner.core.detect.base import DetectContext, DetectorError
from cleaner.core.types import CustomPattern, DictEntry, Settings
from cleaner.core.types import EntityType as T


def found(text: str, ctx: DetectContext) -> set[tuple[T, str, str]]:
    return {(span.type, text[span.start:span.end], span.source) for span in dictionary.detect(text, ctx)}


def test_dictionary_value_and_alias():
    ctx = DetectContext(Settings(always=(DictEntry(T.ORG, "Ромашка", ("Romashka",)),)))
    assert found("ООО «Ромашка» (Romashka LLC)", ctx) == {
        (T.ORG, "Ромашка", "dict"),
        (T.ORG, "Romashka", "dict"),
    }


def test_known_forms_and_manual_rules():
    ctx = DetectContext(Settings(), known=(("ivanov", T.ACCOUNT),), manual=(("вано", T.TERM),))
    assert found("ivanov_backup и Иванов", ctx) == {
        (T.ACCOUNT, "ivanov", "dict"),
        (T.TERM, "вано", "manual"),
    }


def test_custom_pattern():
    ctx = DetectContext(Settings(patterns=(CustomPattern("инвентарный номер", r"INV-\d{6}", T.TERM),)))
    assert found("Ноутбук INV-004512", ctx) == {(T.TERM, "INV-004512", "dict")}


def test_slow_pattern_stops_the_layer(monkeypatch):
    monkeypatch.setattr(dictionary, "PATTERN_TIMEOUT", 0.1)
    ctx = DetectContext(Settings(patterns=(CustomPattern("плохой", r"^(a|aa)+$", T.TERM),)))
    with pytest.raises(DetectorError):
        dictionary.detect("a" * 40 + "!", ctx)
