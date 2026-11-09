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
    ctx = DetectContext(Settings(), known=(("ivanov", T.ACCOUNT),), manual=(("вано", T.TERM, "none"),))
    assert found("ivanov_backup и Иванов", ctx) == {
        (T.ACCOUNT, "ivanov", "dict"),
        (T.TERM, "вано", "manual"),
    }


def test_tables_kept_between_calls_follow_the_known_forms():
    """Задача 5a плана 5Г: таблица написаний берётся из памяти по самим написаниям: написание, добавленное после её
    сборки (в конце и перед правилами пользователя), находится, снятое — нет, и находки — в том же порядке, что у таблицы,
    собранной с начала."""
    text = "ivanov petrov sidorov Иванов"
    known = (("ivanov", T.ACCOUNT),)
    spans = lambda ctx: [(span.start, span.end, span.type, span.source) for span in dictionary.detect(text, ctx)]
    assert found(text, DetectContext(Settings(), known=known)) == {(T.ACCOUNT, "ivanov", "dict")}
    known += (("petrov", T.PERSON), ("Petrov", T.ACCOUNT))
    assert found(text, DetectContext(Settings(), known=known)) == {
        (T.ACCOUNT, "ivanov", "dict"), (T.PERSON, "petrov", "dict"), (T.ACCOUNT, "petrov", "dict"),
    }
    manual = (("вано", T.TERM, "none"),)
    assert found(text, DetectContext(Settings(), known=known + (("sidorov", T.ACCOUNT),), manual=manual)) == {
        (T.ACCOUNT, "ivanov", "dict"), (T.PERSON, "petrov", "dict"), (T.ACCOUNT, "petrov", "dict"),
        (T.ACCOUNT, "sidorov", "dict"), (T.TERM, "вано", "manual"),
    }
    assert found(text, DetectContext(Settings(), known=known[1:])) == {
        (T.PERSON, "petrov", "dict"), (T.ACCOUNT, "petrov", "dict"),
    }
    longer = DetectContext(Settings(), known=known + (("ivanov", T.PERSON),))
    before = spans(longer)
    dictionary._cache.clear()
    assert spans(longer) == before


def test_custom_pattern():
    ctx = DetectContext(Settings(patterns=(CustomPattern("инвентарный номер", r"INV-\d{6}", T.TERM),)))
    assert found("Ноутбук INV-004512", ctx) == {(T.TERM, "INV-004512", "dict")}


def test_slow_pattern_stops_the_layer(monkeypatch):
    monkeypatch.setattr(dictionary, "PATTERN_TIMEOUT", 0.1)
    ctx = DetectContext(Settings(patterns=(CustomPattern("плохой", r"^(a|aa)+$", T.TERM),)))
    with pytest.raises(DetectorError):
        dictionary.detect("a" * 40 + "!", ctx)


def test_known_number_added_later_is_found_by_digits_like_a_fresh_table():
    """FINDINGS «Известный чату номер в другой записи не скрывается…»: ключи номеров берутся из памяти вместе с таблицей
    написаний и дополняются новыми сущностями так же, как при сборке с начала; выделение пользователя по цифрам не ищется."""
    text = "ИНН 77 07 08 38 93, тел. 903 111-22-33"
    known = (("ivanov", T.ACCOUNT), ("7707083893", T.INN))
    assert found(text, DetectContext(Settings(), known=known)) == {(T.INN, "77 07 08 38 93", "dict")}
    longer = DetectContext(Settings(), known=known + (("+7 (903) 111-22-33", T.PHONE),))
    assert found(text, longer) == {(T.INN, "77 07 08 38 93", "dict"), (T.PHONE, "903 111-22-33", "dict")}
    before = [(span.start, span.end, span.type) for span in dictionary.detect(text, longer)]
    dictionary._cache.clear()
    assert [(span.start, span.end, span.type) for span in dictionary.detect(text, longer)] == before
    assert found(text, DetectContext(Settings(), manual=(("7707083893", T.INN, "none"),))) == set()


@pytest.mark.parametrize("type_, value, forms", [
    (T.PERSON, "Смирнова Анна Петровна", {"Смирновой Анне Петровне", "Смирновой Анны Петровны", "Смирнову Анну Петровну"}),
    (T.TERM, "Проект Полярис", {"Проекту Полярис", "Проекте Полярис", "Проекта Полярис"}),
    (T.ADDRESS, "Красная площадь", {"Красной площади", "Красной площадью"}),
    (T.ORG, "Министерство финансов", {"Министерства финансов", "Министерству финансов"}),
], ids=["person", "term", "address", "org"])
def test_inflected_forms_of_a_dictionary_entry(type_, value, forms):
    """IDEAS «Словарь: падежные формы для людей, организаций и терминов»: формы — косвенные падежи всей фразы и, кроме
    людей, её начала до первого существительного. Слова в кавычках, сокращения и латиница не склоняются; у прочих типов
    форм нет."""
    assert forms <= set(dictionary.inflected(type_, value))
    assert value not in dictionary.inflected(type_, value)
    assert dictionary.inflected(T.ORG, "ООО «Ромашка»") == ()
    assert dictionary.inflected(T.HOST, "Проект") == ()
    entry = dictionary.entry(type_, value, ("Вариант",), True)
    assert entry.aliases[0] == "Вариант" and forms <= set(entry.aliases)
    assert dictionary.entry(type_, value, ("Вариант",), False) == DictEntry(type_, value, ("Вариант",))
