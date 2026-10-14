from cleaner.core.entities import names, ops
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import restore
from cleaner.core.types import ChatState, Entity
from cleaner.core.types import EntityType as T


def masked(state, settings, text, *values):
    """Очистить текст, где значения помечены правилом «скрывать» — как будто их нашёл слой 4."""
    for value in values:
        ops.mask(state, value, T.PERSON)
    return sanitize(state, text, settings).sanitized


def test_parts_and_their_initial_forms():
    last, first, middle = names.parse("Иванову Ивану Ивановичу")
    assert ("last", "иванов") in last.options and ("first", "иван") in first.options
    assert ("middle", "иванович") in middle.options and not last.nominative
    (initial,) = names.parse("И.")
    assert initial.initial == "и"
    assert [word.options for word in names.parse("John Smith")] == [(("word", "john"),), (("word", "smith"),)]


def test_three_cases_of_one_name_get_one_label(state, settings):
    """AC-2.1, первая часть; FR-5.3."""
    text = "Иванов Иван Иванович написал. Позвоните Иванову Ивану Ивановичу. Нет Иванова Ивана Ивановича."
    result = masked(state, settings, text, "Иванов Иван Иванович", "Иванову Ивану Ивановичу", "Иванова Ивана Ивановича")
    assert result == "<PERSON_1> написал. Позвоните <PERSON_1>. Нет <PERSON_1>."


def test_lone_surname_joins_the_only_person_and_not_one_of_two(state, settings):
    """AC-2.1, вторая часть."""
    assert masked(state, settings, "Иванов Иван, потом Иванов", "Иванов Иван", "Иванов") == "<PERSON_1>, потом <PERSON_1>"
    other = ChatState(chat_id="other", net_key=bytes(32))
    text = "Иванов Иван и Иванов Пётр, а также Иванов"
    result = masked(other, settings, text, "Иванов Иван", "Иванов Пётр", "Иванов")
    assert result == "<PERSON_1> и <PERSON_2>, а также <PERSON_3>"


def test_different_first_names_stay_apart(state, settings):
    assert masked(state, settings, "Иванова Анна и Иванов Пётр", "Иванова Анна", "Иванов Пётр") == "<PERSON_1> и <PERSON_2>"


def test_initials_must_agree(state, settings):
    text = "Иванов Иван Петрович и И. П. Иванов, но не А. Иванов"
    result = masked(state, settings, text, "Иванов Иван Петрович", "И. П. Иванов", "А. Иванов")
    assert result == "<PERSON_1> и <PERSON_1>, но не <PERSON_2>"


def test_restore_value_is_the_fullest_nominative_form(state, settings):
    text = "Письмо от Петрова Сергея Николаевича. Петров Сергей Николаевич ответит."
    result = masked(state, settings, text, "Петрова Сергея Николаевича", "Петров Сергей Николаевич")
    assert result == "Письмо от <PERSON_1>. <PERSON_1> ответит."
    assert restore(state, "<PERSON_1>", settings).text == "Петров Сергей Николаевич"


def test_restore_value_set_by_the_user_is_kept(state, settings):
    masked(state, settings, "Петров", "Петров")
    entity = next(iter(state.entities.values()))
    ops.set_restore_value(state, entity.id, "Петров С. Н.")
    masked(state, settings, "Петров Сергей Николаевич", "Петров Сергей Николаевич")
    assert restore(state, "<PERSON_1>", settings).text == "Петров С. Н."


def test_latin_names_join_on_equal_words(state, settings):
    text = "John Smith wrote; Smith agreed; Mary Smith did not"
    result = masked(state, settings, text, "John Smith", "Smith", "Mary Smith")
    assert result == "<PERSON_1> wrote; <PERSON_1> agreed; <PERSON_2> did not"


def test_entity_from_an_earlier_version_gets_its_parts_from_its_forms(state):
    old = Entity("p1", T.PERSON, 1, "иванов иван", "Иванов Иван", "manual", ["Иванов Иван"])
    state.entities[old.id] = old
    assert names.compatible(names.parse("Иванову"), old)
    assert old.parts == {"last": "иванов", "first": "иван"}
