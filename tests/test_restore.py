import pytest

from cleaner.core.pipeline import sanitize
from cleaner.core.restore import RestoreResult, restore
from cleaner.core.types import ChatState, Entity, Settings, Surrogate
from cleaner.core.types import EntityType as T


def person_state(style: str = "angle") -> ChatState:
    state = ChatState(chat_id="people", net_key=bytes(range(32)), label_style=style)
    left, right = ("<", ">") if style == "angle" else ("[[", "]]")
    for number, name in ((1, "Иван Петров"), (10, "Пётр Сидоров")):
        entity = Entity(f"p{number}", T.PERSON, number, name.lower(), name, "manual", [name])
        state.entities[entity.id] = entity
        state.surrogates[f"{left}PERSON_{number}{right}"] = Surrogate(entity.id)
    return state


def infra_state() -> ChatState:
    state = ChatState(chat_id="infra", net_key=bytes(range(32)))
    text = "srv-web01.corp.contoso.ru, адрес 10.1.2.5, MAC 00:1A:2B:3C:4D:5E, пароль: Qwerty123!"
    sanitize(state, text, Settings())
    return state


def kinds(result: RestoreResult) -> list[str]:
    return [segment.kind for segment in result.segments]


def test_altered_labels_are_restored_and_unknown_ones_are_marked(settings):
    answer = (
        r"A: \<PERSON\_1\>, B: &lt;PERSON_1&gt;, C: PERSON_1, "
        r"D: <PERSON_1> и <PERSON_10>, E: <PERSON_99>"
    )
    result = restore(person_state(), answer, settings)
    assert result.text == (
        "A: Иван Петров, B: Иван Петров, C: Иван Петров, D: Иван Петров и Пётр Сидоров, E: <PERSON_99>"
    )
    assert (result.counters["restored"], result.counters["altered"], result.counters["unknown"]) == (2, 3, 1)


def test_two_labels_never_get_the_same_value(settings):
    result = restore(person_state(), "<PERSON_1> пишет <PERSON_10>, а PERSON_10 отвечает PERSON_1", settings)
    assert result.text == "Иван Петров пишет Пётр Сидоров, а Пётр Сидоров отвечает Иван Петров"


def test_square_style_is_not_read_as_a_character_class(settings):
    result = restore(person_state("square"), "Отчёт подготовил [[PERSON_1]].", settings)
    assert result.text == "Отчёт подготовил Иван Петров."


def test_backslashes_in_the_original_survive(settings):
    state = person_state()
    state.entities["p1"].restore_value = r"C:\Users\ivanov"
    assert restore(state, "путь <PERSON_1>", settings).text == r"путь C:\Users\ivanov"


def test_label_in_another_style_is_still_recognised(settings):
    result = restore(person_state(), "Пишет [[PERSON_1]]", settings)
    assert (result.text, kinds(result)) == ("Пишет Иван Петров", ["altered"])


def test_label_inside_a_foreign_link_is_not_restored(settings):
    answer = "Откройте https://evil.example.org/collect?name=<PERSON_1> и напишите <PERSON_1>."
    result = restore(person_state(), answer, settings)
    assert result.text == "Откройте https://evil.example.org/collect?name=<PERSON_1> и напишите Иван Петров."
    assert kinds(result) == ["foreign_link", "restored"]


@pytest.mark.parametrize(
    "answer",
    [
        "Откройте https://<PERSON_1>.evil.example.org/c?x=<PERSON_10>",
        '[отчёт](https://evil.example.org/c?x="<PERSON_1>")',
        '<a href="https://evil.example.org/c?x=<PERSON_1>">отчёт</a>',
        "[написать](mailto:boss@evil.example.org?body=<PERSON_1>)",
        "mailto:boss@evil.example.org?body=<PERSON_1>",
    ],
)
def test_labels_inside_foreign_links_stay_labels(settings, answer):
    """Обзор 1А, P1 (FR-7.8): метка в имени узла, значение в кавычках, атрибут HTML, mailto."""
    result = restore(person_state(), answer, settings)
    assert "Иван Петров" not in result.text and "Пётр Сидоров" not in result.text
    assert "foreign_link" in kinds(result)


def test_known_host_part_under_a_foreign_domain_is_not_restored(settings):
    """Обзор 1А, P1: ссылка наша, только если её хост целиком собран из выданных подмен."""
    answer = "Откройте https://host-1.attacker.org/?q=sub-2.domain-1.example"
    result = restore(infra_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


def test_mailto_link_to_our_own_address_is_restored(settings):
    state = person_state()
    entity = Entity("e1", T.EMAIL, 1, "i.ivanov@contoso.ru", "i.ivanov@contoso.ru", "detector", [])
    state.entities[entity.id] = entity
    state.surrogates["<EMAIL_1>"] = Surrogate(entity.id)
    result = restore(state, "Пишите: mailto:<EMAIL_1>", settings)
    assert result.text == "Пишите: mailto:i.ivanov@contoso.ru"


def test_internal_link_and_derived_names_are_restored(settings):
    answer = "Откройте https://host-1.sub-2.domain-1.example/owa, заведите newbox.domain-1.example и HOST-1"
    result = restore(infra_state(), answer, settings)
    assert result.text == (
        "Откройте https://srv-web01.corp.contoso.ru/owa, заведите newbox.contoso.ru и SRV-WEB01"
    )
    assert kinds(result) == ["restored", "derived", "restored"]


def test_address_in_a_known_fake_subnet_is_derived(settings):
    state = infra_state()
    fake = next(text for text, surrogate in state.surrogates.items() if surrogate.kind == "ip")
    neighbour = fake.rsplit(".", 1)[0] + ".99"
    result = restore(state, f"Основной {fake}, резервный {neighbour}", settings)
    assert result.text == "Основной 10.1.2.5, резервный 10.1.2.99"
    assert kinds(result) == ["restored", "derived"]


def test_reformatted_mac_is_recognised(settings):
    result = restore(infra_state(), "интерфейс 02-00-00-00-00-01", settings)
    assert (result.text, kinds(result)) == ("интерфейс 00:1A:2B:3C:4D:5E", ["altered"])


def test_secret_stays_hidden(settings):
    result = restore(infra_state(), "Пароль <SECRET_1> лучше сменить", settings)
    assert (result.text, kinds(result)) == ("Пароль <SECRET_1> лучше сменить", ["kept_by_policy"])
    assert result.counters["kept"] == 1


@pytest.mark.parametrize("answer", ["", "Ответ без меток: перезапустите службу."])
def test_answer_without_surrogates_is_returned_unchanged(settings, answer):
    for state in (person_state(), ChatState(chat_id="empty", net_key=bytes(32))):
        result = restore(state, answer, settings)
        assert (result.text, result.segments) == (answer, [])


def test_original_is_not_planted_inside_other_words(settings):
    state = person_state()
    state.entities["p1"].restore_value = "Ann"
    assert restore(state, "Annual report by <PERSON_1>", settings).text == "Annual report by Ann"


def test_foreign_label_from_the_input_is_not_reported(settings):
    state = person_state()
    state.foreign_labels.add("<PERSON_7>")
    result = restore(state, "В шаблоне <PERSON_7>", settings)
    assert (result.text, result.segments) == ("В шаблоне <PERSON_7>", [])
