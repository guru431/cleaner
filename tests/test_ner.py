import re

import pytest

from cleaner.core.detect.ner import THRESHOLD, Found, NerLayer, identifier, windows
from cleaner.core.pipeline import Layers, sanitize
from cleaner.core.types import EntityType as T
from cleaner.core.types import Span


class Tagger:
    def __init__(self, *found):
        self.found = list(found)

    def tag(self, text):
        return self.found


def spans(text, *found):
    return [(text[s.start:s.end], s.type, s.source) for s in NerLayer([Tagger(*found)]).detect(text)]


def test_name_parts_are_person_fragments_that_the_pipeline_joins(state, settings):
    text = "Иванов Иван Иванович пришёл"
    layer = NerLayer([Tagger(Found(0, 6, "LAST_NAME", 0.98), Found(7, 11, "FIRST_NAME", 0.97), Found(12, 20, "MIDDLE_NAME", 0.9))])
    assert sanitize(state, text, settings, Layers(ner=layer)).sanitized == "<PERSON_1> пришёл"


def test_threshold_is_low_in_favour_of_recall():
    text = "Петров и Сидоров"
    assert spans(text, Found(0, 6, "LAST_NAME", THRESHOLD), Found(9, 16, "LAST_NAME", 0.2)) == [("Петров", T.PERSON, "ner")]


def test_address_parts_become_one_address_only_with_a_street_or_house():
    text = "Офис: г. Тестовск, ул. Примерная, д. 5. Филиал в Москве."
    found = (Found(9, 17, "CITY", 0.9), Found(23, 32, "STREET", 0.9), Found(37, 38, "HOUSE", 0.9), Found(49, 55, "CITY", 0.9))
    assert spans(text, *found) == [("Тестовск, ул. Примерная, д. 5", T.ADDRESS, "ner")]


def test_gliner_address_with_a_number_that_is_no_house_is_not_hidden():
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: «location address» GLiNER называет и «1С»
    («Копию отправили в Сбербанк и в 1С.» → <ADDRESS_1>); одна цифра вплотную к букве — не номер дома."""
    text = "Копию отправили в Сбербанк и в 1С, офис 5А"
    assert spans(text, found_at(text, "1С", "location address"), found_at(text, "5А", "location address")) == []


@pytest.mark.parametrize(
    "value",
    ["ул. Ленина, д. 5", "Ленина 5", "Тверская 12к1", "ул. Мира 5А", "10 Downing Street", "Baker St 1B", "4509 123456"],
)
def test_gliner_address_with_a_street_or_a_house_is_hidden(value):
    """Число в находке — дом; номер документа GLiNER тоже называет адресом, и он остаётся скрытым: слои 1–3 без
    контекста и с испорченной контрольной суммой его не находят."""
    text = f"Адрес: {value}, дальше текст"
    assert spans(text, found_at(text, value, "location address")) == [(value, T.ADDRESS, "ner")]


def test_lone_gliner_place_is_still_an_address():
    """Открытые наборы размечают адресом и место без улицы («в Москве», «на Мойке»): по правилу русской модели
    полнота класса «Организации и почтовые адреса» на hivetrace упала бы с 0,886 до 0,858 — решает владелец."""
    text = "Встреча в Москве, потом дворец на Мойке"
    found = (found_at(text, "Москве", "location address"), found_at(text, "Мойке", "location address"))
    assert spans(text, *found) == [("Москве", T.ADDRESS, "ner"), ("Мойке", T.ADDRESS, "ner")]


def test_gliner_address_and_parts_of_the_russian_model_make_one_address():
    """Адрес GLiNER и части русской модели рядом — один адрес вместе с запятыми между ними: двумя находками
    запятая оставалась открытой, и адрес не считался скрытым (на открытых наборах так открыты были три адреса)."""
    text = "Офис: Тестовск, Северный район, Примерный проспект, 56. Филиал в Москве."
    found = (
        found_at(text, "Тестовск, Северный район", "location address"),
        found_at(text, "Примерный проспект", "STREET"), found_at(text, "56", "HOUSE"),
        found_at(text, "Москве", "CITY"),
    )
    assert spans(text, *found) == [("Тестовск, Северный район, Примерный проспект, 56", T.ADDRESS, "ner")]


def test_organisations_documents_and_labels_of_other_layers():
    text = "Contact John Smith at Example Corp, права 77 АА 123456, почта a@x.example"
    found = (
        Found(8, 18, "name", 0.9), Found(22, 34, "organization", 0.8),
        Found(42, 54, "DRIVER_LICENSE", 0.7), Found(62, 73, "EMAIL", 0.99),
    )
    assert spans(text, *found) == [
        ("John Smith", T.PERSON, "ner"), ("Example Corp", T.ORG, "ner"), ("77 АА 123456", T.PASSPORT, "ner"),
    ]


def test_fragments_of_one_entity_are_glued():
    assert spans("Иванов пришёл", Found(0, 2, "LAST_NAME", 0.9), Found(2, 6, "LAST_NAME", 0.8)) == [("Иванов", T.PERSON, "ner")]


def test_windows_cover_the_text_with_overlap():
    text = " ".join(f"w{n}" for n in range(450))
    parts = windows(text, size=200, overlap=40)
    assert len(parts) == 3
    assert text[parts[0][0]:parts[0][1]].split()[-1] == "w199"
    assert text[parts[1][0]:parts[1][1]].split()[0] == "w160"
    assert parts[-1][1] == len(text) and windows("   ") == []


def found_at(text, value, label):
    start = text.index(value)
    return Found(start, start + len(value), label, 0.5)


def test_lowercase_organisation_of_common_nouns_is_dropped():
    text = "Счёт из бухгалтерии, сверку прислал банк, отдел кадров молчит; Ромашка, автосити, алексей и чапаевская аллея — нет."
    kept = ("Ромашка", "автосити", "алексей", "чапаевская аллея")     # заглавная, не из словаря, имя, прилагательное
    found = [found_at(text, value, "organization") for value in ("из бухгалтерии", "банк", "отдел кадров", *kept)]
    assert spans(text, *found) == [(value, T.ORG, "ner") for value in kept]


def word_at(text, value, label):
    m = re.search(rf"(?<!\w){re.escape(value)}(?!\w)", text)
    return Found(m.start(), m.end(), label, 0.5)


def test_document_acronyms_and_bare_legal_forms_are_not_organisations():
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: GLiNER называет организацией номера документов,
    налоги, страховки и форму без названия (СНИЛС, ОСАГО, ЖКХ, «ИП»)."""
    text = "Укажите СНИЛС, ИНН и ОГРНИП. Для ИП нужен полис ОСАГО и КАСКО, оплата ЖКХ без НДС; формы ООО и АО."
    noise = ("СНИЛС", "ИНН", "ОГРНИП", "ИП", "ОСАГО", "КАСКО", "ЖКХ", "НДС", "ООО", "АО")
    assert spans(text, *(word_at(text, value, "organization") for value in noise)) == []


def test_common_words_acronyms_and_countries_are_not_organisations():
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: шум ORG, который стоп-список не покрывал, и похожее
    с открытых наборов (документ с обычным словом, экзамены и анализы, слова ИТ, страны, обычное существительное)."""
    text = (
        "Нужен полис ОМС и ИНН юрлица, полис ОСАГО. Банк ответил. Сервер упал. ИИ, ДТП, ЕГЭ, ОГЭ; в США и РФ. "
        "УЗИ и МРТ, ТС, HR и IT, СМС. Филиал и Бухгалтерия, Компания; физлицо."
    )
    noise = (
        "полис ОМС", "ИНН юрлица", "полис ОСАГО", "Банк", "Сервер", "ИИ", "ДТП", "ЕГЭ", "ОГЭ", "США", "РФ",
        "УЗИ", "МРТ", "ТС", "HR", "IT", "СМС", "Филиал", "Бухгалтерия", "Компания", "физлицо",
    )
    assert spans(text, *(word_at(text, value, "organization") for value in noise)) == []


def test_names_next_to_the_new_stop_words_stay_organisations():
    text = "Банк «Восток» и Сбербанк, Правительство РФ, фонд ОМС, Сервер-Про и Система"
    kept = ("Банк «Восток»", "Сбербанк", "Правительство РФ", "фонд ОМС", "Сервер-Про", "Система")
    assert spans(text, *(word_at(text, value, "organization") for value in kept)) == [(value, T.ORG, "ner") for value in kept]


def test_state_bodies_and_named_organisations_stay_organisations():
    """ФНС, ПФР и МВД — настоящие организации: открыть их можно словарём «никогда не скрывать», модель не решает."""
    text = "Справку из ФНС и ПФР отправили в ООО «Ромашка», копию — в МВД и ИП Петров."
    kept = ("ФНС", "ПФР", "ООО «Ромашка»", "МВД", "ИП Петров")
    assert spans(text, *(word_at(text, value, "organization") for value in kept)) == [(value, T.ORG, "ner") for value in kept]


def test_common_noun_at_the_start_of_a_sentence_found_only_by_gliner_is_not_a_person():
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: GLiNER называет человеком существительное в начале
    предложения («Копию отправил Петров» → «Копию»)."""
    text = "Копию отправил Петров. Счёт выставил Сидоров!\n«Договор» подписал Иванов"
    names = ("Копию", "Петров", "Счёт", "Сидоров", "Договор", "Иванов")
    assert spans(text, *(word_at(text, value, "name") for value in names)) == [
        (value, T.PERSON, "ner") for value in ("Петров", "Сидоров", "Иванов")
    ]


def test_names_and_nouns_elsewhere_or_seen_by_the_russian_model_stay_persons():
    """Имя, фамилия, два слова и существительное не в начале предложения правило не трогает; находка русской модели —
    тоже: правило только для GLiNER."""
    text = "Иванов пришёл. Роман приедет. Вера звонила. Лев Толстой писал; звонил Директор"
    names = ("Иванов", "Роман", "Вера", "Лев Толстой", "Директор")
    assert spans(text, *(word_at(text, value, "name") for value in names)) == [(value, T.PERSON, "ner") for value in names]
    layer = NerLayer([Tagger(Found(0, 5, "FIRST_NAME", 0.9)), Tagger(Found(0, 5, "name", 0.9))])
    assert {(s.start, s.end, s.type) for s in layer.detect("Копию отправил Петров")} == {(0, 5, T.PERSON)}


def test_password_is_told_by_the_whole_word():
    text = "sunflower77, Qwerty2024; АА1234567, ivanov_test, Вектор-77, Сидоров, ул. Мира5"

    def looks(value, type_):
        start = text.index(value)
        return identifier(text, Span(start, start + len(value), type_, "ner"))

    # «sunflower» — обрывок «sunflower77»: модель может пометить часть слова
    assert looks("sunflower", T.PERSON) and looks("Qwerty2024", T.ORG)
    assert not any(looks(value, type_) for value, type_ in (
        ("АА1234567", T.PERSON), ("ivanov_test", T.PERSON), ("Вектор-77", T.ORG), ("Сидоров", T.PERSON), ("Мира5", T.ADDRESS),
    ))


def test_password_taken_for_a_name_is_left_to_layer_5(state, settings, engines):
    """GLiNER называет «sunflower77» именем; слой 5 видит очищенный текст и без отсева получил бы <PERSON_1>."""
    text = "Для общего ящика на стикере записано: sunflower77, отвечает Сидоров"
    layer = NerLayer([Tagger(found_at(text, "sunflower77", "name"), found_at(text, "Сидоров", "name"))])
    engines.second.marks = {"sunflower77": T.SECRET}
    result = sanitize(state, text, settings, Layers(ner=layer, llm=engines.second))
    assert result.sanitized == "Для общего ящика на стикере записано: <SECRET_1>, отвечает <PERSON_1>"
    assert engines.second.seen == ["Для общего ящика на стикере записано: sunflower77, отвечает <PERSON_1>"]


def test_password_taken_for_a_name_stays_hidden_without_layer_5(state, settings):
    text = "Для общего ящика на стикере записано: sunflower77"
    layer = NerLayer([Tagger(found_at(text, "sunflower77", "name"))])
    assert sanitize(state, text, settings, Layers(ner=layer)).sanitized == "Для общего ящика на стикере записано: <PERSON_1>"


def test_findings_of_both_models_add_up():
    text = "Иванов и John Smith"
    layer = NerLayer([Tagger(Found(0, 6, "LAST_NAME", 0.9)), Tagger(Found(9, 19, "name", 0.9))])
    assert [text[s.start:s.end] for s in layer.detect(text)] == ["Иванов", "John Smith"]
