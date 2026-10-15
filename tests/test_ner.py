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
