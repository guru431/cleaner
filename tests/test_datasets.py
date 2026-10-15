from collections import Counter

from cleaner.eval.datasets import bio_to_spans, convert


def test_tokens_are_found_in_the_text_and_parts_join():
    text = "Звонил Иванов Пётр из г. Тестовск, ул. Примерная, 5"
    tokens = ["Звонил", "Иванов", "Пётр", "из", "г", ".", "Тестовск", ",", "ул", ".", "Примерная", ",", "5"]
    tags = ["O", "B-LAST_NAME", "B-FIRST_NAME", "O", "O", "O", "B-CITY", "O", "B-STREET", "I-STREET", "I-STREET", "O", "B-HOUSE"]
    record = convert(*bio_to_spans(tokens, tags, text), Counter())
    assert [(text[s["start"]:s["end"]], s["type"], s["entity"]) for s in record["spans"]] == [
        ("Иванов Пётр", "PERSON", 0), ("Тестовск, ул. Примерная, 5", "ADDRESS", 1),
    ]


def test_tokens_without_a_text_are_joined_and_a_city_alone_is_dropped():
    text, spans = bio_to_spans(["Живу", "в", "Москве"], ["O", "O", "B-GPE"])
    assert convert(text, spans, Counter()) == {"text": "Живу в Москве", "spans": []}


def test_unknown_labels_are_counted_and_not_measured():
    unmapped = Counter()
    assert convert("код 123", [(4, 7, "SECRET_CODE")], unmapped)["spans"] == []
    assert unmapped == Counter({"SECRET_CODE": 1})


def test_set_labels_with_a_tz_type_are_measured():
    """Метки открытых наборов с типом ТЗ входят в измерение; без типа (URL, CVC) — нет."""
    text = "паспорт 4510 123456, КПП 773601001, ОГРНИП 304500116000157, карта 4111 1111 1111 1111, ключ ghp_x, cvc 123"
    labels = ["PASSPORT_NUMBER", "KPP", "OGRNIP", "BANK_CARD_NUMBER", "TOKEN", "CVC"]
    values = ["4510 123456", "773601001", "304500116000157", "4111 1111 1111 1111", "ghp_x", "123"]
    spans, position = [], 0
    for label, value in zip(labels, values):
        start = text.index(value, position)
        spans.append((start, start + len(value), label))
        position = start + len(value)
    unmapped = Counter()
    record = convert(text, spans, unmapped)
    assert [s["type"] for s in record["spans"]] == ["PASSPORT", "KPP", "OGRN", "CARD", "SECRET"]
    assert unmapped == Counter({"CVC": 1})


def test_tokens_missing_from_the_text_skip_the_example():
    assert bio_to_spans(["нет"], ["O"], "совсем другое") is None
