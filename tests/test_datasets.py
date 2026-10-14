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


def test_tokens_missing_from_the_text_skip_the_example():
    assert bio_to_spans(["нет"], ["O"], "совсем другое") is None
