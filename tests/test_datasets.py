import hashlib
import json
from collections import Counter

from cleaner.eval.datasets import CONVERTER, bio_to_spans, check_snapshot, convert, manifest_path, write_snapshot


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


def test_an_inside_tag_after_an_outside_one_starts_a_new_span():
    """Ревью 24.10.2026: I-метка продлевала фрагмент через O — два человека и «и» между ними были одним PERSON."""
    text, spans = bio_to_spans(["Иванов", "и", "Петров", "Пётр"], ["I-PER", "O", "I-PER", "I-PER"])
    assert [text[start:end] for start, end, _ in spans] == ["Иванов", "Петров Пётр"]


def test_name_parts_join_across_a_dot_only_after_an_initial():
    """Ревью 24.10.2026: точка между частями имени — конец предложения, если перед ней не инициал (как merge в слое 4)."""
    text = "Был Иванов. Петров ушёл, а И. Сидоров остался"
    spans = [(text.index(value), text.index(value) + len(value), "LAST_NAME") for value in ("Иванов", "Петров", "Сидоров")]
    spans.append((text.index("И."), text.index("И.") + 1, "FIRST_NAME"))
    record = convert(text, spans, Counter())
    assert [text[s["start"]:s["end"]] for s in record["spans"]] == ["Иванов", "Петров", "И. Сидоров"]


def test_tokens_missing_from_the_text_skip_the_example():
    assert bio_to_spans(["нет"], ["O"], "совсем другое") is None


def test_mentions_of_one_value_are_one_entity_and_other_forms_are_not():
    """Аудит 21.10.2026: каждое упоминание было отдельной сущностью, и из двух упоминаний, скрытых наполовину,
    выходила полнота 0,5 вместо 0 по QA-2. Одно значение одного типа — одна сущность; другая форма имени — другая."""
    text = "Петров звонил. Потом ПЕТРОВ  написал, Петрову ответили. Петров — и ООО «Петров»"
    values = [("Петров", "LAST_NAME"), ("ПЕТРОВ", "LAST_NAME"), ("Петрову", "LAST_NAME"), ("Петров", "LAST_NAME"), ("Петров", "ORG")]
    spans, position = [], 0
    for value, label in values:
        start = text.index(value, position)
        spans.append((start, start + len(value), label))
        position = start + len(value)
    record = convert(text, spans, Counter())
    assert [(s["type"], s["entity"]) for s in record["spans"]] == [
        ("PERSON", 0), ("PERSON", 0), ("PERSON", 1), ("PERSON", 0), ("ORG", 2),
    ]


RECORD = {"text": "почта a@x.example", "spans": [{"start": 6, "end": 17, "type": "EMAIL", "entity": 0}]}


def test_snapshot_keeps_the_accepted_file_and_is_checked_against_its_manifest(tmp_path):
    """Идея аудита 21.10.2026: повторная загрузка не подменяет снимок, с которым связан базовый замер, незаметно —
    новый занимает основное имя, прежний со своим манифестом сохраняется рядом."""
    first = write_snapshot(tmp_path, "set", [RECORD, {"text": "без разметки", "spans": []}], "org/set", "rev1", False)
    assert first.name == "set.jsonl" and len(first.read_text(encoding="utf-8").splitlines()) == 1
    name, manifest, problems = check_snapshot(first)
    assert (name, problems) == ("set", [])
    assert {k: manifest[k] for k in ("source", "revision", "pinned", "converter", "examples")} == {
        "source": "org/set", "revision": "rev1", "pinned": False, "converter": CONVERTER, "examples": 1,
    }
    assert write_snapshot(tmp_path, "set", [RECORD], "org/set", "rev2", False) == first      # тот же снимок
    assert sorted(p.name for p in tmp_path.iterdir()) == ["set.jsonl", "set.manifest.json"]
    other = {"text": "почта b@x.example", "spans": RECORD["spans"]}
    previous = tmp_path / f"set-{manifest['sha256'][:12]}.jsonl"
    assert write_snapshot(tmp_path, "set", [other], "org/set", "rev3", False) == first
    assert "b@x" in first.read_text(encoding="utf-8") and check_snapshot(first)[::2] == ("set", [])
    assert "a@x" in previous.read_text(encoding="utf-8")
    assert check_snapshot(previous)[::2] == ("set", []) and check_snapshot(previous)[1]["revision"] == "rev2"
    first.write_text(first.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert check_snapshot(first)[2] == ["файл не совпадает с манифестом (sha256): снимок изменён после загрузки"]
    stale = json.loads(manifest_path(previous).read_text(encoding="utf-8")) | {"converter": 1}
    manifest_path(previous).write_text(json.dumps(stale), encoding="utf-8")
    assert "конвертером версии 1" in check_snapshot(previous)[2][0]


def test_snapshot_without_a_manifest_gives_way_to_the_new_one(tmp_path):
    """Ревью 2026-10-21: снимок, скачанный до манифестов, оставался по документированному пути, новый ложился рядом,
    и проверка отправляла скачивать заново — по кругу. Новый занимает основное имя, прежний сохраняется рядом."""
    old = tmp_path / "set.jsonl"
    old.write_text('{"text": "x", "spans": []}\n', encoding="utf-8")
    digest = hashlib.sha256(old.read_bytes()).hexdigest()
    path = write_snapshot(tmp_path, "set", [RECORD], "org/set", "rev1", False)
    assert path == old and check_snapshot(path)[::2] == ("set", [])
    moved = tmp_path / f"set-{digest[:12]}.jsonl"
    assert moved.read_text(encoding="utf-8") == '{"text": "x", "spans": []}\n' and not manifest_path(moved).exists()
    lone = tmp_path / "lone.jsonl"
    lone.write_text("", encoding="utf-8")
    assert check_snapshot(lone) == ("lone", None, ["нет манифеста: источник, ревизия и версия конвертера неизвестны"])
