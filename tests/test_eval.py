import json

from cleaner.core.types import EntityType as T
from cleaner.eval import runner
from cleaner.eval.metrics import Example, GoldSpan, covered, evaluate, recall_by_class


def example(text, *spans):
    return Example(text, tuple(GoldSpan(start, end, type_, entity, origin) for start, end, type_, entity, origin in spans))


def test_entity_is_protected_only_when_every_mention_is_hidden():
    """QA-2: сущность защищена, только если скрыты все её упоминания; тип замены не важен."""
    ex = example("Петров, потом снова Петров", (0, 6, T.PERSON, 0, ""), (20, 26, T.PERSON, 0, ""))
    assert evaluate([ex], lambda text: [(0, 6, T.PERSON)]).protected[T.PERSON] == 0
    assert evaluate([ex], lambda text: [(0, 6, T.PERSON), (20, 26, T.TERM)]).protected[T.PERSON] == 1


def test_mention_must_be_covered_whole():
    assert covered(0, 10, [(0, 4), (4, 10)]) and covered(2, 3, [(0, 10)])
    assert not covered(0, 10, [(0, 4), (5, 10)]) and not covered(0, 10, [])


def test_precision_and_masked_versions_codes_and_well_known_domains():
    text = "Версия 2.4.1, ошибка 0x80070005, сайт microsoft.com, почта a@x.example"
    email = text.index("a@x")
    ex = example(text, (email, len(text), T.EMAIL, 0, ""))
    version = text.index("2.4.1")
    report = evaluate([ex], lambda t: [(version, version + 5, T.HOST), (email, len(text), T.EMAIL)])
    assert (report.found[T.HOST], report.correct[T.HOST], report.correct[T.EMAIL]) == (1, 0, 1)
    assert (report.overmasked, report.candidates) == (1, 3)


def test_classes_follow_qa_3():
    ex = example("ООО «Ромашка», Петров", (0, 13, T.ORG, 0, "dictionary"), (15, 21, T.PERSON, 1, ""))
    report = evaluate([ex], lambda t: [(0, 13, T.ORG)])
    assert recall_by_class(report) == {"Словарь организации": 1.0, "ФИО": 0.0, "Организации и почтовые адреса": 1.0}


def test_layers_1_to_3_on_a_jsonl_set(tmp_path, settings):
    path = tmp_path / "set.jsonl"
    record = {"text": "почта a@x.example", "spans": [{"start": 6, "end": 17, "type": "EMAIL", "entity": 0}]}
    path.write_text(json.dumps(record) + "\n\n", encoding="utf-8")
    results = runner.run(runner.jsonl_examples(path), settings, ["1-3"], None)
    assert recall_by_class(results["1-3"]) == {"Жёсткий формат и контрольная сумма": 1.0}
    assert "EMAIL | 1.000 (1/1) | 1.000 (1/1)" in runner.format_results(results, 1)


def test_drop_against_the_baseline_is_reported(repo, settings):
    ex = example("звонил Петров", (7, 13, T.PERSON, 0, ""))
    results = runner.run([ex], settings, ["1-3"], None)
    runner.save_baseline(repo, results)
    assert runner.compare(results, runner.load_baseline(repo)) == []
    assert runner.compare(results, {"1-3": {"ФИО": 1.0}}) == ["слои 1-3, «ФИО»: 1.000 → 0.000"]
