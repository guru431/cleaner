import json

from cleaner import models
from cleaner.core.types import EntityType as T
from cleaner.core.types import Settings
from cleaner.eval import runner
from cleaner.eval.metrics import Example, GoldSpan, Report, covered, evaluate, recall_by_class


def example(text, *spans):
    return Example(text, tuple(GoldSpan(start, end, type_, entity, origin) for start, end, type_, entity, origin in spans))


def test_entity_is_protected_only_when_every_mention_is_hidden():
    """QA-2: сущность защищена, только если скрыты все её упоминания; тип замены не важен.
    Полнота по упоминаниям считается рядом — ею меряются открытые наборы до объединения упоминаний."""
    ex = example("Петров, потом снова Петров", (0, 6, T.PERSON, 0, ""), (20, 26, T.PERSON, 0, ""))
    half = evaluate([ex], lambda text: [(0, 6, T.PERSON)])
    assert (half.protected[T.PERSON], half.mentions_hidden[T.PERSON], half.mentions[T.PERSON]) == (0, 1, 2)
    assert evaluate([ex], lambda text: [(0, 6, T.PERSON), (20, 26, T.TERM)]).protected[T.PERSON] == 1


def test_one_replacement_over_the_whole_text_is_caught_by_the_new_measures():
    """Отрицательный контроль измерителя (аудит 21.10.2026, находка о точности по пересечениям): одна замена SECRET
    на весь текст с одним именем даёт полноту ФИО и точность по пересечению 1,0. Плохой её показывают точность типа
    и знаки, скрытые вне эталона."""
    text = "Добрый день, звонил Петров по поводу счёта"
    start = text.index("Петров")
    ex = example(text, (start, start + 6, T.PERSON, 0, ""))
    whole = evaluate([ex], lambda t: [(0, len(t), T.SECRET)])
    assert recall_by_class(whole) == {"ФИО": 1.0} and (whole.correct[T.SECRET], whole.found[T.SECRET]) == (1, 1)
    assert whole.typed[T.SECRET] == 0
    assert (whole.chars_outside, whole.chars_masked, whole.chars_free) == (len(text) - 6, len(text), len(text) - 6)
    exact = evaluate([ex], lambda t: [(start, start + 6, T.PERSON)])
    assert (exact.typed[T.PERSON], exact.chars_outside, exact.chars_masked) == (1, 0, 6)
    assert "Скрыто знаков вне эталона: 0.857 (36/42) от скрытых, 1.000 (36/36)" in runner.format_results({"1-3": whole}, 1)


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
    assert "EMAIL | 1.000 (1/1) | 1.000 (1/1) | 1.000 (1/1) | 1.000 (1/1)" in runner.format_results(results, 1)


def classes(**counts) -> Report:
    names = {"fio": "ФИО", "secrets": "Секреты"}
    return Report(classes={names[name]: list(value) for name, value in counts.items()})


def test_saving_some_layers_keeps_the_baseline_of_the_others(repo):
    """Аудит 21.10.2026: сохранение только 1–3 стирало базовый замер 1–5, и падение 1–5 с 1,0 до 0,0 проходило."""
    runner.save_baseline(repo, runner.GOLD, {name: classes(fio=(1, 1)) for name in runner.LAYER_SETS}, "fp", 1)
    runner.save_baseline(repo, runner.GOLD, {"1-3": classes(fio=(1, 1))}, "fp", 1)
    stored = runner.baselines(repo)[runner.GOLD]
    assert set(stored) == {"1-3", "1-4", "1-5"}
    worse = runner.compare({"1-5": classes(fio=(0, 1))}, stored, "fp", 1)
    assert worse.drops == ["слои 1-5, «ФИО»: 1.000 → 0.000 (1 → 0 из 1)"]
    assert worse.unchecked == [
        "слои 1-3: базовый замер есть, в этом прогоне не измерялись",
        "слои 1-4: базовый замер есть, в этом прогоне не измерялись",
    ]
    assert "полнота упала" in worse.verdict()
    same = runner.compare({name: classes(fio=(1, 1)) for name in runner.LAYER_SETS}, stored, "fp", 1)
    assert (same.drops, same.unchecked) == ([], []) and "ни один класс не упал" in same.verdict()


def test_another_set_a_vanished_class_or_no_baseline_is_not_a_pass(repo):
    """Аудит 21.10.2026: исчезнувший класс пропускался молча, а замер на другом наборе сравнивался как тот же."""
    runner.save_baseline(repo, runner.GOLD, {"1-3": classes(fio=(1, 1), secrets=(1, 1))}, "fp", 2)
    stored = runner.baselines(repo)[runner.GOLD]
    gone = runner.compare({"1-3": classes(fio=(1, 1))}, stored, "fp", 2)
    assert (gone.drops, gone.unchecked, gone.replace) == ([], ["слои 1-3, «Секреты»: сущностей класса было 1, сейчас 0"], ["1-3"])
    other = runner.compare({"1-3": classes(fio=(1, 1), secrets=(1, 1))}, stored, "fp2", 3)
    assert other.unchecked == ["слои 1-3: базовый замер снят на другом наборе (примеров было 2, сейчас 3)"]
    assert other.replace == ["1-3"] and "не проверена" in other.verdict()
    fresh = runner.compare({"1-4": classes(fio=(1, 1))}, stored, "fp", 2)
    assert fresh.unchecked[-1] == "слои 1-4: базового замера нет" and fresh.replace == []


def test_old_baseline_format_is_read_as_not_comparable(repo):
    repo.set_setting(runner.BASELINE_KEY, json.dumps({"1-3": {"ФИО": 1.0}}, ensure_ascii=False))
    stored = runner.baselines(repo)
    assert stored == {runner.GOLD: {"1-3": {}}}
    old = runner.compare({"1-3": classes(fio=(0, 1))}, stored[runner.GOLD], "fp", 1)
    assert old.drops == [] and old.replace == ["1-3"] and "прежнего формата" in old.unchecked[0]
    runner.save_baseline(repo, runner.GOLD, {"1-4": classes(fio=(1, 1))}, "fp", 1)
    assert set(runner.baselines(repo)[runner.GOLD]) == {"1-4"}       # записи прежнего формата сравнить не с чем


def test_fingerprint_follows_texts_and_spans_not_the_order():
    one = example("звонил Петров", (7, 13, T.PERSON, 0, ""))
    two = example("почта a@x.example", (6, 17, T.EMAIL, 0, ""))
    key = bytes(32)
    assert runner.fingerprint([one, two], key) == runner.fingerprint([two, one], key)
    assert runner.fingerprint([one], key) != runner.fingerprint([example("звонил Петров", (7, 13, T.ORG, 0, ""))], key)
    assert runner.fingerprint([one], key) != runner.fingerprint([one], bytes(range(32)))      # отпечаток под ключом базы
    plain, changed = Settings(), Settings(never=frozenset({"intranet.example"}))
    assert runner.settings_fingerprint(plain, key) != runner.settings_fingerprint(changed, key)


def test_model_revisions_come_from_the_download_manifests(tmp_path):
    (tmp_path / models.RUBERT_DIR).mkdir()
    (tmp_path / models.RUBERT_DIR / models.MANIFEST).write_text(json.dumps({"revision": "c802e8"}), encoding="utf-8")
    assert runner.model_revisions(tmp_path) == {models.RUBERT_DIR: "c802e8", models.GLINER_DIR: "нет"}
    assert runner.model_revisions(None) == {}


def test_measurement_goes_to_the_passport_without_texts(repo):
    repo.add_gold(None, "звонил Петров", [{"start": 7, "end": 13, "type": "PERSON", "entity": 0, "origin": "detector"}])
    done = runner.measure(repo, runner.GOLD, runner.gold_examples(repo), ["1-3"], None, None)
    assert done.comparison.unchecked == ["слои 1-3: базового замера нет"]
    raw = repo.setting(runner.PASSPORT_KEY)
    assert "Петров" not in raw
    entry = json.loads(raw)[runner.GOLD]
    assert (entry["examples"], entry["fingerprint"], entry["unit"]) == (1, done.fingerprint, runner.UNIT_GOLD)
    assert entry["layers"]["1-3"]["classes"] == {"ФИО": [0, 1]}
    assert entry["layers"]["1-3"]["types"]["PERSON"]["entities"] == [0, 1]
    assert entry["versions"]["models"] == {} and len(entry["versions"]["code"]) == 64
    assert entry["unchecked"] == ["слои 1-3: базового замера нет"] and entry["measured_at"] == "2026-10-14T09:00:00+00:00"


def test_utility_warning_preserves_the_recall_gate_and_is_persisted(repo):
    ex = example("mail a@x.example; Version 2.4.1", (5, 16, T.EMAIL, 0, ""))
    before = evaluate([ex], lambda _: [(5, 16, T.EMAIL)])
    after = evaluate([ex], lambda _: [(0, 16, T.EMAIL), (26, 31, T.TERM)])
    runner.save_baseline(repo, runner.GOLD, {"1-3": before}, "fp", 1)
    comparison = runner.compare({"1-3": after}, runner.baselines(repo)[runner.GOLD], "fp", 1)
    assert comparison.drops == [] and comparison.unchecked == []
    assert len(comparison.warnings) == 2
    assert "знаков было 0, стало" in comparison.warnings[0]
    assert "ложных срабатываний было 0, стало 1" in comparison.warnings[1]
    assert "ПОЛЕЗНОСТЬ:" in "\n".join(comparison.lines())
    worse = evaluate([ex], lambda _: [])
    assert runner.compare({"1-3": worse}, runner.baselines(repo)[runner.GOLD], "fp", 1).drops


def test_coverage_includes_empty_cells_and_counts_examples_once(repo):
    from cleaner.eval import coverage

    spans = [{"start": 0, "end": 3, "type": "PERSON", "entity": 0},
             {"start": 4, "end": 7, "type": "PERSON", "entity": 0}]
    metadata = coverage.metadata("config", ["word_forms", "repeated"])
    repo.add_gold(None, "Лев Лев", spans, metadata)
    repo.add_gold(None, "Лев", spans[:1])
    classified = next(row for row in repo.gold() if row.metadata)
    legacy = next(row for row in repo.gold() if not row.metadata)
    assert classified.metadata == metadata and legacy.metadata == {}
    matrix = coverage.matrix(repo.gold())
    names = [key for key, _ in matrix["scenarios"]]
    fio = next(row for row in matrix["rows"] if row["title"] == "ФИО")
    assert fio["cells"][names.index("config")] == 1
    assert fio["cells"][names.index("")] == 1
    assert fio["cells"][names.index("agent")] == 0
    assert matrix["repeated"] == 1
    assert dict(matrix["checks"])["Все повторные упоминания проверены"] == 1
