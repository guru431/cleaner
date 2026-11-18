"""Прогон эталонного набора по слоям 1–3, 1–4, 1–5 (QA-5), сравнение с базовым замером (QA-6) и паспорт качества.

Базовый замер и паспорт лежат открыто в settings: только счётчики и отпечатки, без текстов. Базовый замер хранится
по набору и по каждому набору слоёв отдельно — сохранение одних слоёв не стирает другие. Сравнивается только замер
того же набора (отпечаток) с теми же знаменателями классов; иначе слои «не проверены», а не «ухудшений нет».
"""
from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cleaner import models
from cleaner.core.entities import hostmap
from cleaner.core.pipeline import Layers, sanitize
from cleaner.core.types import ChatState, EntityType, Settings
from cleaner.engines import local_settings
from cleaner.eval.metrics import CLASSES, Example, GoldSpan, Predict, Report, evaluate, interval, recall_by_class
from cleaner.storage.db import transaction

LAYER_SETS = ("1-3", "1-4", "1-5")
BASELINE_KEY = "eval.baseline"
PASSPORT_KEY = "eval.passport"
GOLD = "gold"                       # собственный набор; открытые — «open:<имя набора из манифеста>»
PARTITIONS = {"tuning": "Для настройки", "control": "Контрольный"}
OPEN_PREFIX = "open:"
UNIT_GOLD = "сущности разметки экрана проверки (QA-2: защищена, только если скрыты все её упоминания)"
UNIT_OPEN = (
    "сущности после преобразования открытого набора: одно значение одного типа в примере — одна сущность, "
    "разные формы имени — разные"
)
UNIT_FILE = "номера сущностей из файла: единица зависит от разметки снимка"
_CODE = ("core", "data", "eval")     # каталоги пакета, от которых зависит замер


def example_from(text: str, spans: Sequence[dict], metadata: dict | None = None) -> Example:
    metadata = metadata or {}
    return Example(text, tuple(
        GoldSpan(int(s["start"]), int(s["end"]), EntityType(s["type"]), int(s["entity"]), s.get("origin", ""), s.get("secret_context", ""))
        for s in spans
    ), metadata.get("scenario", ""), metadata.get("source", ""))


def gold_examples(repo, purpose: str = "") -> list[Example]:
    rows = repo.gold()
    assignments = {}
    for row in rows:
        source, part = row.metadata.get("source"), row.metadata.get("purpose")
        if source and part:
            if source in assignments and assignments[source] != part:
                raise ValueError("Примеры одного источника попали в разные части эталона")
            assignments[source] = part
    return [example_from(row.text, row.spans, row.metadata) for row in rows if not purpose or row.metadata.get("purpose") == purpose]


def jsonl_examples(path: Path, *, data: bytes | None = None) -> list[Example]:
    examples = []
    for line in (path.read_bytes() if data is None else data).decode("utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            examples.append(example_from(record["text"], record["spans"]))
    return examples


def layers_for(name: str, engines: Any) -> Layers:
    if name == "1-3":
        return Layers()
    if name == "1-4":
        return Layers(ner=engines.ner())
    return Layers(ner=engines.ner(), llm=engines.llm())


def predictor(settings: Settings, layers: Layers) -> Predict:
    """Каждый пример — в новом чате, с общими настройками (словарь организации, политики)."""
    def predict(text: str):
        state = ChatState(chat_id="eval", net_key=bytes(32))
        result = sanitize(state, text, settings, layers)
        return [(s.start, s.end, state.entities[s.entity_id].type) for s in result.spans]

    return predict


def run(examples: Sequence[Example], settings: Settings, layer_sets: Sequence[str], engines: Any) -> dict[str, Report]:
    with hostmap.using_suffixes(settings.internal_suffixes):
        return {name: evaluate(examples, predictor(settings, layers_for(name, engines))) for name in layer_sets}


def share(part: int, whole: int) -> str:
    """Доля с числителем и знаменателем — для отчёта и страницы замера."""
    return f"{part / whole:.3f} ({part}/{whole})" if whole else "—"


def confidence(part: int, whole: int) -> str:
    bounds = interval(part, whole)
    return share(part, whole) + (f"; 95% [{bounds[0]:.3f}, {bounds[1]:.3f}]" if bounds else "")


def format_results(results: dict[str, Report], count: int, *, dataset: str = GOLD) -> str:
    own = not dataset.startswith(OPEN_PREFIX)
    lines = [
        f"Примеров: {count}",
        "Полнота — по сущностям (QA-2: скрыты все упоминания) и по упоминаниям. Точность — по пересечению: найденный "
        "фрагмент верен, если задел любой эталонный, без учёта типа и лишнего захвата; точность типа — доля задевших "
        "эталон с тем же типом, что у эталона.",
    ]
    for name, report in results.items():
        lines += [
            "", f"Слои {name}",
            "Тип | полнота по сущностям (скрыто/всего) | по упоминаниям | точность по пересечению (задели эталон/найдено) "
            "| точность типа (тот же тип/задели эталон)",
        ]
        for type_ in sorted(set(report.entities) | set(report.found), key=lambda t: t.value):
            lines.append(" | ".join((
                type_.value, share(report.protected[type_], report.entities[type_]),
                share(report.mentions_hidden[type_], report.mentions[type_]),
                share(report.correct[type_], report.found[type_]), share(report.typed[type_], report.correct[type_]),
            )))
        lines.append("Класс QA-3 | полнота (скрыто/всего) | цель" if own else "Класс | полнота (скрыто/всего)")
        recalls = recall_by_class(report)
        for title, _, target in CLASSES:
            if title in recalls:
                line = f"{title} | {confidence(*report.classes[title])}"
                if not own:
                    lines.append(line)
                    continue
                verdict = "цель не задана" if target is None else (
                    f"{target:.2f} — достигнута" if recalls[title] >= target else f"{target:.2f} — не достигнута"
                )
                lines.append(f"{line} | {verdict}")
        lines.append("95% Wilson — описательный интервал по сущностям, зависимость внутри документа ограничивает перенос. "
                     f"Источников: {len(report.sources)}; объём и разнообразие контрольного набора не заменяются точечной долей.")
        lines.append(
            f"Скрыто знаков вне эталона: {share(report.chars_outside, report.chars_masked)} от скрытых, "
            f"{share(report.chars_outside, report.chars_free)} от текста вне эталона"
        )
        lines.append(
            "Лишние замены среди версий, кодов ошибок и общеизвестных доменов: "
            f"{share(report.overmasked, report.candidates)}"
        )
        lines.append(f"Ложные срабатывания вне эталона: {sum(report.found.values()) - sum(report.correct.values())}")
    return "\n".join(lines)


# --- отпечатки: набор, настройки, код, модели -------------------------------------------------

def _keyed(key: bytes, data: bytes) -> str:
    """HMAC под ключом, выведенным из общего ключа базы: открытый sha256 короткого примера или значения словаря
    подбирается перебором, а отпечаток лежит открыто в settings."""
    derived = hmac.new(key, b"cleaner eval fingerprint", hashlib.sha256).digest()
    return hmac.new(derived, data, hashlib.sha256).hexdigest()


def fingerprint(examples: Sequence[Example], key: bytes) -> str:
    """Отпечаток набора: тексты и разметка, порядок примеров не важен."""
    digests = sorted(
        hashlib.sha256(json.dumps(
            [example.text, [[s.start, s.end, s.type.value, s.entity, s.origin, s.secret_context] for s in example.spans], example.scenario, example.source],
            ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        for example in examples
    )
    return _keyed(key, "\n".join(digests).encode("ascii"))


def settings_fingerprint(settings: Settings, key: bytes) -> str:
    """Словарь, шаблоны, политики и дополнения внутренних суффиксов — отпечатком, без значений."""
    canonical = {
        "always": sorted([entry.type.value, entry.value, sorted(entry.aliases)] for entry in settings.always),
        "never": sorted(settings.never),
        "patterns": sorted([pattern.name, pattern.regex, pattern.type.value] for pattern in settings.patterns),
        "policies": {type_.value: policy.value for type_, policy in settings.policies.items()},
        "internal_suffixes": list(settings.internal_suffixes),
    }
    return _keyed(key, json.dumps(canonical, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def code_fingerprint() -> str:
    """Версия ядра: в установке на сервере нет git (доставка — git archive), поэтому — sha256 исходников ядра,
    встроенных списков и мер. Переводы строк приводятся к LF: на Windows и Linux отпечаток тот же."""
    root = Path(__file__).resolve().parents[1]
    files = sorted(
        (path.relative_to(root).as_posix(), path)
        for directory in _CODE for path in (root / directory).rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )
    digest = hashlib.sha256()
    for name, path in files:
        digest.update(name.encode("utf-8") + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return digest.hexdigest()


def model_revisions(models_dir: Path | None) -> dict[str, str]:
    """Ревизии моделей слоя 4 из манифестов models download; «нет» — модель не загружена или манифест повреждён."""
    if models_dir is None:
        return {}
    found = {}
    for directory in (models.RUBERT_DIR, models.GLINER_DIR):
        try:
            found[directory] = str(json.loads((models_dir / directory / models.MANIFEST).read_text(encoding="utf-8"))["revision"])
        except (OSError, ValueError, KeyError, TypeError):
            found[directory] = "нет"
    return found


def summary(report: Report) -> dict:
    """Счётчики замера для паспорта — без текстов."""
    types = sorted(set(report.entities) | set(report.found), key=lambda t: t.value)
    return {
        "classes": {title: list(counts) for title, counts in report.classes.items()},
        "scenarios": report.scenarios,
        "sources": len(report.sources),
        "types": {
            type_.value: {
                "entities": [report.protected[type_], report.entities[type_]],
                "mentions": [report.mentions_hidden[type_], report.mentions[type_]],
                "found": report.found[type_], "correct": report.correct[type_], "typed": report.typed[type_],
            }
            for type_ in types
        },
        "chars": [report.chars_outside, report.chars_masked, report.chars_free],
        "overmasked": [report.overmasked, report.candidates],
    }


# --- базовый замер (QA-6) ----------------------------------------------------------------

@dataclass
class Comparison:
    drops: list[str] = field(default_factory=list)       # полнота класса упала
    unchecked: list[str] = field(default_factory=list)   # сопоставимого базового замера нет — QA-6 не проверена
    replace: list[str] = field(default_factory=list)     # слои, чей базовый замер снят на другом наборе: замена — только явно
    warnings: list[str] = field(default_factory=list)    # цена маскирования; предупреждение отдельно от запрета QA-6

    def verdict(self) -> str:
        if self.drops:
            return "QA-6: полнота упала — изменение не принимается."
        if self.unchecked:
            return "QA-6 не проверена: сопоставимого базового замера нет — это не «ухудшений нет»."
        return "QA-6: ни один класс не упал против базового замера."

    def lines(self) -> list[str]:
        return (
            [f"ПОЛНОТА УПАЛА: {d}" for d in self.drops] + [f"НЕ ПРОВЕРЕНО: {u}" for u in self.unchecked]
            + [f"ПОЛЕЗНОСТЬ: {w}" for w in self.warnings] + [self.verdict()]
        )


def baselines(repo) -> dict[str, dict[str, dict]]:
    """Набор -> слои -> {fingerprint, examples, classes: {класс: [скрыто, всего]}}."""
    raw = repo.setting(BASELINE_KEY)
    data = json.loads(raw) if raw else {}
    if data and data.get("version") != 2:
        # Прежний формат — только полноты собственного набора по слоям: без отпечатка и знаменателей сравнивать не с чем.
        return {GOLD: {name: {} for name in data}}
    return data.get("datasets", {})


def save_baseline(repo, dataset: str, results: dict[str, Report], fp: str, examples: int) -> None:
    """Заменяет базовый замер только измеренных слоёв этого набора; записи прежнего формата отбрасываются."""
    update = {
        name: {"fingerprint": fp, "examples": examples, **summary(report)}
        for name, report in results.items()
    }
    with repo.lock, transaction(repo.conn):
        stored = baselines(repo)
        layers = {name: entry for name, entry in stored.get(dataset, {}).items() if entry}
        stored[dataset] = layers | update
        repo.set_setting(BASELINE_KEY, json.dumps({"version": 2, "datasets": stored}, ensure_ascii=False))


def compare(results: dict[str, Report], baseline: dict[str, dict], fp: str, examples: int) -> Comparison:
    """QA-6: изменение не принимается, если полнота любого класса упала против базового замера того же набора.
    Нет замера слоёв, замер на другом наборе или с другими знаменателями класса — «не проверено»."""
    result = Comparison()
    for name in sorted(set(baseline) - set(results)):
        result.unchecked.append(f"слои {name}: базовый замер есть, в этом прогоне не измерялись")
    for name, report in results.items():
        before = baseline.get(name)
        if before is None:
            result.unchecked.append(f"слои {name}: базового замера нет")
            continue
        if "fingerprint" not in before:
            result.unchecked.append(f"слои {name}: базовый замер прежнего формата — без отпечатка набора и знаменателей")
            result.replace.append(name)
            continue
        if before["fingerprint"] != fp:
            result.unchecked.append(
                f"слои {name}: базовый замер снят на другом наборе (примеров было {before['examples']}, сейчас {examples})"
            )
            result.replace.append(name)
            continue
        old, new = before["classes"], report.classes
        if "chars" in before and "types" in before:
            previous = before["chars"][0]
            if report.chars_outside > previous:
                result.warnings.append(
                    f"слои {name}: лишне скрытых знаков было {previous}, стало {report.chars_outside}"
                )
            previous_fp = sum(t["found"] - t["correct"] for t in before["types"].values())
            current_fp = sum(report.found.values()) - sum(report.correct.values())
            if current_fp > previous_fp:
                result.warnings.append(
                    f"слои {name}: ложных срабатываний было {previous_fp}, стало {current_fp}"
                )
        else:
            result.warnings.append(f"слои {name}: полезность не сравнивалась — в базовом замере нет счётчиков")
        for title in sorted(set(old) | set(new)):
            (hidden, total), (now, current) = old.get(title, (0, 0)), new.get(title, (0, 0))
            if total != current:
                # Тот же набор, другой знаменатель — изменился отбор класса в CLASSES: сравнивать не с чем.
                result.unchecked.append(f"слои {name}, «{title}»: сущностей класса было {total}, сейчас {current}")
                if name not in result.replace:
                    result.replace.append(name)
            elif now < hidden:
                result.drops.append(
                    f"слои {name}, «{title}»: {hidden / total:.3f} → {now / total:.3f} ({hidden} → {now} из {total})"
                )
    return result


# --- замер и паспорт качества ---------------------------------------------------------------

@dataclass
class Measurement:
    results: dict[str, Report]
    comparison: Comparison
    fingerprint: str
    examples: int


def passport(repo) -> dict[str, dict]:
    """Последний замер каждого набора: набор -> запись measure."""
    raw = repo.setting(PASSPORT_KEY)
    return json.loads(raw) if raw else {}


def measure(
    repo, dataset: str, examples: Sequence[Example], layer_sets: Sequence[str], engines: Any, models_dir: Path | None,
    unit: str = UNIT_GOLD, source: dict | None = None,
) -> Measurement:
    """Замер, сравнение с базовым и запись в паспорт как последнего замера этого набора."""
    settings = repo.settings(apply_suffixes=False)
    results = run(examples, settings, layer_sets, engines)
    fp = fingerprint(examples, repo.global_key)
    versions = {
        "code": code_fingerprint(), "settings": settings_fingerprint(settings, repo.global_key),
        "models": model_revisions(models_dir) if any(name != "1-3" for name in layer_sets) else {},
    }
    if "1-5" in layer_sets:
        versions["local_model"] = local_settings(repo).model
    entry = {
        "measured_at": repo.clock.now().isoformat(timespec="seconds"), "examples": len(examples), "fingerprint": fp,
        "unit": unit, "versions": versions, "source": source or {},
        "layers": {name: summary(report) for name, report in results.items()},
    }
    with repo.lock, transaction(repo.conn):
        comparison = compare(results, baselines(repo).get(dataset, {}), fp, len(examples))
        stored = passport(repo)
        stored[dataset] = entry | {"drops": comparison.drops, "unchecked": comparison.unchecked, "warnings": comparison.warnings}
        repo.set_setting(PASSPORT_KEY, json.dumps(stored, ensure_ascii=False))
    return Measurement(results, comparison, fp, len(examples))
