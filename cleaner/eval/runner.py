"""Прогон эталонного набора по слоям 1–3, 1–4, 1–5 (QA-5) и сравнение с базовым замером (QA-6)."""
from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cleaner.core.pipeline import Layers, sanitize
from cleaner.core.types import ChatState, EntityType, Settings
from cleaner.eval.metrics import CLASSES, Example, GoldSpan, Predict, Report, evaluate, recall_by_class

LAYER_SETS = ("1-3", "1-4", "1-5")
BASELINE_KEY = "eval.baseline"


def example_from(text: str, spans: Sequence[dict]) -> Example:
    return Example(text, tuple(
        GoldSpan(int(s["start"]), int(s["end"]), EntityType(s["type"]), int(s["entity"]), s.get("origin", ""))
        for s in spans
    ))


def gold_examples(repo) -> list[Example]:
    return [example_from(row.text, row.spans) for row in repo.gold()]


def jsonl_examples(path: Path) -> list[Example]:
    examples = []
    for line in path.read_text(encoding="utf-8").splitlines():
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
    return {name: evaluate(examples, predictor(settings, layers_for(name, engines))) for name in layer_sets}


def format_results(results: dict[str, Report], count: int) -> str:
    lines = [f"Примеров: {count}"]
    for name, report in results.items():
        lines += ["", f"Слои {name}", "Тип | полнота (скрыто/всего) | точность (верных/найдено)"]
        for type_ in sorted(set(report.entities) | set(report.found), key=lambda t: t.value):
            total, hidden = report.entities[type_], report.protected[type_]
            found, correct = report.found[type_], report.correct[type_]
            recall = f"{hidden / total:.3f} ({hidden}/{total})" if total else "—"
            precision = f"{correct / found:.3f} ({correct}/{found})" if found else "—"
            lines.append(f"{type_.value} | {recall} | {precision}")
        lines.append("Класс QA-3 | полнота | цель")
        recalls = recall_by_class(report)
        for title, _, target in CLASSES:
            if title in recalls:
                verdict = "цель не задана" if target is None else (
                    f"{target:.2f} — достигнута" if recalls[title] >= target else f"{target:.2f} — не достигнута"
                )
                lines.append(f"{title} | {recalls[title]:.3f} | {verdict}")
        share = report.overmasked / report.candidates if report.candidates else 0.0
        lines.append(
            f"Лишние замены среди версий, кодов ошибок и общеизвестных доменов: "
            f"{report.overmasked}/{report.candidates} ({share:.3f})"
        )
    return "\n".join(lines)


def compare(results: dict[str, Report], baseline: dict[str, dict[str, float]]) -> list[str]:
    """QA-6: изменение не принимается, если полнота любого класса упала против базового замера."""
    drops = []
    for name, report in results.items():
        before = baseline.get(name, {})
        for title, value in recall_by_class(report).items():
            if title in before and value < before[title] - 1e-9:
                drops.append(f"слои {name}, «{title}»: {before[title]:.3f} → {value:.3f}")
    return drops


def load_baseline(repo) -> dict[str, dict[str, float]]:
    raw = repo.setting(BASELINE_KEY)
    return json.loads(raw) if raw else {}


def save_baseline(repo, results: dict[str, Report]) -> None:
    """Только полноты по классам — без текстов: хранится открыто в settings."""
    repo.set_setting(BASELINE_KEY, json.dumps({name: recall_by_class(r) for name, r in results.items()}, ensure_ascii=False))
