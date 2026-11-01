"""Покрытие собственного эталона: только счётчики и явные отметки проверившего."""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from cleaner.core.types import EntityType
from cleaner.eval.metrics import CLASSES

SCENARIOS = (
    ("log", "Журнал"), ("config", "Конфигурация"), ("correspondence", "Переписка"),
    ("document", "Документ"), ("agent", "Диалог агента"),
)
CHECKS = (
    ("word_forms", "Формы слов проверены"), ("repeated", "Все повторные упоминания проверены"),
    ("false_positives", "Ложные срабатывания проверены"), ("extraction", "Полнота извлечения проверена"),
)


def metadata(scenario: str = "", checks: Sequence[str] = ()) -> dict:
    if scenario and scenario not in dict(SCENARIOS):
        raise ValueError("Неизвестный сценарий эталона")
    if set(checks) - dict(CHECKS).keys():
        raise ValueError("Неизвестная отметка проверки эталона")
    return {"scenario": scenario, "checks": sorted(set(checks))}


def matrix(examples: Sequence) -> dict:
    scenarios = (*SCENARIOS, ("", "Не указан"))
    counts: Counter = Counter()
    checked: Counter = Counter()
    repeated = 0
    for row in examples:
        scenario = row.metadata.get("scenario", "")
        scenario = scenario if scenario in dict(SCENARIOS) else ""
        checked.update(set(row.metadata.get("checks", ())) & dict(CHECKS).keys())
        entities: dict[int, list[dict]] = {}
        for span in row.spans:
            entities.setdefault(span["entity"], []).append(span)
        repeated += sum(len(mentions) > 1 for mentions in entities.values())
        for title, belongs, _ in CLASSES:
            if any(belongs(EntityType(s["type"]), s.get("origin", "")) for s in row.spans):
                counts[title, scenario] += 1
    return {
        "scenarios": scenarios,
        "rows": [{"title": title, "cells": [counts[title, scenario] for scenario, _ in scenarios]} for title, _, _ in CLASSES],
        "checks": [(label, checked[key]) for key, label in CHECKS],
        "repeated": repeated,
    }
