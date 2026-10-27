"""Проверка начала этапа 2: модели слоя 4 на процессоре — скорость и качество (раздел 19 спецификации).

  python scripts/checks/ner_check.py [каталог моделей, по умолчанию models]
Модели — каталог после models download, разметка — классы слоя 4 (ner_models), эталон B2 — разбор BIO открытых наборов
(eval.datasets), адрес набора B2 — scripts/fetch_open_sets.py: своих копий ревизий, меток, порога и окон у проверки нет.
Набор B2 скачивается (нужен интернет).
"""
from __future__ import annotations

import csv
import io
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cleaner.core.detect.ner import THRESHOLD  # noqa: E402
from cleaner.core.detect.ner_models import GlinerTagger, RubertTagger  # noqa: E402
from cleaner.eval.datasets import bio_to_spans  # noqa: E402
from cleaner.models import GLINER_DIR, RUBERT_DIR  # noqa: E402
from scripts.fetch_open_sets import PII_BENCHMARK  # noqa: E402

NAME_LABELS = ("FIRST_NAME", "LAST_NAME", "MIDDLE_NAME")
SAMPLE = (
    "Заявка от Петрова Ивана Сергеевича: на сервере srv-test-07 не открывается отчёт. "
    "Иванова Мария Олеговна просит проверить доступ, адрес офиса — г. Тестовск, ул. Примерная, д. 5. "
    "Contact John Smith at Example Corp for details. "
)


def glued(found: list[tuple[int, int, str]]) -> set[tuple[int, int, str]]:
    """Обрывки одного слова одной метки («Леонтьев» + «ич») — одна находка, как склеивает их слой 4 (ner._joined)."""
    out: list[list] = []
    for start, end, label in sorted(found):
        if out and out[-1][2] == label and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end, label])
    return {tuple(s) for s in out}


def main(models: Path) -> None:
    rubert, gliner = RubertTagger(models / RUBERT_DIR), GlinerTagger(models / GLINER_DIR)
    text = (SAMPLE * (100_000 // len(SAMPLE) + 1))[:100_000]
    started = time.perf_counter()
    rubert.tag(text)
    middle = time.perf_counter()
    gliner.tag(text)
    finished = time.perf_counter()
    print(f"B1: rubert {middle - started:.1f} с, gliner {finished - middle:.1f} с, всего {finished - started:.1f} с на 100 000 знаков")

    with urllib.request.urlopen(PII_BENCHMARK, timeout=60) as response:
        raw = response.read().decode("utf-8")
    counts = {label: [0, 0, 0] for label in NAME_LABELS}           # верных, найдено, в эталоне
    for row in csv.DictReader(io.StringIO(raw)):
        parsed = bio_to_spans(json.loads(row["tokens"]), json.loads(row["ner_tags"]), row["text"])
        if parsed is None:
            continue                    # токенов нет в тексте — пример пропускается, как в scripts/fetch_open_sets.py
        gold = {s for s in parsed[1] if s[2] in NAME_LABELS}
        found = glued([(f.start, f.end, f.label) for f in rubert.tag(row["text"]) if f.label in NAME_LABELS and f.score >= THRESHOLD])
        for label in NAME_LABELS:
            g = {s for s in gold if s[2] == label}
            f = {s for s in found if s[2] == label}
            counts[label][0] += len(g & f)
            counts[label][1] += len(f)
            counts[label][2] += len(g)
    for label, (hit, found, gold) in counts.items():
        precision = hit / found if found else 0.0
        recall = hit / gold if gold else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        print(f"B2: {label}: P={precision:.3f} R={recall:.3f} F1={f1:.3f} (эталонных {gold})")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]) if len(sys.argv) == 2 else Path("models"))
