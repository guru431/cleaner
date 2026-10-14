"""Проверка начала этапа 2: модели слоя 4 на процессоре — скорость и качество (раздел 19 спецификации).

Запуск на машине с интернетом: модели и набор скачиваются в кэш Hugging Face.
  python scripts/checks/ner_check.py
"""
from __future__ import annotations

import csv
import io
import json
import time
import urllib.request

import torch
from gliner import GLiNER
from huggingface_hub import snapshot_download
from transformers import pipeline

RUBERT = ("redmadrobot-rnd/rubert-base-pii-ner", "c802e8cd26f85d1cf920973ea6f83965a0618d63")
GLINER = ("knowledgator/gliner-pii-base-v1.0", "61726e0ad791dcab3e29339bbec3ad42ded65641")
BENCH = (
    "https://huggingface.co/datasets/redmadrobot-rnd/pii_benchmark/resolve/"
    "f77ea831274daf980cc45c61a93c226be9d978d6/test.csv"
)
NAME_LABELS = ("FIRST_NAME", "LAST_NAME", "MIDDLE_NAME")
SAMPLE = (
    "Заявка от Петрова Ивана Сергеевича: на сервере srv-test-07 не открывается отчёт. "
    "Иванова Мария Олеговна просит проверить доступ, адрес офиса — г. Тестовск, ул. Примерная, д. 5. "
    "Contact John Smith at Example Corp for details. "
)


def words_windows(text: str, size: int = 200, overlap: int = 40) -> list[tuple[int, int]]:
    import re

    spans = [m.span() for m in re.finditer(r"\S+", text)]
    out, i = [], 0
    while spans:
        chunk = spans[i:i + size]
        out.append((chunk[0][0], chunk[-1][1]))
        if i + size >= len(spans):
            break
        i += size - overlap
    return out


def bio_spans(tokens: list[str], tags: list[str], text: str) -> list[tuple[int, int, str]]:
    """Позиции размеченных токенов в тексте: токены идут по порядку, регистр может отличаться."""
    lowered, position, offsets = text.lower(), 0, []
    for token in tokens:
        found = lowered.find(token.lower(), position)
        if found < 0:
            return []
        offsets.append((found, found + len(token)))
        position = found + len(token)
    spans: list[list] = []
    for (start, end), tag in zip(offsets, tags):
        if tag == "O":
            continue
        kind = tag[2:]
        if tag.startswith("I-") and spans and spans[-1][2] == kind:
            spans[-1][1] = end
        else:
            spans.append([start, end, kind])
    return [tuple(s) for s in spans]


def glued(found: list[tuple[int, int, str]]) -> set[tuple[int, int, str]]:
    """Обрывки одного слова одной метки («Леонтьев» + «ич») — одна находка, как склеивает их слой 4 (ner._joined)."""
    out: list[list] = []
    for start, end, label in sorted(found):
        if out and out[-1][2] == label and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end, label])
    return {tuple(s) for s in out}


def main() -> None:
    torch.set_num_threads(4)
    rubert = pipeline(
        "token-classification", model=RUBERT[0], revision=RUBERT[1],
        aggregation_strategy="simple", stride=128, device="cpu",
    )
    gliner_dir = snapshot_download(GLINER[0], revision=GLINER[1], ignore_patterns=["onnx/*", "trainer_state.json"])
    gliner = GLiNER.from_pretrained(gliner_dir)
    text = (SAMPLE * (100_000 // len(SAMPLE) + 1))[:100_000]
    started = time.perf_counter()
    rubert(text)
    middle = time.perf_counter()
    for start, end in words_windows(text):
        gliner.predict_entities(text[start:end], ["name", "organization", "location address"], threshold=0.25)
    finished = time.perf_counter()
    print(f"B1: rubert {middle - started:.1f} с, gliner {finished - middle:.1f} с, всего {finished - started:.1f} с на 100 000 знаков")

    raw = urllib.request.urlopen(BENCH, timeout=60).read().decode("utf-8")
    counts = {label: [0, 0, 0] for label in NAME_LABELS}           # верных, найдено, в эталоне
    for row in csv.DictReader(io.StringIO(raw)):
        gold = {s for s in bio_spans(json.loads(row["tokens"]), json.loads(row["ner_tags"]), row["text"]) if s[2] in NAME_LABELS}
        found = glued([
            (e["start"], e["end"], e["entity_group"]) for e in rubert(row["text"])
            if e["entity_group"] in NAME_LABELS and e["score"] >= 0.25
        ])
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
    main()
