"""Скачать открытые русские наборы (QA-4) и записать их в формате eval (JSONL). Нужен интернет; только для разработки.

  python scripts/fetch_open_sets.py data/open-sets
  python -m cleaner eval --jsonl data/open-sets/pii_benchmark.jsonl --layers 1-3 1-4
Каталог data/ — в .gitignore: наборы в репозиторий не попадают.
"""
from __future__ import annotations

import csv
import io
import json
import sys
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cleaner.eval.datasets import bio_to_spans, convert  # noqa: E402

PII_BENCHMARK = (
    "https://huggingface.co/datasets/redmadrobot-rnd/pii_benchmark/resolve/"
    "f77ea831274daf980cc45c61a93c226be9d978d6/test.csv"
)
ROWS = "https://datasets-server.huggingface.co/rows"


def rows(dataset: str, split: str) -> Iterator[dict]:
    offset = 0
    while True:
        query = urllib.parse.urlencode({"dataset": dataset, "config": "default", "split": split, "offset": offset, "length": 100})
        with urllib.request.urlopen(f"{ROWS}?{query}", timeout=60) as response:
            page = json.load(response).get("rows", [])
        if not page:
            return
        for row in page:
            yield row["row"]
        offset += len(page)


def write(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            if record["spans"]:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    unmapped: Counter = Counter()
    skipped = 0
    benchmark = []
    raw = urllib.request.urlopen(PII_BENCHMARK, timeout=120).read().decode("utf-8")
    for row in csv.DictReader(io.StringIO(raw)):
        parsed = bio_to_spans(json.loads(row["tokens"]), json.loads(row["ner_tags"]), row["text"])
        if parsed is None:
            skipped += 1
            continue
        benchmark.append(convert(*parsed, unmapped))
    write(out / "pii_benchmark.jsonl", benchmark)
    hivetrace = [
        convert(row["text"], [(e["start"], e["end"], e["type"]) for e in row["entities"]], unmapped)
        for split in ("entity", "domain") for row in rows("hivetrace/pii-bench", split)
    ]
    write(out / "hivetrace.jsonl", hivetrace)
    jayguard = [convert(*bio_to_spans(row["tokens"], row["ner_tags"]), unmapped) for row in rows("just-ai/jayguard-ner-benchmark", "train")]
    write(out / "jayguard.jsonl", jayguard)
    print(f"pii_benchmark: {len(benchmark)} примеров (пропущено {skipped}), hivetrace: {len(hivetrace)}, jayguard: {len(jayguard)}")
    print("Метки, не вошедшие в измерение:", ", ".join(f"{label} ({count})" for label, count in unmapped.most_common()) or "нет")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
