"""Скачать открытые русские наборы (QA-4) и записать их в формате eval (JSONL). Нужен интернет; только для разработки.

  python scripts/fetch_open_sets.py data/open-sets
  python -m cleaner eval --jsonl data/open-sets/pii_benchmark.jsonl --layers 1-3 1-4
Каталог data/ — в .gitignore: наборы в репозиторий не попадают. Рядом с каждым набором — манифест (источник, ревизия,
sha256, версия конвертера, число примеров); eval --jsonl сверяет с ним файл. Изменившийся снимок занимает основное
имя, а прежний (с манифестом, если был) сохраняется рядом под именем с началом своего sha256.
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

from cleaner.eval.datasets import bio_to_spans, convert, write_snapshot  # noqa: E402

PII_BENCHMARK_REPO = "redmadrobot-rnd/pii_benchmark"
PII_BENCHMARK_REVISION = "f77ea831274daf980cc45c61a93c226be9d978d6"
PII_BENCHMARK = f"https://huggingface.co/datasets/{PII_BENCHMARK_REPO}/resolve/{PII_BENCHMARK_REVISION}/test.csv"
ROWS = "https://datasets-server.huggingface.co/rows"
API = "https://huggingface.co/api/datasets/"


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


def revision(dataset: str) -> str:
    """Ревизия набора на момент загрузки: datasets-server отдаёт последнюю и закрепить её не даёт —
    воспроизводимость держит sha256 снимка в манифесте."""
    with urllib.request.urlopen(API + dataset, timeout=60) as response:
        return str(json.load(response).get("sha", ""))


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
    written = [write_snapshot(out, "pii_benchmark", benchmark, PII_BENCHMARK_REPO, PII_BENCHMARK_REVISION, True)]
    hivetrace_revision = revision("hivetrace/pii-bench")
    hivetrace = [
        convert(row["text"], [(e["start"], e["end"], e["type"]) for e in row["entities"]], unmapped)
        for split in ("entity", "domain") for row in rows("hivetrace/pii-bench", split)
    ]
    written.append(write_snapshot(out, "hivetrace", hivetrace, "hivetrace/pii-bench", hivetrace_revision, False))
    jayguard_revision = revision("just-ai/jayguard-ner-benchmark")
    jayguard = [convert(*bio_to_spans(row["tokens"], row["ner_tags"]), unmapped) for row in rows("just-ai/jayguard-ner-benchmark", "train")]
    written.append(write_snapshot(out, "jayguard", jayguard, "just-ai/jayguard-ner-benchmark", jayguard_revision, False))
    print(f"pii_benchmark: {len(benchmark)} примеров (пропущено {skipped}), hivetrace: {len(hivetrace)}, jayguard: {len(jayguard)}")
    print("Записано:", ", ".join(path.name for path in written))
    print("Метки, не вошедшие в измерение:", ", ".join(f"{label} ({count})" for label, count in unmapped.most_common()) or "нет")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]))
