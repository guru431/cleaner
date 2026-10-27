"""Проверка начала этапа 4: соблюдает ли модель за шлюзом схему JSON слоя 5 (раздел 19 спецификации).

  CLEANER_GATEWAY_KEY=… python scripts/checks/llm_schema_check.py http://example:30000/v1 qwen-27b qwen-27b-fast
Типы и схема ответа — слоя 5 (cleaner.core.detect.llm): своих копий у проверки нет.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cleaner.core.detect.llm import SCHEMA, TYPES  # noqa: E402

TEXT = (
    "Пользователь <PERSON_1> сообщил, что на host-3.domain-1.example не входит в почту. "
    "Пароль от общего ящика он записал на стикере: sunflower77. Руководитель проекта — Сидоров."
)
PROMPT = (
    "Найди в тексте строки, которые ещё выдают человека, организацию, учётные данные или внутреннюю инфраструктуру. "
    "Замены вида <PERSON_1>, host-3, domain-1.example не трогай. Выпиши каждую строку дословно. "
    'Ответ — только JSON: {"items": [{"text": "…", "type": "' + "|".join(TYPES) + '"}]}.'
)


def valid(content: str) -> bool:
    try:
        data = json.loads(content.strip().removeprefix("```json").removesuffix("```"))
    except ValueError:
        return False
    items = data.get("items") if isinstance(data, dict) else None
    return isinstance(items, list) and all(
        isinstance(i, dict) and isinstance(i.get("text"), str) and i.get("type") in TYPES for i in items
    )


def ask(base: str, key: str, model: str, schema: bool) -> tuple[bool, str, float]:
    body = {
        "model": model, "temperature": 0, "max_tokens": 2048,
        "messages": [{"role": "system", "content": PROMPT}, {"role": "user", "content": TEXT}],
    }
    if schema:
        body["response_format"] = {"type": "json_schema", "json_schema": {"name": "cleaner", "schema": SCHEMA, "strict": True}}
    request = urllib.request.Request(
        f"{base.rstrip('/')}/chat/completions", data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            choice = json.load(response)["choices"][0]
    except urllib.error.HTTPError as exc:
        return False, f"http {exc.code}", time.perf_counter() - started
    content = choice["message"].get("content") or ""
    return valid(content) and choice.get("finish_reason") != "length", choice.get("finish_reason", "?"), time.perf_counter() - started


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    base, models = sys.argv[1], sys.argv[2:]
    key = os.environ["CLEANER_GATEWAY_KEY"]
    for model in models:
        for schema in (True, False):
            runs = [ask(base, key, model, schema) for _ in range(20)]
            ok = sum(1 for good, _, _ in runs if good)
            reasons = sorted({reason for _, reason, _ in runs})
            print(f"E: {model}, {'response_format' if schema else 'схема в тексте'}: {ok}/20, "
                  f"медиана {statistics.median(t for _, _, t in runs):.1f} с, finish_reason {reasons}")


if __name__ == "__main__":
    main()
