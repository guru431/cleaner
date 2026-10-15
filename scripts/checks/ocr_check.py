"""Проверка начала этапа 2: качество и скорость ocr-ru на сканах владельца (раздел 19 спецификации).

  CLEANER_GATEWAY_KEY=… python scripts/checks/ocr_check.py http://example:30000 <каталог для результата> <файлы PNG/JPEG>…
Ключ берётся из окружения и никуда не выводится. Результат — markdown по странице рядом с именем файла.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def ocr(gateway: str, key: str, image: bytes) -> dict:
    body = json.dumps({"model": "ocr-ru", "image": base64.b64encode(image).decode("ascii")}).encode("utf-8")
    for _ in range(10):
        request = urllib.request.Request(
            f"{gateway.rstrip('/')}/pages/ocr", data=body, method="POST",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=1300) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code != 503:
                return {"error": exc.code, "body": exc.read().decode("utf-8", "replace")[:200]}
            time.sleep(min(60, int(exc.headers.get("Retry-After") or 10)))
    return {"error": 503}


def main() -> None:
    gateway, out, files = sys.argv[1], Path(sys.argv[2]), [Path(p) for p in sys.argv[3:]]
    key = os.environ["CLEANER_GATEWAY_KEY"]
    out.mkdir(parents=True, exist_ok=True)
    for path in files:
        started = time.perf_counter()
        answer = ocr(gateway, key, path.read_bytes())
        seconds = time.perf_counter() - started
        if "markdown" in answer:
            (out / f"{path.stem}.md").write_text(answer["markdown"], encoding="utf-8")
            print(f"D: {path.name}: {seconds:.0f} с, знаков {answer.get('chars')}, "
                  f"покрытие {answer.get('coverage_ratio')}, латинизированных слов {answer.get('homoglyph_words')}")
        else:
            print(f"D: {path.name}: отказ {answer.get('error')}")


if __name__ == "__main__":
    main()
