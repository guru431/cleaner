"""Проверка живого экземпляра Cleaner через /api/v1 (AC-5.8) и пример клиента для своих проектов.

  CLEANER_API_KEY=ck_… python scripts/api_smoke.py --url https://example5464 --cacert cert.pem
  CLEANER_API_KEY=ck_… python scripts/api_smoke.py --url https://example5464 --cacert cert.pem --expect-revoked

Сценарий: чат → очистка контрольного текста (вымышленные почта, телефон, адрес IP, имя узла, пароль в строке
подключения) → в очищенном нет ни одного контрольного значения → восстановление очищенного → в нём все значения,
кроме пароля (секрет остаётся меткой, FR-7.7) → таблица соответствий не пуста → чат удаляется. --expect-revoked:
ключ отозван, /api/v1 отвечает 401.

Только стандартная библиотека: скрипт идёт и системным python3 сервера. Ключ — из переменной окружения, а не из
аргументов (их видно в списке процессов). В вывод — шаги и коды ответов, без текстов и ключа.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable

KEY_ENV = "CLEANER_API_KEY"
TEXT = (
    "Пишет a.petrova@kontora-primer.ru, телефон +7 (916) 555-01-23. Узел srv-app07.corp.kontora-primer.ru (10.40.50.60) "
    "не отвечает. Строка подключения: Server=srv-app07;User Id=svc;Password=Kp7#mQ2!vX9z;"
)
SECRET = "Kp7#mQ2!vX9z"
CONTROL = ("a.petrova@kontora-primer.ru", "+7 (916) 555-01-23", "srv-app07", "10.40.50.60", SECRET)
POLL_LIMIT = 180.0          # сколько ждать очистки после ответа 202, секунд

# call(метод, путь, тело JSON или None) → (код ответа, JSON ответа; {} — тела нет)
Call = Callable[[str, str, dict | None], tuple[int, object]]


def run(call: Call, expect_revoked: bool = False) -> list[str]:
    """Сценарий AC-5.8. Провалы — без значений; пустой список — успех."""
    failures: list[str] = []

    def step(name: str, method: str, path: str, body: dict | None = None, expected: int = 200) -> object:
        code, data = call(method, path, body)
        print(f"{'ок    ' if code == expected else 'ПРОВАЛ'} {name}: {code}")
        if code != expected:
            failures.append(f"{name}: код {code}, ожидался {expected}")
            return None
        return data

    if expect_revoked:
        step("отозванный ключ не принимается", "GET", "/api/v1/chats", expected=401)
        return failures
    created = step("создать чат", "POST", "/api/v1/chats", {"title": "AC-5.8 api_smoke"}, expected=201)
    if not isinstance(created, dict):
        return failures
    chat = f"/api/v1/chats/{created['id']}"
    try:
        result = _clean(step, chat)
        if result is None:
            return failures
        if result.get("status") != "done" or not result.get("deliverable"):
            failures.append(f"очистка: состояние {result.get('status')}, выдача {'есть' if result.get('deliverable') else 'нет'}")
            return failures
        sanitized = result["sanitized"]
        left = sum(value.lower() in sanitized.lower() for value in CONTROL)
        print(f"{'ок    ' if not left else 'ПРОВАЛ'} в очищенном нет контрольных значений: осталось {left}")
        if left:
            failures.append(f"очистка: в очищенном осталось контрольных значений — {left}")
        restored = step("восстановить ответ", "POST", f"{chat}/restore", {"text": sanitized})
        if isinstance(restored, dict):
            text = restored["restored"]
            missing = sum(value not in text for value in CONTROL if value != SECRET)
            secret = SECRET in text
            print(f"{'ок    ' if not missing and not secret else 'ПРОВАЛ'} восстановлено всё, кроме секрета: "
                  f"не восстановлено {missing}, секрет {'открыт' if secret else 'меткой'}")
            if missing:
                failures.append(f"восстановление: не восстановлено контрольных значений — {missing}")
            if secret:
                failures.append("восстановление: секрет восстановлен, а должен остаться меткой")
        entities = step("таблица соответствий", "GET", f"{chat}/entities")
        if isinstance(entities, list) and not entities:
            failures.append("таблица соответствий пуста")
    finally:
        step("удалить чат", "DELETE", chat, expected=204)
    return failures


def _clean(step: Callable[..., object], chat: str) -> dict | None:
    """Очистка: ответ сразу или 202 и опрос элемента, пока текст в работе."""
    first = step("очистить текст", "POST", f"{chat}/texts", {"text": TEXT, "wait": 60})
    if not isinstance(first, dict):
        return None
    deadline = time.monotonic() + POLL_LIMIT
    result = first
    while result.get("status") in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(1)
        polled = step("опрос очистки", "GET", f"{chat}/items/{first['item_id']}")
        if not isinstance(polled, dict):
            return None
        result = polled
    return result


def http_call(base_url: str, key: str, context: ssl.SSLContext | None) -> Call:
    """Запросы к экземпляру без прокси окружения: адрес Cleaner — внутренний."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

    def call(method: str, path: str, body: dict | None) -> tuple[int, object]:
        request = urllib.request.Request(
            base_url.rstrip("/") + path, method=method,
            data=None if body is None else json.dumps(body).encode("utf-8"),
            headers={"X-Cleaner-Key": key, "Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with opener.open(request, timeout=120) as response:
                code, raw = response.status, response.read()
        except urllib.error.HTTPError as exc:
            code, raw = exc.code, exc.read()
        return code, json.loads(raw) if raw else {}

    return call


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка экземпляра Cleaner через /api/v1 (AC-5.8)")
    parser.add_argument("--url", required=True, help="адрес экземпляра, например https://example5464")
    parser.add_argument("--cacert", help="сертификат экземпляра (самоподписанный) для проверки TLS")
    parser.add_argument("--expect-revoked", action="store_true", help="ключ отозван: ждать 401")
    args = parser.parse_args(argv)
    key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        print(f"нет ключа: задайте переменную окружения {KEY_ENV}", file=sys.stderr)
        return 2
    context = ssl.create_default_context(cafile=args.cacert) if args.cacert else None
    failures = run(http_call(args.url, key, context), args.expect_revoked)
    print("итог: ок" if not failures else f"итог: провалов — {len(failures)}")
    for failure in failures:
        print(f"  {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
