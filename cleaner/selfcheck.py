"""Самопроверка: подложенные значения должны быть скрыты и возвращены."""
from __future__ import annotations

from collections.abc import Callable

from cleaner.core.pipeline import sanitize
from cleaner.core.restore import restore
from cleaner.core.types import ChatState, EntityType, Settings

SECRET = "Zx9!kLm2#Qp"
TEXT = (
    "Сотрудник KONTORA\\sidorov (p.sidorov@kontora-test.ru, +7 (900) 555-01-02) пишет с узла "
    "ws-0142.office.kontora-test.ru, адрес 10.20.30.40, шлюз 10.20.30.1. "
    f"ИНН 7707083893. Password={SECRET}; профиль C:\\Users\\sidorov\\AppData."
)
CANARIES = (
    "KONTORA", "sidorov", "p.sidorov@kontora-test.ru", "+7 (900) 555-01-02",
    "ws-0142.office.kontora-test.ru", "kontora-test.ru", "10.20.30.40", "10.20.30.1",
    "7707083893", SECRET,
)


def run(report: Callable[[str], None]) -> int:
    """0 — все подложенные значения скрыты и возвращены; 1 — нет. Строки отчёта уходят в report."""
    state = ChatState(chat_id="selfcheck", net_key=bytes(32))
    settings = Settings()
    result = sanitize(state, TEXT, settings)
    lowered = result.sanitized.lower()
    failures = [f"не скрыто: {value}" for value in CANARIES if value.lower() in lowered]
    if not result.deliverable:
        failures.append("проверка утечек нашла оригинал в очищенном тексте")
    secret_label = next(
        (span.surrogate for span in result.spans
         if state.entities[span.entity_id].type is EntityType.SECRET),
        SECRET,
    )
    if restore(state, result.sanitized, settings).text != TEXT.replace(SECRET, secret_label):
        failures.append("восстановленный текст отличается от исходного")
    for failure in failures:
        report(f"FAIL: {failure}")
    if not failures:
        report(f"OK: подложенные значения скрыты и восстановлены ({len(CANARIES)})")
    return 1 if failures else 0
