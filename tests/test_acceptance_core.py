"""Приёмочные проверки этапа 1 на уровне ядра (TZ.md, раздел 11)."""
import ipaddress
import time

import pytest

from cleaner.core.pipeline import SanitizeResult, sanitize
from cleaner.core.restore import restore
from cleaner.core.types import DictEntry, Settings
from cleaner.core.types import EntityType as T

TEXT = (
    "Пользователь CONTOSO\\ivanov (i.ivanov@contoso.ru, +7 (916) 123-45-67, запасной 89161234567) "
    "не может войти на srv-dc01.corp.contoso.ru (10.1.2.5). "
    "Соседний узел 10.1.2.77, внешний адрес 85.143.10.20. "
    "Профиль C:\\Users\\ivanov\\Desktop, ИНН организации 7707083893. "
    "Строка подключения: Server=SRV-DC01;User Id=app;Password=P@ssw0rd!2024;\n"
    "REDACTED_PRIVATE_KEY\n"
)
SECRETS = ("P@ssw0rd!2024", "MIIEowIBAAKCAQEA1234")
CONTROL = (
    "CONTOSO", "ivanov", "i.ivanov@contoso.ru", "+7 (916) 123-45-67", "89161234567",
    "srv-dc01", "SRV-DC01", "contoso.ru", "10.1.2.5", "10.1.2.77", "85.143.10.20", "7707083893",
    *SECRETS,
)


def replacements(result: SanitizeResult, text: str) -> dict[str, str]:
    return {text[span.start:span.end]: span.surrogate for span in result.spans}


def test_ac_1_1_every_control_value_is_replaced(state, settings):
    result = sanitize(state, TEXT, settings)
    lowered = result.sanitized.lower()
    assert [value for value in CONTROL if value.lower() in lowered] == []
    assert result.deliverable


def test_ac_1_3_same_values_get_the_same_replacements(state, settings):
    first = replacements(sanitize(state, TEXT, settings), TEXT)
    again = "Повторно: CONTOSO\\ivanov, 10.1.2.5, srv-dc01.corp.contoso.ru, 89161234567"
    second = replacements(sanitize(state, again, settings), again)
    for value in ("CONTOSO", "ivanov", "10.1.2.5", "srv-dc01.corp.contoso.ru"):
        assert first[value] == second[value], value
    assert first["+7 (916) 123-45-67"] == first["89161234567"] == second["89161234567"]
    assert first["SRV-DC01"] == "HOST-1"
    assert first["srv-dc01.corp.contoso.ru"].startswith("host-1.")
    assert first["ivanov"] == "<ACCOUNT_1>"


def test_ac_1_4_subnet_private_range_and_host_octet(state, settings):
    fakes = replacements(sanitize(state, TEXT, settings), TEXT)
    a, b = fakes["10.1.2.5"], fakes["10.1.2.77"]
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    assert ipaddress.ip_address(a) in ipaddress.ip_network("10.0.0.0/8")
    assert a.endswith(".5") and b.endswith(".77")
    assert fakes["85.143.10.20"] == "203.0.113.1"


def test_round_trip_returns_everything_but_secrets(state, settings):
    result = sanitize(state, TEXT, settings)
    restored = restore(state, result.sanitized, settings).text
    # Второй формат телефона возвращается в первом написании — это одна сущность.
    expected_back = [value for value in CONTROL if value not in (*SECRETS, "89161234567")]
    assert [value for value in expected_back if value not in restored] == []
    assert not any(secret in restored for secret in SECRETS)
    assert "<SECRET_1>" in restored and "<SECRET_2>" in restored


@pytest.mark.integration
def test_layers_1_to_3_fit_the_time_budget_on_a_large_input(state):
    settings = Settings(always=tuple(DictEntry(T.ACCOUNT, f"user{n:05d}") for n in range(5000)))
    line = "2026-10-13 12:00:01 INFO user00042 вошёл с 10.1.2.5 на srv-app01.corp.contoso.ru, запрос 500100732258\n"
    text = (line * (100_000 // len(line) + 1))[:100_000]
    started = time.perf_counter()
    result = sanitize(state, text, settings)
    elapsed = time.perf_counter() - started
    assert "user00042" not in result.sanitized
    assert elapsed < 3.0, f"очистка заняла {elapsed:.1f} с"


@pytest.mark.integration
def test_large_log_with_thousands_of_distinct_values_fits_the_time_budget(state, settings):
    """Обзор 1А, P2: время не должно расти с размером таблицы замен (NFR-4)."""
    lines = [
        f"{n:05d} i.user{n}@corp{n % 97}.example.ru вошёл с 10.{n // 256 % 256}.{n % 256}.7 "
        f"на srv-app{n:04d}.corp.contoso.ru\n"
        for n in range(1400)
    ]
    text = "".join(lines)[:100_000]
    for attempt in ("первая", "повторная"):
        started = time.perf_counter()
        result = sanitize(state, text, settings)
        elapsed = time.perf_counter() - started
        assert elapsed < 3.0, f"{attempt} очистка заняла {elapsed:.1f} с"
    assert len(state.surrogates) > 3000
    assert "srv-app0042" not in result.sanitized
