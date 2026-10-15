"""Обзор 1А, P2: длинная цепочка без пробелов не должна давать квадратичное время.

Очистка не ограничена по времени, поэтому одна такая вставка заняла бы обработчик на минуту.
"""
import time

import pytest

from cleaner.core.detect.base import DetectContext
from cleaner.core.pipeline import DETECTORS, sanitize
from cleaner.core.restore import restore
from cleaner.core.types import ChatState, Settings


@pytest.mark.parametrize(
    "text",
    [
        "a.b." * 5000, "CN=a," * 5000, "x" * 20000, "1," * 10000, "a:" * 10000, "token" * 20000 + "=Zx81kLmN02pQ",
        "token" * 4000, "pwd" * 7000, "a_pass" * 3500, "8 " * 50000,
        # Правила detect-secrets: «//…» (NpmDetector), пробелы после слова ключа (IBM, Cloudant, Softlayer),
        # «eyJ» и «sk-» без начала слова (JWT, OpenAI), один токен много раз на строке выгрузки JSON.
        "/home/" * 20000, " token" + " " * 5000 + "!", " secret_key" + " " * 5000 + "!", "eyJ" * 30000,
        "sk-" * 30000, '{"account_sid":"AC' + "0123456789abcdef" * 2 + '","n":1},' * 2000, "token=" * 20000,
        "password=P;" + "Ab " * 30000, "password=P" + ";Ab Cd" * 15000, "PWD=/" * 20000, "token=${a}" * 10000,
        "net use \\\\a\\b" + " /x" * 30000 + " ", "mysql -u " * 10000, '<add key="pass" value="x"' * 4000,
    ],
    ids=["dotted", "dn", "letters", "commas", "colons", "long_key", "token", "pwd", "a_pass", "eights",
         "slashes", "spaced_key", "spaced_secret_key", "eyj", "sk", "same_token", "token_pairs",
         "spaced_field", "spaced_fields", "pwd_paths", "token_templates", "net_use", "mysql", "add_key"],
)
def test_every_layer_is_fast_on_a_long_run_without_spaces(text):
    ctx = DetectContext(Settings())
    for detector in DETECTORS:
        started = time.perf_counter()
        detector.detect(text, ctx)
        assert time.perf_counter() - started < 0.5, detector.name


def test_restore_is_fast_on_a_host_name_of_many_parts():
    """Обзор пакета исправлений 1А, P2: проверка хоста ссылки шла квадратичное время."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "узел srv-dc01.corp.contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, "https://" + "a." * 20000 + "x", Settings())
    assert time.perf_counter() - started < 0.5


def test_restore_is_fast_on_many_reference_brackets():
    """Обзор партии P1: «]: <» по всей строке давал квадратичное время восстановления."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, "]: <" * 25000, Settings())
    assert time.perf_counter() - started < 0.5
