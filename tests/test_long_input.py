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
    ],
    ids=["dotted", "dn", "letters", "commas", "colons", "long_key", "token", "pwd", "a_pass", "eights"],
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


@pytest.mark.parametrize(
    "text",
    ['url("' * 20000, "url(" * 25000, "@import '" * 12000, 'url("\\' * 16000, "url(\\" * 20000, "url('\\'" * 12000],
    ids=["quoted", "unquoted", "import", "quoted_escape", "unquoted_escape", "escaped_quotes"],
)
def test_restore_is_fast_on_unclosed_css_urls(text):
    """CSS url() и @import без закрывающей кавычки или скобки не дают квадратичного времени."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, text + "<EMAIL_1>", Settings())
    assert time.perf_counter() - started < 0.5
