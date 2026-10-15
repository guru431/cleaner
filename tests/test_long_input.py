"""Обзор 1А, P2: длинная цепочка без пробелов не должна давать квадратичное время.

Очистка не ограничена по времени, поэтому одна такая вставка заняла бы обработчик на минуту.
"""
import time

import pytest

from cleaner.core.detect import rules
from cleaner.core.detect.base import DetectContext
from cleaner.core.pipeline import DETECTORS, sanitize
from cleaner.core.restore import restore
from cleaner.core.types import ChatState, Settings


@pytest.mark.parametrize(
    "text",
    [
        "a.b." * 5000, "CN=a," * 5000, "x" * 20000, "1," * 10000, "a:" * 10000, "token" * 20000 + "=Zx81kLmN02pQ",
        "token" * 4000, "pwd" * 7000, "a_pass" * 3500, "8 " * 50000, "/home/" + "a'" * 10000,
        "CORP\\" + "и\\" * 10000, "Source" * 5000 + ":1:2", "1 - " * 25000, "123.456/" * 12500,
        "д.р. 11.11.11 " * 7000,
    ],
    ids=[
        "dotted", "dn", "letters", "commas", "colons", "long_key", "token", "pwd", "a_pass", "eights", "apostrophes",
        "cyrillic_logins", "label_colons", "spaced_dashes", "dots_slashes", "short_dates",
    ],
)
def test_every_layer_is_fast_on_a_long_run_without_spaces(text):
    ctx = DetectContext(Settings())
    for detector in DETECTORS:
        started = time.perf_counter()
        detector.detect(text, ctx)
        assert time.perf_counter() - started < 0.5, detector.name


def test_run_of_eights_gives_no_phones():
    """FINDINGS P2 «false … PHONE, CARD …»: «8 8 8 …» давал тысячи ложных телефонов, очистка шла две секунды."""
    assert rules.detect("8 " * 50000, DetectContext(Settings())) == []


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


@pytest.mark.parametrize(
    "text",
    [
        "<" * 50000, "<a>, data='x' " * 10000, "<a " * 20000 + "f(a, data='x')",
        "EMAIL_1" + " " * 50000, "//x:<EMAIL_1> " * 5000, "file:///" * 20000, "//" * 50000,
        "\\" * 100000, "/\\" * 50000, " \\\\x" * 10000, "https:" * 20000, "!http:a:" * 15000, "//a:wss:" * 15000,
        "file:\\" * 20000, "//" + "a@" * 50000, "https:@" * 20000, "//@:" * 25000,
    ],
    ids=[
        "brackets", "arguments", "open_tags", "spaced_label", "bare_links", "file_links", "slashes",
        "backslashes", "mixed_slashes", "unc_paths", "schemes", "schemes_without_slashes", "schemes_in_userinfo",
        "file_backslashes", "at_signs", "schemes_with_at_signs", "empty_users",
    ],
)
def test_restore_is_fast_on_many_tags_arguments_and_bare_links(text):
    """Участки вне тегов считаются один раз на ответ, а не для каждого атрибута; метка без ограничителей,
    адреса без схемы и «file:///» проверяются за линейное время."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, text + "<EMAIL_1>", Settings())
    assert time.perf_counter() - started < 0.5
