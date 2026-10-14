"""Обзор 1А, P2: длинная цепочка без пробелов не должна давать квадратичное время.

Очистка не ограничена по времени, поэтому одна такая вставка заняла бы обработчик на минуту.
"""
import time

import pytest

from cleaner.core.detect.base import DetectContext
from cleaner.core.pipeline import DETECTORS
from cleaner.core.types import Settings


@pytest.mark.parametrize(
    "text",
    ["a.b." * 5000, "CN=a," * 5000, "x" * 20000, "1," * 10000, "a:" * 10000],
    ids=["dotted", "dn", "letters", "commas", "colons"],
)
def test_every_layer_is_fast_on_a_long_run_without_spaces(text):
    ctx = DetectContext(Settings())
    for detector in DETECTORS:
        started = time.perf_counter()
        detector.detect(text, ctx)
        assert time.perf_counter() - started < 0.5, detector.name
