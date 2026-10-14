"""Фоновые задания: извлечение текста, слои 4 и 5, запросы к локальной модели (раздел 14 спецификации).

Пул из двух потоков в процессе службы. Состояние пишет само задание — в items.status; страница
опрашивает его раз в секунду. Очередь не переживает перезапуск: прерванное становится failed (NFR-6).
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import Executor, ThreadPoolExecutor

log = logging.getLogger("cleaner.jobs")

WORKERS = 2
INTERRUPTED = "Обработка прервана перезапуском службы: запустите её ещё раз"


class Jobs:
    def __init__(self, executor: Executor | None = None):
        self._executor = executor or ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="cleaner-job")

    def submit(self, fn: Callable[..., None], *args: object) -> None:
        self._executor.submit(_run, fn, args)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


def _run(fn: Callable[..., None], args: tuple[object, ...]) -> None:
    """Задание само отмечает отказ в элементе; сюда доходит только непредвиденное — в лог по виду, без текста (SEC-11)."""
    try:
        fn(*args)
    except Exception as exc:
        log.error("фоновое задание %s: %s", getattr(fn, "__name__", "?"), type(exc).__name__)
