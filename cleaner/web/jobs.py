"""Фоновые задания: извлечение текста, слои 4 и 5, запросы к локальной модели (раздел 14 спецификации).

Пул из двух потоков в процессе службы. Состояние пишет само задание — в items.status; страница
опрашивает его раз в секунду. Очередь не переживает перезапуск: прерванное становится failed (NFR-6).
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import Executor, Future, ThreadPoolExecutor, wait

log = logging.getLogger("cleaner.jobs")

WORKERS = 2
INTERRUPTED = "Обработка прервана перезапуском службы: запустите её ещё раз"
# Сколько остановка службы ждёт идущие задания. systemd ждёт остановки 90 с, а страница распознавания
# идёт до минуты: дольше ждать незачем, недождавшиеся помечаются прерванными.
STOP_WAIT = 30.0


class Jobs:
    def __init__(self, executor: Executor | None = None, stop_wait: float = STOP_WAIT):
        self._executor = executor or ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="cleaner-job")
        self._stop_wait = stop_wait
        self._pending: set[Future] = set()      # add и discard атомарны под GIL: отдельный замок не нужен

    def submit(self, fn: Callable[..., None], *args: object) -> None:
        future = self._executor.submit(_run, fn, args)
        self._pending.add(future)
        future.add_done_callback(self._pending.discard)

    def shutdown(self) -> int:
        """Остановка службы: новые задания не принимаются, ждущие в очереди отменяются, идущие — ждём не
        дольше stop_wait секунд. Возвращает число недождавшихся: их элементы помечает прерванными
        вызывающий, пока соединение с базой открыто (app.lifespan)."""
        self._executor.shutdown(wait=False, cancel_futures=True)
        _, unfinished = wait(set(self._pending), timeout=self._stop_wait)
        return len(unfinished)


def _run(fn: Callable[..., None], args: tuple[object, ...]) -> None:
    """Задание само отмечает отказ в элементе; сюда доходит только непредвиденное — в лог по виду, без текста (SEC-11)."""
    try:
        fn(*args)
    except Exception as exc:
        log.error("фоновое задание %s: %s", getattr(fn, "__name__", "?"), type(exc).__name__)
