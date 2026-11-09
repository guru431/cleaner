"""Фоновые задания: извлечение текста, слои 4 и 5, запросы к локальной модели (раздел 14 спецификации).

Пулы потоков в процессе службы: общий из двух, свои у разбора файлов и отправок облаку (app.create_app).
Состояние пишет само задание — в items.status; страница опрашивает его раз в секунду. Очередь не переживает
перезапуск: прерванное становится failed (NFR-6).
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import Executor, Future, ThreadPoolExecutor, wait
from datetime import datetime, timezone

from cleaner.queueing import Budget, Reservation

log = logging.getLogger("cleaner.jobs")

WORKERS = 2
INTERRUPTED = "Обработка прервана перезапуском службы: запустите её ещё раз"
# Разбор файла до извлечения текста повторить нельзя: файл не хранится (как FILE_CANCELLED).
FILE_INTERRUPTED = "Обработка прервана перезапуском службы, а исходный файл не хранится: загрузите файл ещё раз"
# Сколько остановка службы ждёт идущие задания. systemd ждёт остановки 90 с, а страница распознавания
# идёт до минуты: дольше ждать незачем, недождавшиеся помечаются прерванными.
STOP_WAIT = 30.0
MAX_WAIT = 300.0
CANCELLED = "Отменено до начала обработки: запустите её ещё раз"
FILE_CANCELLED = "Отменено до начала обработки, а исходный файл не хранится: загрузите файл ещё раз"
EXPIRED = "Время ожидания истекло: запустите обработку ещё раз"
# Без срока ожидания: разбор файла. Его память уже учтена в бюджете (Budget), отменить его можно в очереди, а пакет
# сканов на двух потоках идёт дольше любого срока (5 страниц по ≈72 с — 6 минут на файл): хвост пакета истекал бы
# всегда, а повторить нечего — файл не хранится.
_NO_DEADLINE = frozenset({"file"})


def _cancelled(kind: str) -> str:
    return FILE_CANCELLED if kind == "file" else CANCELLED


class Task:
    def __init__(self, fn, args, reservation, user, chat, item, kind, cancelled, now):
        self.id = uuid.uuid4().hex
        self.fn, self.args, self.reservation = fn, args, reservation
        self.user, self.chat, self.item, self.kind = user, chat, item, kind
        self.cancelled = cancelled
        self.state = "queued"
        self.created = now().isoformat()
        self.lock = threading.RLock()
        self.future: Future | None = None
        self.timer: threading.Timer | None = None

    def run(self):
        with self.lock:
            if self.state != "queued":
                return
            self.state = "running"
            fn, args = self.fn, self.args
            self.fn, self.args = None, ()
            if self.timer:
                self.timer.cancel()
        _run(fn, args)

    def cancel(self, reason):
        with self.lock:
            if self.state != "queued":
                return False
            self.state = "cancelled"
            # Future.cancel сам по себе оставляет аргументы в очереди ThreadPoolExecutor до следующего worker.
            self.fn, self.args = None, ()
            if self.timer:
                self.timer.cancel()
            if self.future:
                self.future.cancel()
        try:
            if self.cancelled:
                self.cancelled(reason)
        except Exception as exc:
            log.error("отмена задания: %s", type(exc).__name__)
        finally:
            self.reservation.release()
        return True


class Jobs:
    def __init__(self, executor: Executor | None = None, stop_wait: float = STOP_WAIT,
                 budget: Budget | None = None, max_wait: float = MAX_WAIT, now=None):
        self._executor = executor or ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="cleaner-job")
        self._stop_wait = stop_wait
        self.budget = budget or Budget()
        self.max_wait = max_wait
        self.now = now or (lambda: datetime.now(timezone.utc))
        self._tasks: dict[str, Task] = {}
        self._lock = threading.RLock()
        # add, discard и копия set(...) в shutdown атомарны под GIL (копия множества идёт в C без обхода на Python):
        # отдельный замок не нужен.
        self._pending: set[Future] = set()

    def submit(self, fn: Callable[..., None], *args: object) -> None:
        reservation = self.budget.reserve("")
        self.submit_reserved(fn, args, reservation)

    def submit_reserved(self, fn, args, reservation: Reservation, *, user="", chat="", item="", kind="",
                        cancelled=None) -> None:
        task = Task(fn, args, reservation, user, chat, item, kind, cancelled, self.now)
        reservation.attached = True
        with self._lock:
            self._tasks[task.id] = task
        try:
            future = self._executor.submit(task.run)
        except BaseException:
            with self._lock:
                self._tasks.pop(task.id, None)
            reservation.release()
            raise
        task.future = future
        self._pending.add(future)

        def finished(future):
            self._pending.discard(future)
            if future.cancelled():
                task.cancel(FILE_INTERRUPTED if kind == "file" else INTERRUPTED)
            if task.timer:
                task.timer.cancel()
            reservation.release()
            with self._lock:
                self._tasks.pop(task.id, None)

        future.add_done_callback(finished)
        with task.lock:
            if task.state == "queued" and not future.done() and kind not in _NO_DEADLINE:
                task.timer = threading.Timer(self.max_wait, task.cancel, (EXPIRED,))
                task.timer.daemon = True
                task.timer.start()

    def owned(self, user: str) -> list[dict]:
        with self._lock:
            return [{"id": t.id, "chat_id": t.chat, "item_id": t.item, "kind": t.kind,
                     "status": t.state, "created_at": t.created, "cancellable": t.state == "queued"}
                    for t in self._tasks.values() if t.user == user]

    def cancel(self, task_id: str, user: str) -> bool | None:
        with self._lock:
            task = self._tasks.get(task_id)
        return task.cancel(_cancelled(task.kind)) if task is not None and task.user == user else None

    def cancel_chat(self, chat: str) -> None:
        with self._lock:
            tasks = [t for t in self._tasks.values() if t.chat == chat]
        for task in tasks:
            task.cancel(_cancelled(task.kind))

    def shutdown(self) -> int:
        return shutdown(self)


def shutdown(*pools: Jobs) -> int:
    """Остановка службы: новые задания не принимаются, ждущие в очереди отменяются сразу во всех пулах, идущие —
    ждём вместе не дольше stop_wait секунд. По очереди пул файлов брал бы следующий скан, пока ждётся общий,
    а остановка росла бы на stop_wait с каждым пулом. Возвращает число недождавшихся: их элементы помечает
    прерванными вызывающий, пока соединение с базой открыто (app.lifespan)."""
    for pool in pools:
        pool._executor.shutdown(wait=False, cancel_futures=True)
    started, unfinished = time.monotonic(), 0
    for pool in pools:                   # срок у каждого пула свой, отсчёт — от общего начала
        _, left = wait(set(pool._pending), timeout=max(0.0, pool._stop_wait - (time.monotonic() - started)))
        unfinished += len(left)
    return unfinished


def _run(fn: Callable[..., None], args: tuple[object, ...]) -> None:
    """Задание само отмечает отказ в элементе; сюда доходит только непредвиденное — в лог по виду, без текста (SEC-11)."""
    try:
        fn(*args)
    except Exception as exc:
        log.error("фоновое задание %s: %s", getattr(fn, "__name__", "?"), type(exc).__name__)
