"""Общий бюджет работы службы: резерв до чтения файла и до записи задания в БД."""
from __future__ import annotations

import threading


class QueueFull(Exception):
    def __init__(self, personal: bool = False):
        self.status = 429 if personal else 503
        self.retry_after = 5
        super().__init__("Личная очередь заполнена: повторите позже" if personal else "Служба занята: повторите позже")


class Budget:
    def __init__(self, jobs: int = 64, bytes_: int = 512 * 1024 * 1024,
                 user_jobs: int = 16, user_bytes: int = 256 * 1024 * 1024):
        self.max_jobs, self.max_bytes = jobs, bytes_
        self.user_jobs, self.user_bytes = user_jobs, user_bytes
        self._lock = threading.Lock()
        self._used: dict[str | None, tuple[int, int]] = {}

    def reserve(self, user: str | None, size: int = 0, count: int = 1) -> Reservation:
        with self._lock:
            jobs, bytes_ = self._used.get(user, (0, 0))
            if user is not None and (jobs + count > self.user_jobs or bytes_ + size > self.user_bytes):
                raise QueueFull(True)
            if sum(v[0] for v in self._used.values()) + count > self.max_jobs or sum(v[1] for v in self._used.values()) + size > self.max_bytes:
                raise QueueFull()
            self._used[user] = jobs + count, bytes_ + size
        return Reservation(self, user, size, count)

    def _release(self, user: str | None, size: int, count: int) -> None:
        with self._lock:
            jobs, bytes_ = self._used[user]
            if jobs == count and bytes_ == size:
                del self._used[user]
            else:
                self._used[user] = jobs - count, bytes_ - size

    def usage(self) -> tuple[int, int]:
        with self._lock:
            return sum(v[0] for v in self._used.values()), sum(v[1] for v in self._used.values())


class Reservation:
    def __init__(self, budget: Budget, user: str | None, size: int, count: int = 1):
        self.budget, self.user, self.size, self.count = budget, user, size, count
        self.attached = False
        self._lock = threading.Lock()
        self._released = False

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
            self.budget._release(self.user, self.size, self.count)

    def release_unused(self) -> None:
        if not self.attached:
            self.release()

    def split(self, sizes: list[int]) -> list[Reservation]:
        """Уже зарезервированный пакет становится независимыми заданиями без нового допуска."""
        with self._lock:
            if self._released or len(sizes) > self.count or sum(sizes) > self.size:
                raise ValueError("резерв пакета недостаточен")
            self._released = True
            self.budget._release(self.user, self.size - sum(sizes), self.count - len(sizes))
            return [Reservation(self.budget, self.user, size) for size in sizes]
