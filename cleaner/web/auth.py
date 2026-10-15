"""Пароли, токены сессий, ограничение попыток входа (раздел 13 спецификации)."""
from __future__ import annotations

import hashlib
import secrets
import threading
from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from cleaner.clock import Clock

MIN_PASSWORD = 12
_hasher = PasswordHasher()          # Argon2id с параметрами библиотеки по умолчанию
# Проверка берёт 64 МиБ, а вход выполняется в пуле потоков — до сорока анонимных проверок разом, около
# 2,5 ГиБ. Одновременно идут не больше HASH_SLOTS; остальные ждут места не дольше HASH_WAIT секунд.
HASH_SLOTS = 4
HASH_WAIT = 5.0
_hashing = threading.BoundedSemaphore(HASH_SLOTS)


class Busy(Exception):
    """Места для проверки пароля заняты дольше HASH_WAIT: пароль не проверялся."""


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"пароль короче {MIN_PASSWORD} знаков")
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Для неизвестного логина хэш всё равно считается: по времени ответа логины не различить."""
    if not _hashing.acquire(timeout=HASH_WAIT):
        raise Busy()
    try:
        if password_hash is None:
            _hasher.hash(password)
            return False
        try:
            return _hasher.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            return False
    finally:
        _hashing.release()


def new_token() -> str:
    return secrets.token_urlsafe(32)        # 256 бит


def token_hash(token: str) -> str:
    """В базе хранится только хэш токена: копия базы не даёт войти."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Throttle:
    """После пяти неудач подряд вход по логину откладывается: 1, 2, 4… секунды, не больше 5 минут.

    Вход выполняется в пуле потоков, поэтому записи меняются под замком.
    """

    FREE = 5
    LIMIT = 300.0
    _KEEP = 10_000          # перебор случайных логинов не раздувает память

    def __init__(self, clock: Clock):
        self.clock = clock
        self.failures: dict[str, tuple[int, datetime]] = {}
        self.lock = threading.Lock()

    def _wait(self, key: str) -> float:
        count, last = self.failures.get(key, (0, None))
        if count < self.FREE or last is None:
            return 0.0
        delay = min(2.0 ** (count - self.FREE), self.LIMIT)
        return max(0.0, delay - (self.clock.now() - last).total_seconds())

    def wait(self, login: str) -> float:
        with self.lock:
            return self._wait(login.lower())

    def failed(self, login: str) -> None:
        with self.lock:
            count, _ = self.failures.pop(login.lower(), (0, None))
            if len(self.failures) >= self._KEEP:
                self._forget()
            self.failures[login.lower()] = (count + 1, self.clock.now())

    def _forget(self) -> None:
        """Место под новый логин. Забываются записи без действующей паузы и меньше чем с пятью неудачами:
        иначе перебор случайных логинов вытеснил бы запись атакуемой учётной записи и обнулил её счёт —
        и когда её пауза уже истекла. Нет таких — уходит одна запись без паузы, нет и их — самая давняя.
        Есть ли логин в базе, не учитывается: иначе по ответам 401 и 429 после перебора было бы видно,
        какие логины существуют."""
        idle = [key for key in self.failures if not self._wait(key)]      # от давней неудачи к свежей
        light = [key for key in idle if self.failures[key][0] < self.FREE]
        for key in light or idle[:1] or [next(iter(self.failures))]:
            del self.failures[key]

    def succeeded(self, login: str) -> None:
        with self.lock:
            self.failures.pop(login.lower(), None)
