"""Пароли, токены сессий, ограничение попыток входа (раздел 13 спецификации)."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from cleaner.clock import Clock

MIN_PASSWORD = 12
_hasher = PasswordHasher()          # Argon2id с параметрами библиотеки по умолчанию


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"пароль короче {MIN_PASSWORD} знаков")
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Для неизвестного логина хэш всё равно считается: по времени ответа логины не различить."""
    if password_hash is None:
        _hasher.hash(password)
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)        # 256 бит


def token_hash(token: str) -> str:
    """В базе хранится только хэш токена: копия базы не даёт войти."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Throttle:
    """После пяти неудач подряд вход по логину откладывается: 1, 2, 4… секунды, не больше 5 минут."""

    FREE = 5
    LIMIT = 300.0
    _KEEP = 10_000          # перебор случайных логинов не раздувает память

    def __init__(self, clock: Clock):
        self.clock = clock
        self.failures: dict[str, tuple[int, datetime]] = {}

    def wait(self, login: str) -> float:
        count, last = self.failures.get(login.lower(), (0, None))
        if count < self.FREE or last is None:
            return 0.0
        delay = min(2.0 ** (count - self.FREE), self.LIMIT)
        return max(0.0, delay - (self.clock.now() - last).total_seconds())

    def failed(self, login: str) -> None:
        count, _ = self.failures.pop(login.lower(), (0, None))
        if len(self.failures) >= self._KEEP:
            self.failures.pop(next(iter(self.failures)))
        self.failures[login.lower()] = (count + 1, self.clock.now())

    def succeeded(self, login: str) -> None:
        self.failures.pop(login.lower(), None)
