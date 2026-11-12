"""Пароли, токены сессий, ограничение попыток входа (раздел 13 спецификации)."""
from __future__ import annotations

import asyncio
import hashlib
import secrets
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from cleaner.clock import Clock

MIN_PASSWORD = 12
API_KEY_NAME = 100


def api_key_name(value: str) -> str:
    """Имя ключа пригодно для формы и табличного вывода CLI."""
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError("В имени ключа недопустимы управляющие знаки")
    value = value.strip()
    if not 1 <= len(value) <= API_KEY_NAME:
        raise ValueError(f"Имя ключа — от 1 до {API_KEY_NAME} знаков")
    return value


_hasher = PasswordHasher()          # Argon2id с параметрами библиотеки по умолчанию
# Хэш берёт 64 МиБ: анонимных входов разом может быть сколько угодно. Argon2 считается только в своём пуле
# из HASH_SLOTS потоков, и очередь к нему — задания пула, а не потоки: вход ждёт места в цикле событий
# и не держит потоков общего пула Starlette (их сорок, ими же обслуживаются все страницы). Вход, не
# получивший места за HASH_WAIT секунд, снимает своё задание; хэш нового пароля ждёт в той же очереди.
HASH_SLOTS = 4
HASH_WAIT = 5.0
_hashing = ThreadPoolExecutor(HASH_SLOTS, thread_name_prefix="cleaner-argon2")


class Busy(Exception):
    """Места для проверки пароля заняты дольше HASH_WAIT: пароль не проверялся."""


def hash_password(password: str) -> str:
    """Хэш нового пароля. Ждёт места без срока: впереди в очереди только входы, а каждый из них
    уходит из неё не позже чем через HASH_WAIT."""
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"пароль короче {MIN_PASSWORD} знаков")
    return _hashing.submit(_hasher.hash, password).result()


def verify_password(password_hash: str | None, password: str) -> bool:
    """Для неизвестного логина хэш всё равно считается: по времени ответа логины не различить.
    Выполняется в пуле Argon2 (check_password)."""
    if password_hash is None:
        _hasher.hash(password)
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


async def check_password(password_hash: str | None, password: str) -> bool:
    """Проверка пароля при входе: место в пуле Argon2 ждётся в цикле событий, без потока."""
    job = _hashing.submit(verify_password, password_hash, password)
    result = asyncio.wrap_future(job)
    done, _ = await asyncio.wait({result}, timeout=HASH_WAIT)
    if not done and job.cancel():       # не началась — места заняты; началась в последний момент — дождаться её
        raise Busy()
    return await result


def new_token() -> str:
    return secrets.token_urlsafe(32)        # 256 бит


API_KEY_PREFIX = "ck_"


def new_api_key() -> str:
    """Ключ доступа программы (FR-13.1): приставка и 256 бит, 46 знаков. В базе — token_hash и последние четыре знака."""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """В базе хранится только хэш токена: копия базы не даёт войти."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Throttle:
    """После пяти неудач подряд вход по логину откладывается: 1, 2, 4… секунды, не больше 5 минут.

    Неудачи и успехи входа записываются из пула потоков, поэтому записи меняются под замком.
    Пароль входа идёт в счёт до проверки (attempt): пауза, прочитанная до Argon2, и неудача, записанная после,
    пропускали к проверке все одновременные попытки разом.
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
            self._fail(login.lower())

    def _fail(self, key: str) -> None:
        count, _ = self.failures.pop(key, (0, None))
        if len(self.failures) >= self._KEEP:
            self._forget()
        self.failures[key] = (count + 1, self.clock.now())

    def attempt(self, login: str) -> float:
        """Пауза логина; без паузы попытка сразу записывается неудачей — до проверки пароля. Верный пароль
        снимает счёт (succeeded), непроверенный возвращает попытку (cancel). Одновременных проверок
        одного логина поэтому не больше, чем последовательных: пять до первой паузы, затем по одной на паузу."""
        with self.lock:
            wait = self._wait(login.lower())
            if not wait:
                self._fail(login.lower())
            return wait

    def cancel(self, login: str) -> None:
        """Попытка не состоялась (пароль не проверялся): одна неудача из счёта снимается."""
        with self.lock:
            count, last = self.failures.get(login.lower(), (0, None))
            if count > 1:
                self.failures[login.lower()] = (count - 1, last)
            else:
                self.failures.pop(login.lower(), None)

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
