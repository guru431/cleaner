"""Хранилище: содержимое зашифровано, у каждого чата свой ключ, состояние чата — одним столбцом."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
import uuid
import weakref
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from cleaner.clock import Clock
from cleaner.core.agent import ledger
from cleaner.core.detect import dictionary
from cleaner.core.types import ChatState, CustomPattern, EntityType, Policy, Settings, default_policies
from cleaner.storage import crypto
from cleaner.storage.codec import state_from_json, state_to_json
from cleaner.storage.db import transaction


class StaleState(Exception):
    """Состояние чата изменилось после чтения: работу нужно повторить на свежем."""


class CheckpointBusy(Exception):
    """Чат удалён, но журнал WAL не усечён: копии его страниц, с ключом, остаются там до следующей
    контрольной точки. Её не пускает другое соединение с базой — копия, eval."""


_CHECKPOINT_ATTEMPTS = 3            # каждая попытка сама ждёт читателей до busy_timeout (5 с)


# Слои 4 и 5 по умолчанию для чатов без явного решения (FR-3.8). Слой 4 включён по умолчанию;
# слой 5 — после замера задачи 23 (раздел 19 спецификации).
DEFAULT_LAYERS = {"ner": True, "llm": False}
# Слои 4 и 5 для ключа шлюза — выключены, пока не включены явно (решение владельца 4, спецификация 2026-10-28).
KEY_LAYERS = {"ner": False, "llm": False}
_IN_CHUNK = 500         # отпечатков в одном запросе IN: предел переменных SQLite


@dataclass(frozen=True)
class User:
    id: str
    login: str
    password_hash: str
    role: str          # admin | user
    disabled: bool


@dataclass(frozen=True)
class Session:
    token_hash: str
    user_id: str
    csrf: str
    last_seen_at: str
    created_at: str = ""


@dataclass(frozen=True)
class Chat:
    id: str
    user_id: str
    title: str
    updated_at: str
    kind: str = "chat"         # chat | agent (чат шлюза, спецификация 2026-10-28, 6.3)
    created_at: str = ""


@dataclass(frozen=True)
class Conversation:
    """Разговор агента (6.3): запросы с одной историей; id — HMAC отпечатка первого сообщения пользователя."""

    id: str
    chat_id: str
    key_id: str
    session: str
    first_seen: str
    last_seen: str
    requests: int


@dataclass(frozen=True)
class LedgerEntry:
    """Запись журнала отправленного (7.2): блок со стороны агента (local) и как он ушёл провайдеру или пришёл от него
    (wire) — JSON блока. withheld — причина удержания (7.4) или ""; counts — замены по типам."""

    conversation: str
    direction: str             # in — блок агента; out — блок модели
    digest: str
    local: str
    wire: str
    withheld: str = ""
    counts: dict[str, int] = field(default_factory=dict, hash=False)


@dataclass
class Item:
    id: str
    seq: int
    kind: str                                            # input | answer
    original: str
    sanitized: str | None
    spans: list[dict] = field(default_factory=list)      # позиции в оригинале, id сущности, замена
    notices: list[dict] = field(default_factory=list)
    exposed: list[str] = field(default_factory=list)     # сущности, открытые в выданном тексте (FR-6.8)
    created_at: str = ""
    source: str = "paste"                                # paste | file | pasted_answer; план «3» добавит api, local
    status: str = "done"                                 # queued | running | done | failed; план «3» добавит partial
    meta: dict = field(default_factory=dict)             # вид файла, страницы, слои, ход, причина отказа — без текста
    model_spans: list[dict] = field(default_factory=list)  # находки слоёв 4–5: start, end, type, source, score
    risk_status: str = ""                                # "" | queued | running | done | failed | interrupted
    reviewed_at: str = ""                                # когда пользователь отметил очищенный текст проверенным; "" — нет


@dataclass(frozen=True)
class DictionaryRow:
    id: str
    list: str                     # always | never
    type: EntityType | None
    value: str
    aliases: tuple[str, ...]
    comment: str
    inflect: bool = False         # искать во всех падежах (detect.dictionary.entry)


@dataclass(frozen=True)
class PatternRow:
    id: str
    name: str
    regex: str
    type: EntityType
    enabled: bool


@dataclass(frozen=True)
class AuditRow:
    id: int
    ts: str
    user_id: str | None
    chat_id: str | None
    event: str
    details: dict


@dataclass(frozen=True)
class GoldRow:
    id: str
    user_id: str | None
    text: str
    spans: list[dict]          # start, end, type, entity (номер сущности в примере), origin
    created_at: str
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Provider:
    """Подключение к облачной модели (FR-8.1). Ключ хранится под общим ключом и после сохранения не показывается."""

    id: str
    name: str
    protocol: str              # openai | anthropic
    base_url: str
    auth_style: str            # bearer | x-api-key
    api_key: str
    models: tuple[str, ...]
    max_tokens: int = 4096
    extra_body: dict = field(default_factory=dict, hash=False)
    enabled: bool = True

    def binding(self) -> str:
        """Changing any connection parameter invalidates an approved request."""
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, default=str).encode()).hexdigest()

    def allowed_models(self, key_models: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(m for m in self.models if not key_models or m in key_models) if self.enabled else ()

    @property
    def key_tail(self) -> str:
        """FR-8.10: видны только последние четыре знака."""
        return self.api_key[-4:]

    def __repr__(self) -> str:
        return f"Provider(id={self.id!r}, name={self.name!r}, protocol={self.protocol!r}, base_url={self.base_url!r})"


@dataclass(frozen=True)
class ApiKey:
    """Ключ доступа программы (FR-13.1). Самого ключа здесь нет: в базе только его хэш и последние четыре знака."""

    id: str
    user_id: str
    name: str
    tail: str
    disabled: bool
    created_at: str
    last_used_at: str          # "" — не использовался
    upstream: str | None = None                # None — только /api/v1; "provider:<id>" — шлюз к подключению (6.1)
    models: tuple[str, ...] = ()               # разрешённые модели подключения; пусто — все
    layers: dict[str, bool] = field(default_factory=lambda: dict(KEY_LAYERS), hash=False)     # слои 4 и 5 шлюза
    chat_id: str | None = None                 # текущий чат шлюза
    agent_epoch: int = 0                       # namespace после явного сброса клиента без id разговора
    hold_secrets: bool = True                  # шлюз: секреты и учётные записи в адресах чужих узлов не восстанавливаются


class Repository:
    def __init__(self, conn: sqlite3.Connection, master_key: bytes, clock: Clock):
        self.conn = conn
        self.master = master_key
        self.clock = clock
        self.lock = threading.RLock()            # одно соединение на процесс: доступ по очереди
        self.global_key = self._load_global_key()
        self._chat_delete_hooks: list[weakref.WeakMethod] = []

    # --- служебное ---------------------------------------------------------

    def _now(self) -> str:
        return self.clock.now().isoformat(timespec="seconds")

    def _one(self, sql: str, *args: object) -> sqlite3.Row | None:
        with self.lock:
            return self.conn.execute(sql, args).fetchone()

    def _all(self, sql: str, *args: object) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def _run(self, sql: str, *args: object) -> int:
        with self.lock:
            return self.conn.execute(sql, args).rowcount

    @staticmethod
    def _enc(key: bytes, text: str, aad: str) -> bytes:
        return crypto.seal(key, text.encode("utf-8"), aad)

    @staticmethod
    def _dec(key: bytes, blob: bytes, aad: str) -> str:
        return crypto.unseal(key, blob, aad).decode("utf-8")

    def _load_global_key(self) -> bytes:
        """Ключ словаря организации; при первом запуске создаётся, при чужом главном ключе — ошибка."""
        row = self._one("SELECT value FROM settings WHERE key = 'global_dek'")
        if row is not None:
            return crypto.unseal(self.master, base64.b64decode(row["value"]), "global-dek")
        key = crypto.new_key()
        sealed = base64.b64encode(crypto.seal(self.master, key, "global-dek")).decode("ascii")
        self._run("INSERT INTO settings(key, value) VALUES ('global_dek', ?)", sealed)
        return key

    def truncate_wal(self) -> bool:
        """Контрольная точка с усечением журнала WAL, как у delete_chat: False — её не пустило другое соединение."""
        for _ in range(_CHECKPOINT_ATTEMPTS):
            with self.lock:
                if not self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]:
                    return True
        return False

    def rotate_master(self, new_master: bytes) -> int:
        """Смена главного ключа (cleaner key rotate): обёртки ключей чатов и общего ключа перешифровываются новым
        ключом одной транзакцией — не открылась прежним хоть одна, не меняется ничего; исключение отсюда — база под
        прежним ключом. Содержимое под ключами чатов и общим ключом не трогается. После неё вызывающий выполняет
        truncate_wal(): до контрольной точки прежние обёртки лежат в WAL и открываются прежним ключом.
        Возвращает число чатов."""
        with self.lock:
            with transaction(self.conn):
                rows = self.conn.execute("SELECT id, dek_wrapped FROM chats").fetchall()
                for row in rows:
                    aad = f"chat-dek:{row['id']}"
                    wrapped = crypto.seal(new_master, crypto.unseal(self.master, row["dek_wrapped"], aad), aad)
                    self.conn.execute("UPDATE chats SET dek_wrapped = ? WHERE id = ?", (wrapped, row["id"]))
                sealed = base64.b64encode(crypto.seal(new_master, self.global_key, "global-dek")).decode("ascii")
                self.conn.execute("UPDATE settings SET value = ? WHERE key = 'global_dek'", (sealed,))
            self.master = new_master
        return len(rows)

    # --- пользователи и сессии ---------------------------------------------

    @staticmethod
    def _user(row: sqlite3.Row | None) -> User | None:
        if row is None:
            return None
        return User(row["id"], row["login"], row["password_hash"], row["role"], bool(row["disabled"]))

    def create_user(self, login: str, password_hash: str, role: str) -> str:
        user_id = uuid.uuid4().hex
        self._run(
            "INSERT INTO users(id, login, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, 0, ?)",
            user_id, login, password_hash, role, self._now(),
        )
        return user_id

    def user(self, user_id: str) -> User | None:
        return self._user(self._one("SELECT * FROM users WHERE id = ?", user_id))

    def user_by_login(self, login: str) -> User | None:
        return self._user(self._one("SELECT * FROM users WHERE login = ?", login))

    def users(self) -> list[User]:
        return [self._user(row) for row in self._all("SELECT * FROM users ORDER BY login")]

    def set_password(self, user_id: str, password_hash: str) -> None:
        """Новый хэш и закрытие сессий — одной транзакцией: и для другого соединения (команда cleaner user)
        нет мгновения, когда пароль уже новый, а сессии по старому ещё действуют."""
        with self.lock, transaction(self.conn):
            self.conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
            self.conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def set_disabled(self, user_id: str, disabled: bool) -> None:
        with self.lock, transaction(self.conn):
            self.conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
            if disabled:
                self.conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def chat_ids(self, user_id: str) -> list[str]:
        """Чаты пользователя без расшифровки названий."""
        return [row["id"] for row in self._all("SELECT id FROM chats WHERE user_id = ? ORDER BY id", user_id)]

    def delete_user(self, user_id: str) -> bool:
        """Удаление отключённой учётной записи, у которой уже нет чатов: их удаляет вызывающий через
        ChatService.delete_chat (задания, кэши, журнал), а каскадом схемы уходят только сессии и ключи доступа.
        Затем контрольная точка с усечением журнала WAL; не вышла — CheckpointBusy, а запись уже удалена.
        False — записи нет, она включена или у неё появились чаты."""
        with self.lock:
            deleted = self._run(
                "DELETE FROM users WHERE id = ? AND disabled = 1 AND NOT EXISTS (SELECT 1 FROM chats WHERE user_id = ?)",
                user_id, user_id,
            ) == 1
        if deleted and not self.truncate_wal():
            raise CheckpointBusy(user_id)
        return deleted

    def create_session(self, token_hash: str, user_id: str, csrf: str, password_hash: str) -> bool:
        """Сессия — одной записью и только для того хэша пароля, что проверен при входе, у включённой учётной
        записи. Пока Argon2 проверял пароль, его могли сменить, а запись — отключить: сессии они уже закрыли,
        и новая по отозванному паролю не открывается. False — сессии нет."""
        now = self._now()
        return self._run(
            "INSERT INTO sessions(token_hash, user_id, csrf, created_at, last_seen_at) SELECT ?, ?, ?, ?, ? "
            "WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND password_hash = ? AND disabled = 0)",
            token_hash, user_id, csrf, now, now, user_id, password_hash,
        ) == 1

    @staticmethod
    def _session(row: sqlite3.Row) -> Session:
        return Session(row["token_hash"], row["user_id"], row["csrf"], row["last_seen_at"], row["created_at"])

    def session(self, token_hash: str) -> Session | None:
        row = self._one("SELECT * FROM sessions WHERE token_hash = ?", token_hash)
        return None if row is None else self._session(row)

    def sessions(self, user_id: str) -> list[Session]:
        """Сессии пользователя, свежие первыми."""
        return [
            self._session(row)
            for row in self._all("SELECT * FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC, created_at DESC", user_id)
        ]

    def delete_sessions(self, user_id: str) -> int:
        """«Выйти на всех устройствах»: все сессии пользователя; число закрытых."""
        return self._run("DELETE FROM sessions WHERE user_id = ?", user_id)

    def touch_session(self, token_hash: str) -> None:
        self._run("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", self._now(), token_hash)

    def delete_session(self, token_hash: str) -> None:
        self._run("DELETE FROM sessions WHERE token_hash = ?", token_hash)

    # --- чаты и их элементы --------------------------------------------------

    def _dek(self, chat_id: str) -> bytes:
        row = self._one("SELECT dek_wrapped FROM chats WHERE id = ?", chat_id)
        if row is None:
            raise KeyError(chat_id)
        return crypto.unseal(self.master, row["dek_wrapped"], f"chat-dek:{chat_id}")

    def create_chat(self, user_id: str, title: str, label_style: str = "angle", kind: str = "chat") -> str:
        """kind="agent" — чат шлюза: состояние в режиме написаний (спецификация 2026-10-28, 6.3, 11)."""
        chat_id = uuid.uuid4().hex
        dek = crypto.new_key()
        state = ChatState(chat_id=chat_id, net_key=os.urandom(32), label_style=label_style, written=kind == "agent")
        now = self._now()
        self._run(
            "INSERT INTO chats(id, user_id, title_enc, dek_wrapped, state_enc, version, created_at, updated_at, kind) "
            "VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)",
            chat_id, user_id,
            self._enc(dek, title, f"chats.title:{chat_id}"),
            crypto.seal(self.master, dek, f"chat-dek:{chat_id}"),
            crypto.seal(dek, state_to_json(state), f"chats.state:{chat_id}"),
            now, now, kind,
        )
        return chat_id

    _CHAT_COLUMNS = "id, user_id, title_enc, updated_at, kind, created_at"

    def _chat(self, row: sqlite3.Row) -> Chat:
        title = self._dec(self._dek(row["id"]), row["title_enc"], f"chats.title:{row['id']}")
        return Chat(row["id"], row["user_id"], title, row["updated_at"], row["kind"], row["created_at"])

    def chat(self, chat_id: str) -> Chat | None:
        row = self._one(f"SELECT {self._CHAT_COLUMNS} FROM chats WHERE id = ?", chat_id)
        return None if row is None else self._chat(row)

    def chats(self, user_id: str) -> list[Chat]:
        rows = self._all(
            f"SELECT {self._CHAT_COLUMNS} FROM chats WHERE user_id = ? ORDER BY updated_at DESC, id",
            user_id,
        )
        return [self._chat(row) for row in rows]

    def rename_chat(self, chat_id: str, title: str) -> None:
        self._run(
            "UPDATE chats SET title_enc = ?, updated_at = ? WHERE id = ?",
            self._enc(self._dek(chat_id), title, f"chats.title:{chat_id}"), self._now(), chat_id,
        )

    def on_chat_deleted(self, callback: Callable[[str], None]) -> None:
        """Подписка живой службы на удаление; хранилище не продлевает жизнь службы и её кэшей."""
        with self.lock:
            self._chat_delete_hooks.append(weakref.WeakMethod(callback))

    def _forget_chat(self, chat_id: str) -> None:
        from cleaner.core.cache import invalidate_chat

        invalidate_chat(chat_id)
        with self.lock:
            alive = [(reference, callback) for reference in self._chat_delete_hooks if (callback := reference()) is not None]
            self._chat_delete_hooks = [reference for reference, _ in alive]
        for _, callback in alive:
            callback(chat_id)

    def delete_chat(self, chat_id: str) -> None:
        """Строки чата и его ключ удаляются (элементы — каскадом схемы: items.chat_id ON DELETE CASCADE, foreign_keys
        включает db.connect); secure_delete перезаписывает их на диске (FR-1.4).

        Копии страниц с ключом чата остаются в файле журнала WAL до контрольной точки, а соединение
        службы живёт долго: контрольная точка с усечением журнала выполняется сразу. Занята (первый
        столбец ответа — 1) — ещё попытка; между попытками замок отпущен, чтобы служба не стояла.
        Не вышло — CheckpointBusy: чат удалён, а молчать о копиях в журнале нельзя.
        """
        with self.lock:
            self.conn.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
        self._forget_chat(chat_id)
        for _ in range(_CHECKPOINT_ATTEMPTS):
            with self.lock:
                busy = self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
            if not busy:
                return
        raise CheckpointBusy(chat_id)

    def chat_version(self, chat_id: str) -> int:
        """Версия состояния без расшифровки: по ней шлюз узнаёт, годится ли состояние, которое он держит в памяти."""
        row = self._one("SELECT version FROM chats WHERE id = ?", chat_id)
        if row is None:
            raise KeyError(chat_id)
        return row["version"]

    def chat_secret(self, chat_id: str) -> bytes:
        """Ключ отпечатков блоков журнала отправленного — выведен из ключа чата (спецификация 2026-10-28, 7.2)."""
        return ledger.chat_secret(self._dek(chat_id))

    def load_state(self, chat_id: str) -> tuple[ChatState, int]:
        from cleaner.core.cache import lease_of

        with self.lock:
            row = self._one("SELECT state_enc, version FROM chats WHERE id = ?", chat_id)
            if row is None:
                raise KeyError(chat_id)
            raw = crypto.unseal(self._dek(chat_id), row["state_enc"], f"chats.state:{chat_id}")
            state = state_from_json(raw)
            lease_of(state)
            return state, row["version"]

    # --- отмена последней правки (раздел 14) -------------------------------------------

    def save_undo(self, chat_id: str, before: bytes, version: int, action: str) -> bool:
        """Снимок состояния до правки (запись state_to_json) — под ключом чата, как само состояние (SEC-4). Пишется,
        только если версия чата та, что дала правка: успела другая запись — снимка нет, отменять нечего."""
        sealed = crypto.seal(self._dek(chat_id), before, f"chats.undo:{chat_id}")
        return self._run(
            "UPDATE chats SET undo_enc = ?, undo_action = ?, undo_version = ? WHERE id = ? AND version = ?",
            sealed, action, version, chat_id, version,
        ) == 1

    def undo_action(self, chat_id: str) -> tuple[str, int] | None:
        """Вид правки, которую можно отменить, и версия чата, к которой относится снимок; None — отменять нечего.
        Снимок действует, только пока версия чата та, что дала правка (без расшифровки — для кнопки на странице)."""
        row = self._one("SELECT undo_action, undo_version, version FROM chats WHERE id = ? AND undo_enc IS NOT NULL", chat_id)
        if row is None or row["undo_version"] != row["version"]:
            return None
        return row["undo_action"], row["version"]

    def undo_snapshot(self, chat_id: str) -> tuple[ChatState, str, int, int] | None:
        """Снимок до правки, её вид, версия чата, которую дала правка, и нынешняя версия: снимок действует, только
        пока они равны. None — снимка нет."""
        row = self._one("SELECT undo_enc, undo_action, undo_version, version FROM chats WHERE id = ?", chat_id)
        if row is None:
            raise KeyError(chat_id)
        if row["undo_enc"] is None:
            return None
        raw = crypto.unseal(self._dek(chat_id), row["undo_enc"], f"chats.undo:{chat_id}")
        return state_from_json(raw), row["undo_action"], row["undo_version"], row["version"]

    def clear_undo(self, chat_id: str) -> None:
        self._run("UPDATE chats SET undo_enc = NULL, undo_action = NULL, undo_version = NULL WHERE id = ?", chat_id)

    def _item(self, row: sqlite3.Row, key: bytes) -> Item:
        sanitized = row["sanitized_enc"]
        return Item(
            id=row["id"], seq=row["seq"], kind=row["kind"],
            original=self._dec(key, row["original_enc"], f"items.original:{row['id']}"),
            sanitized=None if sanitized is None else self._dec(key, sanitized, f"items.sanitized:{row['id']}"),
            spans=json.loads(row["spans"]), notices=json.loads(row["notices"]), exposed=json.loads(row["exposed"]),
            created_at=row["created_at"], source=row["source"], status=row["status"], meta=json.loads(row["meta"]),
            model_spans=json.loads(row["model_spans"]), risk_status=row["risk_status"], reviewed_at=row["reviewed_at"] or "",
        )

    def items(self, chat_id: str) -> list[Item]:
        key = self._dek(chat_id)
        return [self._item(row, key) for row in self._all("SELECT * FROM items WHERE chat_id = ? ORDER BY seq", chat_id)]

    def item(self, chat_id: str, item_id: str) -> Item | None:
        row = self._one("SELECT * FROM items WHERE id = ? AND chat_id = ?", item_id, chat_id)
        return None if row is None else self._item(row, self._dek(chat_id))

    def item_status(self, chat_id: str, item_id: str) -> str | None:
        """Опрос задания без чтения и расшифровки оригинала и результата."""
        row = self._one("SELECT status FROM items WHERE id = ? AND chat_id = ?", item_id, chat_id)
        return None if row is None else row["status"]

    def _insert_item(self, key: bytes, chat_id: str, item: Item, seq: int, now: str) -> None:
        self.conn.execute(
            "INSERT INTO items(id, chat_id, seq, kind, original_enc, sanitized_enc, spans, notices, exposed, created_at, "
            "source, status, meta, model_spans) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                item.id, chat_id, seq, item.kind,
                self._enc(key, item.original, f"items.original:{item.id}"),
                None if item.sanitized is None else self._enc(key, item.sanitized, f"items.sanitized:{item.id}"),
                json.dumps(item.spans), json.dumps(item.notices), json.dumps(item.exposed), now,
                item.source, item.status, json.dumps(item.meta, ensure_ascii=False), json.dumps(item.model_spans),
            ),
        )

    def add_item(self, chat_id: str, item: Item) -> Item:
        """Элемент в очередь фоновой обработки: состояние чата не меняется. Возвращается с номером."""
        key = self._dek(chat_id)
        now = self._now()
        with self.lock, transaction(self.conn):
            seq = self.conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM items WHERE chat_id = ?", (chat_id,)
            ).fetchone()[0]
            self._insert_item(key, chat_id, item, seq, now)
            self.conn.execute("UPDATE chats SET updated_at = ? WHERE id = ?", (now, chat_id))
        return replace(item, seq=seq, created_at=now)

    def commit_chat(
        self, chat_id: str, state: ChatState, version: int,
        new_items: Iterable[Item] = (), updated_items: Iterable[Item] = (), ledger: Iterable[LedgerEntry] = (),
    ) -> None:
        """Состояние, элементы и записи журнала отправленного — одной транзакцией. StaleState, если чат успели изменить.

        Если очищенный текст элемента изменился, догадки проверки риска стираются, а идущая проверка
        отменяется вместе с её заданием: они о прежнем тексте (FR-9.3). Так же снимается отметка
        «проверено пользователем»: проверяли прежний текст. Сравнение — здесь, а не у вызывающего:
        так его не обойти.
        """
        key = self._dek(chat_id)
        now = self._now()
        with self.lock, transaction(self.conn):
            cursor = self.conn.execute(
                "UPDATE chats SET state_enc = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?",
                (crypto.seal(key, state_to_json(state), f"chats.state:{chat_id}"), now, chat_id, version),
            )
            if cursor.rowcount != 1:
                raise StaleState(chat_id)
            self._insert_ledger(key, ledger, now)
            seq = self.conn.execute("SELECT COALESCE(MAX(seq), 0) FROM items WHERE chat_id = ?", (chat_id,)).fetchone()[0]
            for item in new_items:
                seq += 1
                self._insert_item(key, chat_id, item, seq, now)
            for item in updated_items:
                row = self.conn.execute(
                    "SELECT sanitized_enc FROM items WHERE id = ? AND chat_id = ?", (item.id, chat_id)
                ).fetchone()
                sealed = row["sanitized_enc"] if row else None
                before = None if sealed is None else self._dec(key, sealed, f"items.sanitized:{item.id}")
                if before != item.sanitized:
                    self.conn.execute(
                        "UPDATE items SET risk_enc = NULL, risk_status = '', risk_job = NULL, reviewed_at = NULL "
                        "WHERE id = ? AND chat_id = ?",
                        (item.id, chat_id),
                    )
                self.conn.execute(
                    "UPDATE items SET original_enc = ?, sanitized_enc = ?, spans = ?, notices = ?, exposed = ?, "
                    "status = ?, meta = ?, model_spans = ? WHERE id = ? AND chat_id = ?",
                    (
                        self._enc(key, item.original, f"items.original:{item.id}"),
                        None if item.sanitized is None else self._enc(key, item.sanitized, f"items.sanitized:{item.id}"),
                        json.dumps(item.spans), json.dumps(item.notices), json.dumps(item.exposed),
                        item.status, json.dumps(item.meta, ensure_ascii=False), json.dumps(item.model_spans),
                        item.id, chat_id,
                    ),
                )

    # --- обработка элементов (раздел 14) ------------------------------------------

    def _update_meta(self, chat_id: str, item_id: str, change, status: str | None = None) -> None:
        # Одно соединение защищено lock; meta и status сохраняются атомарно одним UPDATE.
        with self.lock:
            row = self.conn.execute(
                "SELECT meta, status FROM items WHERE id = ? AND chat_id = ?", (item_id, chat_id)
            ).fetchone()
            if row is None:
                raise KeyError(item_id)
            meta = json.loads(row["meta"])
            change(meta)
            self.conn.execute(
                "UPDATE items SET meta = ?, status = ? WHERE id = ?",
                (json.dumps(meta, ensure_ascii=False), status or row["status"], item_id),
            )

    def set_item_status(self, chat_id: str, item_id: str, status: str, error: str | None = None) -> None:
        """Состояние обработки. error — причина отказа для пользователя, без его данных (FR-2.9)."""
        def change(meta: dict) -> None:
            meta.pop("progress", None)
            meta.pop("error", None)
            if error is not None:
                meta["error"] = error

        self._update_meta(chat_id, item_id, change, status)

    def queue_item(self, chat_id: str, item_id: str) -> bool:
        """Готовый или отказавший входной текст — снова в очередь, одним UPDATE. False — он уже в очереди
        или в работе: двойное нажатие «Повторить» не запускает модели дважды. Причина и ход стираются."""
        return self._run(
            "UPDATE items SET status = 'queued', meta = json_remove(meta, '$.error', '$.progress') "
            "WHERE id = ? AND chat_id = ? AND kind = 'input' AND status IN ('done', 'failed')",
            item_id, chat_id,
        ) == 1

    def set_item_progress(self, chat_id: str, item_id: str, progress: str) -> None:
        """Ход долгой обработки, например «3/12» страниц распознавания (NFR-4)."""
        self._update_meta(chat_id, item_id, lambda meta: meta.update(progress=progress))

    def set_item_original(self, chat_id: str, item_id: str, text: str, meta: dict) -> None:
        """Текст, извлечённый из файла, — сразу, до очистки: при сбое очистки его можно очистить заново."""
        sealed = self._enc(self._dek(chat_id), text, f"items.original:{item_id}")
        changed = self._run(
            "UPDATE items SET original_enc = ?, meta = ? WHERE id = ? AND chat_id = ?",
            sealed, json.dumps(meta, ensure_ascii=False), item_id, chat_id,
        )
        if changed != 1:
            raise KeyError(item_id)

    def finish_answer(self, chat_id: str, item_id: str, text: str, status: str, meta: dict) -> None:
        """Ответ модели по окончании потока: текст, как получен, состояние и meta — одной записью."""
        sealed = self._enc(self._dek(chat_id), text, f"items.original:{item_id}")
        changed = self._run(
            "UPDATE items SET original_enc = ?, status = ?, meta = ? WHERE id = ? AND chat_id = ?",
            sealed, status, json.dumps(meta, ensure_ascii=False), item_id, chat_id,
        )
        if changed != 1:
            raise KeyError(item_id)

    def fail_interrupted(self, reason: str, file_reason: str | None = None) -> int:
        """При старте службы: обработка, прерванная остановкой, — отказ с причиной (NFR-6). Число таких элементов.
        file_reason — у файла, текст которого ещё не извлечён (в meta нет kind, его пишет set_item_original): файл
        не хранится, и запустить обработку ещё раз нельзя."""
        with self.lock, transaction(self.conn):
            rows = self.conn.execute("SELECT id, source, meta FROM items WHERE status IN ('queued', 'running')").fetchall()
            for row in rows:
                meta = json.loads(row["meta"])
                meta.pop("progress", None)
                unread = file_reason is not None and row["source"] == "file" and "kind" not in meta
                meta["error"] = file_reason if unread else reason
                self.conn.execute(
                    "UPDATE items SET status = 'failed', meta = ? WHERE id = ?",
                    (json.dumps(meta, ensure_ascii=False), row["id"]),
                )
            # Своё состояние, а не failed: экран говорит «прервана, запустите ещё раз», а не «модель недоступна».
            self.conn.execute(
                "UPDATE items SET risk_status = 'interrupted', risk_job = NULL WHERE risk_status IN ('queued', 'running')"
            )
        return len(rows)

    def queue_risk(self, chat_id: str, item_id: str, current: tuple[str, ...]) -> str | None:
        """Проверка риска — в очередь из состояний current с новым заданием, одним UPDATE; None — её уже
        поставили: двойное нажатие не запускает модель дважды. Задание сверяют все её дальнейшие переходы."""
        job = uuid.uuid4().hex
        marks = ", ".join("?" * len(current))
        changed = self._run(
            f"UPDATE items SET risk_status = 'queued', risk_job = ? WHERE id = ? AND chat_id = ? AND risk_status IN ({marks})",
            job, item_id, chat_id, *current,
        )
        return job if changed == 1 else None

    def set_item_risk_status(self, chat_id: str, item_id: str, job: str, status: str, current: tuple[str, ...]) -> bool:
        """Переход проверки риска — только своего задания и из состояний current, одним UPDATE; False — перехода
        не было. Проверку, которую отменила смена очищенного текста (commit_chat), задание не продолжает, а
        отказ прежнего задания не ложится на новую проверку того же элемента."""
        marks = ", ".join("?" * len(current))
        return self._run(
            f"UPDATE items SET risk_status = ? WHERE id = ? AND chat_id = ? AND risk_job = ? AND risk_status IN ({marks})",
            status, item_id, chat_id, job, *current,
        ) == 1

    def set_item_risk(self, chat_id: str, item_id: str, job: str, sanitized: str | None, risk: dict) -> bool:
        """Догадки локальной модели: верная догадка — это оригинал, поэтому они зашифрованы (FR-9.3).

        Записываются, только пока идёт это задание и очищенный текст тот, что видела модель (sanitized); False —
        проверку отменила смена текста, её место заняла новая или чат удалён. Задание стирает commit_chat — он
        один меняет очищенный текст; сверка самого текста — на случай записи мимо него."""
        key = self._dek(chat_id)
        sealed = self._enc(key, json.dumps(risk, ensure_ascii=False), f"items.risk:{item_id}")
        with self.lock:
            row = self.conn.execute(
                "SELECT sanitized_enc FROM items WHERE id = ? AND chat_id = ? AND risk_job = ? AND risk_status = 'running'",
                (item_id, chat_id, job),
            ).fetchone()
            if row is None:
                return False
            current = None if row["sanitized_enc"] is None else self._dec(key, row["sanitized_enc"], f"items.sanitized:{item_id}")
            if current != sanitized:
                return False
            self.conn.execute("UPDATE items SET risk_enc = ?, risk_status = 'done' WHERE id = ?", (sealed, item_id))
        return True

    def mark_reviewed(self, chat_id: str, item_id: str, digest: str) -> bool:
        """Отметка «проверено пользователем» — только готовому входному тексту и только тому очищенному тексту,
        который пользователь видел (digest — sha256 показанного): если текст сменили, пока страница была открыта,
        отмечать нечего. False — отметки нет. Снимает её commit_chat при смене очищенного текста."""
        key = self._dek(chat_id)
        with self.lock:
            row = self.conn.execute(
                "SELECT sanitized_enc FROM items WHERE id = ? AND chat_id = ? AND kind = 'input' AND status = 'done'",
                (item_id, chat_id),
            ).fetchone()
            if row is None or row["sanitized_enc"] is None:
                return False
            current = self._dec(key, row["sanitized_enc"], f"items.sanitized:{item_id}")
            if hashlib.sha256(current.encode("utf-8")).hexdigest() != digest:
                return False
            self.conn.execute("UPDATE items SET reviewed_at = ? WHERE id = ?", (self._now(), item_id))
        return True

    def item_risk(self, chat_id: str, item_id: str) -> dict | None:
        row = self._one("SELECT risk_enc FROM items WHERE id = ? AND chat_id = ?", item_id, chat_id)
        if row is None or row["risk_enc"] is None:
            return None
        return json.loads(self._dec(self._dek(chat_id), row["risk_enc"], f"items.risk:{item_id}"))

    # --- слои 4 и 5 в чате (FR-3.8) -------------------------------------------------

    def chat_layers(self, chat_id: str) -> dict[str, bool]:
        """Только явные решения пользователя в этом чате."""
        row = self._one("SELECT layers FROM chats WHERE id = ?", chat_id)
        if row is None:
            raise KeyError(chat_id)
        return {name: bool(value) for name, value in json.loads(row["layers"]).items()}

    def set_chat_layer(self, chat_id: str, layer: str, enabled: bool) -> None:
        with self.lock, transaction(self.conn):
            row = self.conn.execute("SELECT layers FROM chats WHERE id = ?", (chat_id,)).fetchone()
            if row is None:
                raise KeyError(chat_id)
            layers = json.loads(row["layers"]) | {layer: bool(enabled)}
            self.conn.execute("UPDATE chats SET layers = ? WHERE id = ?", (json.dumps(layers), chat_id))

    def layer_defaults(self) -> dict[str, bool]:
        raw = self.setting("layers.default")
        stored = json.loads(raw) if raw else {}
        return {name: bool(stored.get(name, default)) for name, default in DEFAULT_LAYERS.items()}

    def set_layer_defaults(self, values: dict[str, bool]) -> None:
        self.set_setting("layers.default", json.dumps({name: bool(values[name]) for name in DEFAULT_LAYERS}))

    # --- подключения к облачным моделям (FR-8.1, FR-8.3) --------------------------------

    def _provider(self, row: sqlite3.Row) -> Provider:
        return Provider(
            row["id"], row["name"], row["protocol"], row["base_url"], row["auth_style"],
            self._dec(self.global_key, row["api_key_enc"], f"providers.api_key:{row['id']}"),
            tuple(json.loads(row["models"])), row["max_tokens"], json.loads(row["extra_body"]), bool(row["enabled"]),
        )

    def add_provider(self, provider: Provider) -> str:
        provider_id = uuid.uuid4().hex
        self._run(
            "INSERT INTO providers(id, name, protocol, base_url, auth_style, api_key_enc, models, max_tokens, "
            "extra_body, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            provider_id, provider.name, provider.protocol, provider.base_url, provider.auth_style,
            self._enc(self.global_key, provider.api_key, f"providers.api_key:{provider_id}"),
            json.dumps(list(provider.models), ensure_ascii=False), provider.max_tokens,
            json.dumps(provider.extra_body, ensure_ascii=False), int(provider.enabled), self._now(),
        )
        return provider_id

    def update_provider(self, provider: Provider, api_key: str | None) -> None:
        """api_key None — ключ прежний: после сохранения он в форму не возвращается (FR-8.10)."""
        with self.lock, transaction(self.conn):
            cursor = self.conn.execute(
                "UPDATE providers SET name = ?, protocol = ?, base_url = ?, auth_style = ?, models = ?, max_tokens = ?, "
                "extra_body = ?, enabled = ? WHERE id = ?",
                (
                    provider.name, provider.protocol, provider.base_url, provider.auth_style,
                    json.dumps(list(provider.models), ensure_ascii=False), provider.max_tokens,
                    json.dumps(provider.extra_body, ensure_ascii=False), int(provider.enabled), provider.id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(provider.id)
            if api_key is not None:
                self.conn.execute(
                    "UPDATE providers SET api_key_enc = ? WHERE id = ?",
                    (self._enc(self.global_key, api_key, f"providers.api_key:{provider.id}"), provider.id),
                )

    def providers(self) -> list[Provider]:
        return [self._provider(row) for row in self._all("SELECT * FROM providers ORDER BY name, id")]

    def provider(self, provider_id: str) -> Provider | None:
        row = self._one("SELECT * FROM providers WHERE id = ?", provider_id)
        return None if row is None else self._provider(row)

    def delete_provider(self, provider_id: str) -> bool:
        return self._run("DELETE FROM providers WHERE id = ?", provider_id) == 1

    def chat_provider(self, chat_id: str) -> tuple[str | None, str]:
        """Подключение и модель, выбранные в чате; подключение могли удалить — тогда вызывающий получит None."""
        row = self._one("SELECT provider_id, model FROM chats WHERE id = ?", chat_id)
        if row is None:
            raise KeyError(chat_id)
        return row["provider_id"], row["model"]

    def set_chat_provider(self, chat_id: str, provider_id: str | None, model: str) -> None:
        if self._run("UPDATE chats SET provider_id = ?, model = ? WHERE id = ?", provider_id, model, chat_id) != 1:
            raise KeyError(chat_id)

    # --- ключи доступа программ (FR-13.1) ------------------------------------------

    def _api_key(self, row: sqlite3.Row | None) -> ApiKey | None:
        if row is None:
            return None
        return ApiKey(
            row["id"], row["user_id"], self._dec(self.global_key, row["name_enc"], f"api_keys.name:{row['id']}"),
            row["tail"], bool(row["disabled"]), row["created_at"], row["last_used_at"] or "",
            row["upstream"], tuple(json.loads(row["models"])), KEY_LAYERS | json.loads(row["layers"]), row["chat_id"], row["agent_epoch"],
            bool(row["hold_secrets"]),
        )

    def add_api_key(
        self, user_id: str, name: str, token_hash: str, tail: str,
        upstream: str | None = None, models: tuple[str, ...] = (), layers: dict[str, bool] | None = None,
        hold_secrets: bool = True,
    ) -> str:
        """Доступ к модели (upstream, models) задаётся при создании и не меняется: другой доступ — новый ключ."""
        key_id = uuid.uuid4().hex
        self._run(
            "INSERT INTO api_keys(id, user_id, name_enc, token_hash, tail, disabled, created_at, upstream, models, layers, "
            "hold_secrets) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)",
            key_id, user_id, self._enc(self.global_key, name, f"api_keys.name:{key_id}"), token_hash, tail, self._now(),
            upstream, json.dumps(list(models), ensure_ascii=False),
            json.dumps({name_: bool((layers or KEY_LAYERS).get(name_, False)) for name_ in KEY_LAYERS}), int(hold_secrets),
        )
        return key_id

    def set_key_chat(self, key_id: str, chat_id: str | None) -> None:
        """Текущий чат шлюза ключа; None — следующий новый разговор начнёт новый чат («Начать заново»)."""
        self._run("UPDATE api_keys SET chat_id = ? WHERE id = ?", chat_id, key_id)

    def restart_key_chat(self, key_id: str) -> None:
        """Explicit reset: clients without stable session ids get a new persistent namespace. Identified sessions can
        continue their existing conversation; a new session or X-Cleaner-Conversation-Id starts a separate one."""
        self._run("UPDATE api_keys SET chat_id = NULL, agent_epoch = agent_epoch + 1 WHERE id = ?", key_id)

    def api_key_by_hash(self, token_hash: str) -> ApiKey | None:
        return self._api_key(self._one("SELECT * FROM api_keys WHERE token_hash = ?", token_hash))

    def api_key(self, key_id: str) -> ApiKey | None:
        return self._api_key(self._one("SELECT * FROM api_keys WHERE id = ?", key_id))

    def api_keys(self, user_id: str | None = None) -> list[ApiKey]:
        """Ключи пользователя, None — всех; новые первыми."""
        if user_id is None:
            rows = self._all("SELECT * FROM api_keys ORDER BY created_at DESC, id")
        else:
            rows = self._all("SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC, id", user_id)
        return [self._api_key(row) for row in rows]

    def disable_api_key(self, key_id: str) -> bool:
        """Отзыв насовсем: включить отозванный ключ нельзя, выпускается новый."""
        return self._run("UPDATE api_keys SET disabled = 1 WHERE id = ?", key_id) == 1

    def touch_api_key(self, key_id: str) -> None:
        self._run("UPDATE api_keys SET last_used_at = ? WHERE id = ?", self._now(), key_id)

    # --- разговоры агентов и журнал отправленного (спецификация 2026-10-28, 6.3, 7) -------------

    @staticmethod
    def _conversation(row: sqlite3.Row | None) -> Conversation | None:
        if row is None:
            return None
        return Conversation(
            row["id"], row["chat_id"], row["key_id"], row["session"], row["first_seen"], row["last_seen"], row["requests"],
        )

    def chat_conversations(self, chat_id: str) -> list[Conversation]:
        """Разговоры чата шлюза — для его страницы; новые первыми."""
        rows = self._all("SELECT * FROM agent_conversations WHERE chat_id = ? ORDER BY last_seen DESC, id", chat_id)
        return [self._conversation(row) for row in rows]

    def conversation(self, conv_id: str) -> Conversation | None:
        return self._conversation(self._one("SELECT * FROM agent_conversations WHERE id = ?", conv_id))

    def add_conversation(self, conv_id: str, chat_id: str, key_id: str, session: str) -> Conversation:
        """Новый разговор в чате; уже записанный (параллельный запрос успел первым) остаётся в своём чате."""
        now = self._now()
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO agent_conversations(id, chat_id, key_id, session, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (conv_id, chat_id, key_id, session, now, now),
            )
            return self._conversation(
                self.conn.execute("SELECT * FROM agent_conversations WHERE id = ?", (conv_id,)).fetchone()
            )

    def touch_conversation(self, conv_id: str, session: str) -> None:
        """Запрос разговора: время и счётчик; сессия агента записывается первая увиденная — для просмотра."""
        self._run(
            "UPDATE agent_conversations SET last_seen = ?, requests = requests + 1, "
            "session = CASE WHEN session = '' THEN ? ELSE session END WHERE id = ?",
            self._now(), session, conv_id,
        )

    @staticmethod
    def _ledger_aad(column: str, conversation: str, direction: str, digest: str) -> str:
        return f"agent_ledger.{column}:{conversation}:{direction}:{digest}"

    def _insert_ledger(self, key: bytes, entries: Iterable[LedgerEntry], now: str) -> None:
        """Под замком и в транзакции вызывающего. INSERT OR IGNORE: блок, записанный параллельным запросом, остаётся
        первым — его вид уже ушёл провайдеру."""
        for e in entries:
            self.conn.execute(
                "INSERT OR IGNORE INTO agent_ledger(conversation, direction, digest, local_enc, wire_enc, withheld, counts, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    e.conversation, e.direction, e.digest,
                    self._enc(key, e.local, self._ledger_aad("local", e.conversation, e.direction, e.digest)),
                    self._enc(key, e.wire, self._ledger_aad("wire", e.conversation, e.direction, e.digest)),
                    e.withheld, json.dumps(e.counts), now, now,
                ),
            )

    def add_ledger(self, chat_id: str, entries: Iterable[LedgerEntry]) -> None:
        """Записи без состояния чата — блоки ответа модели (out) по концу потока."""
        key = self._dek(chat_id)
        with self.lock, transaction(self.conn):
            self._insert_ledger(key, entries, self._now())

    def _ledger_entry(self, row: sqlite3.Row, key: bytes) -> LedgerEntry:
        conversation, direction, digest = row["conversation"], row["direction"], row["digest"]
        return LedgerEntry(
            conversation, direction, digest,
            self._dec(key, row["local_enc"], self._ledger_aad("local", conversation, direction, digest)),
            self._dec(key, row["wire_enc"], self._ledger_aad("wire", conversation, direction, digest)),
            row["withheld"], json.loads(row["counts"]),
        )

    def ledger_get(self, chat_id: str, conversation: str, direction: str, digests: list[str]) -> dict[str, LedgerEntry]:
        """Записанные блоки разговора по отпечаткам; расшифровываются только найденные."""
        key = self._dek(chat_id)
        found: dict[str, LedgerEntry] = {}
        unique = list(dict.fromkeys(digests))
        for start in range(0, len(unique), _IN_CHUNK):
            chunk = unique[start:start + _IN_CHUNK]
            rows = self._all(
                f"SELECT * FROM agent_ledger WHERE conversation = ? AND direction = ? AND digest IN ({', '.join('?' * len(chunk))})",
                conversation, direction, *chunk,
            )
            for row in rows:
                found[row["digest"]] = self._ledger_entry(row, key)
        return found

    def touch_ledger(self, chat_id: str, conversation: str, direction: str, digests: list[str]) -> None:
        """Повторённые блоки — время последнего повтора (для просмотра)."""
        unique = list(dict.fromkeys(digests))
        now = self._now()
        with self.lock, transaction(self.conn):
            for start in range(0, len(unique), _IN_CHUNK):
                chunk = unique[start:start + _IN_CHUNK]
                self.conn.execute(
                    f"UPDATE agent_ledger SET last_seen = ? WHERE conversation = ? AND direction = ? "
                    f"AND digest IN ({', '.join('?' * len(chunk))})",
                    (now, conversation, direction, *chunk),
                )

    def ledger_page(self, chat_id: str, offset: int, limit: int) -> list[tuple[LedgerEntry, str]]:
        """Записи журнала чата шлюза — новые первыми — и время первой записи каждой."""
        key = self._dek(chat_id)
        rows = self._all(
            "SELECT l.* FROM agent_ledger l JOIN agent_conversations c ON c.id = l.conversation WHERE c.chat_id = ? "
            "ORDER BY l.first_seen DESC, l.rowid DESC LIMIT ? OFFSET ?",
            chat_id, limit, offset,
        )
        return [(self._ledger_entry(row, key), row["first_seen"]) for row in rows]

    def add_agent_receipt(self, chat_id: str, conversation: str, receipt: dict) -> str:
        request_id = uuid.uuid4().hex
        self._run(
            "INSERT INTO agent_receipts(id, conversation, created_at, content_enc) VALUES (?, ?, ?, ?)",
            request_id, conversation, self._now(),
            self._enc(self._dek(chat_id), json.dumps(receipt, ensure_ascii=False), f"agent_receipts.content:{request_id}"),
        )
        return request_id

    def agent_receipts(self, chat_id: str, offset: int = 0, limit: int = 20) -> list[dict]:
        key = self._dek(chat_id)
        rows = self._all(
            "SELECT r.* FROM agent_receipts r JOIN agent_conversations c ON c.id = r.conversation WHERE c.chat_id = ? "
            "ORDER BY r.created_at DESC, r.rowid DESC LIMIT ? OFFSET ?", chat_id, limit, offset,
        )
        return [dict(json.loads(self._dec(key, row["content_enc"], f"agent_receipts.content:{row['id']}")),
                     id=row["id"], conversation=row["conversation"], time=row["created_at"]) for row in rows]

    def agent_receipt(self, chat_id: str, request_id: str) -> dict | None:
        row = self._one(
            "SELECT r.* FROM agent_receipts r JOIN agent_conversations c ON c.id = r.conversation "
            "WHERE c.chat_id = ? AND r.id = ?", chat_id, request_id,
        )
        if row is None:
            return None
        return dict(json.loads(self._dec(self._dek(chat_id), row["content_enc"], f"agent_receipts.content:{row['id']}")),
                    id=row["id"], conversation=row["conversation"], time=row["created_at"])

    def prune_agent(self, before: str) -> int:
        """Разговоры без запросов с before удаляются с журналом (каскадом, 7.3); чаты шлюза без разговоров, которые не
        текущие ни у одного ключа, — как удаление чата (контрольная точка WAL). Число удалённых чатов."""
        with self.lock, transaction(self.conn):
            self.conn.execute("DELETE FROM agent_conversations WHERE last_seen < ?", (before,))
            orphans = [row["id"] for row in self.conn.execute(
                "SELECT id FROM chats WHERE kind = 'agent' "
                "AND NOT EXISTS (SELECT 1 FROM agent_conversations c WHERE c.chat_id = chats.id) "
                "AND NOT EXISTS (SELECT 1 FROM api_keys k WHERE k.chat_id = chats.id)"
            ).fetchall()]
        for chat_id in orphans:
            self.delete_chat(chat_id)
        return len(orphans)

    # --- настройки в базе ---------------------------------------------------------

    def setting(self, key: str) -> str | None:
        row = self._one("SELECT value FROM settings WHERE key = ?", key)
        return None if row is None else row["value"]

    def set_setting(self, key: str, value: str) -> None:
        self._run(
            "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            key, value,
        )

    # --- эталонный набор (FR-6.10, QA-1) -----------------------------------------------

    def add_gold(self, user_id: str | None, text: str, spans: list[dict], metadata: dict | None = None) -> str:
        gold_id = uuid.uuid4().hex
        key = self.global_key
        metadata = metadata or {}
        with self.lock, transaction(self.conn):
            if metadata.get("purpose"):
                for row in self.gold():
                    same_source = metadata.get("source") == row.metadata.get("source") or text == row.text
                    if same_source and row.metadata.get("purpose") and row.metadata["purpose"] != metadata["purpose"]:
                        raise ValueError("Примеры одного источника нельзя разделять между настройкой и контролем")
            self.conn.execute(
                "INSERT INTO gold(id, user_id, text_enc, spans_enc, created_at, metadata_enc) VALUES (?, ?, ?, ?, ?, ?)",
                (gold_id, user_id, self._enc(key, text, f"gold.text:{gold_id}"),
                 self._enc(key, json.dumps(spans), f"gold.spans:{gold_id}"), self._now(),
                 self._enc(key, json.dumps(metadata), f"gold.metadata:{gold_id}")),
            )
        return gold_id

    def gold(self) -> list[GoldRow]:
        key = self.global_key
        return [
            GoldRow(
                row["id"], row["user_id"],
                self._dec(key, row["text_enc"], f"gold.text:{row['id']}"),
                json.loads(self._dec(key, row["spans_enc"], f"gold.spans:{row['id']}")),
                row["created_at"],
                json.loads(self._dec(key, row["metadata_enc"], f"gold.metadata:{row['id']}")) if row["metadata_enc"] else {},
            )
            for row in self._all("SELECT * FROM gold ORDER BY created_at, id")
        ]

    def delete_gold(self, gold_id: str) -> bool:
        return self._run("DELETE FROM gold WHERE id = ?", gold_id) == 1

    def chat_gold(self, chat_id: str) -> list[str]:
        """Примеры эталона, сохранённые из чата: отметка chat в метаданных (ChatService.save_gold) или источник по
        умолчанию «chat:<id>» у сохранённых до отметки. Расшифровываются только метаданные, не тексты."""
        key = self.global_key
        found = []
        for row in self._all("SELECT id, metadata_enc FROM gold WHERE metadata_enc IS NOT NULL"):
            metadata = json.loads(self._dec(key, row["metadata_enc"], f"gold.metadata:{row['id']}"))
            if metadata.get("chat") == chat_id or metadata.get("source") == f"chat:{chat_id}":
                found.append(row["id"])
        return found

    # --- словарь, шаблоны, политики -------------------------------------------

    def _insert_dictionary(
        self, list_: str, value: str, type_: EntityType | None, aliases: tuple[str, ...], comment: str,
        inflect: bool = False,
    ) -> str:
        entry_id = uuid.uuid4().hex
        key = self.global_key
        self.conn.execute(
            "INSERT INTO dictionary(id, list, type, value_enc, aliases_enc, comment_enc, created_at, inflect)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry_id, list_, type_.value if type_ else None,
                self._enc(key, value, f"dictionary.value:{entry_id}"),
                self._enc(key, json.dumps(list(aliases), ensure_ascii=False), f"dictionary.aliases:{entry_id}"),
                self._enc(key, comment, f"dictionary.comment:{entry_id}"),
                self._now(), int(inflect),
            ),
        )
        return entry_id

    def add_dictionary(
        self, list_: str, value: str, type_: EntityType | None = None, aliases: tuple[str, ...] = (), comment: str = "",
        inflect: bool = False,
    ) -> str:
        with self.lock:
            return self._insert_dictionary(list_, value, type_, aliases, comment, inflect)

    def add_dictionary_many(self, list_: str, values: list[str], type_: EntityType | None = None) -> int:
        """Импорт из CSV: тысячи строк одной транзакцией, а не по записи на диск каждая."""
        with self.lock, transaction(self.conn):
            for value in values:
                self._insert_dictionary(list_, value, type_, (), "")
        return len(values)

    def dictionary(self) -> list[DictionaryRow]:
        key = self.global_key
        return [
            DictionaryRow(
                row["id"], row["list"], EntityType(row["type"]) if row["type"] else None,
                self._dec(key, row["value_enc"], f"dictionary.value:{row['id']}"),
                tuple(json.loads(self._dec(key, row["aliases_enc"], f"dictionary.aliases:{row['id']}"))),
                self._dec(key, row["comment_enc"], f"dictionary.comment:{row['id']}"), bool(row["inflect"]),
            )
            for row in self._all("SELECT * FROM dictionary ORDER BY created_at, id")
        ]

    def in_dictionary(self, list_: str, value: str) -> bool:
        """Значение уже есть в списке — без учёта регистра, как при импорте CSV. Значения зашифрованы,
        поэтому сравнение — после расшифровки только значений нужного списка, до первого совпадения."""
        wanted = value.lower()
        return any(
            self._dec(self.global_key, row["value_enc"], f"dictionary.value:{row['id']}").lower() == wanted
            for row in self._all("SELECT id, value_enc FROM dictionary WHERE list = ? ORDER BY created_at, id", list_)
        )

    def delete_dictionary(self, entry_id: str) -> None:
        self._run("DELETE FROM dictionary WHERE id = ?", entry_id)

    def add_pattern(self, name: str, regex: str, type_: EntityType) -> str:
        pattern_id = uuid.uuid4().hex
        self._run("INSERT INTO patterns(id, name, regex, type, enabled) VALUES (?, ?, ?, ?, 1)", pattern_id, name, regex, type_.value)
        return pattern_id

    def patterns(self) -> list[PatternRow]:
        return [
            PatternRow(row["id"], row["name"], row["regex"], EntityType(row["type"]), bool(row["enabled"]))
            for row in self._all("SELECT * FROM patterns ORDER BY name")
        ]

    def delete_pattern(self, pattern_id: str) -> bool:
        return self._run("DELETE FROM patterns WHERE id = ?", pattern_id) == 1

    def policies(self) -> dict[EntityType, Policy]:
        result = default_policies()
        for row in self._all("SELECT type, policy FROM policies"):
            result[EntityType(row["type"])] = Policy(row["policy"])
        return result

    def set_policy(self, type_: EntityType, policy: Policy) -> None:
        self._run("INSERT OR REPLACE INTO policies(type, policy) VALUES (?, ?)", type_.value, policy.value)

    def settings(self) -> Settings:
        """Настройки ядра. Значения «никогда не скрывать» приводятся к нижнему регистру здесь, на границе."""
        rows = self.dictionary()
        always = tuple(
            dictionary.entry(r.type, r.value, r.aliases, r.inflect) for r in rows if r.list == "always" and r.type is not None
        )
        never = frozenset(v.strip().lower() for r in rows if r.list == "never" for v in (r.value, *r.aliases) if v.strip())
        patterns = tuple(CustomPattern(p.name, p.regex, p.type) for p in self.patterns() if p.enabled)
        return Settings(always=always, never=never, patterns=patterns, policies=self.policies())

    # --- журнал и копия --------------------------------------------------------

    def audit(self, event: str, user_id: str | None = None, chat_id: str | None = None, **details: object) -> None:
        """Только идентификаторы и счётчики: оригиналы и тексты сюда не передаются (FR-11.2)."""
        self._run(
            "INSERT INTO audit(ts, user_id, chat_id, event, details) VALUES (?, ?, ?, ?, ?)",
            self._now(), user_id, chat_id, event, json.dumps(details, ensure_ascii=False),
        )

    def audit_events(
        self, event: str | None = None, user_id: str | None = None,
        since: str | None = None, before: str | None = None, limit: int | None = 200,
    ) -> list[AuditRow]:
        """Свежие первыми. since и before — начало строки ISO: «2026-10-14» отбирает с начала суток (UTC).
        limit None — без предела (выгрузка CSV)."""
        sql, args = "SELECT * FROM audit WHERE 1 = 1", []
        for condition, value in (("event = ?", event), ("user_id = ?", user_id), ("ts >= ?", since), ("ts < ?", before)):
            if value:
                sql += f" AND {condition}"
                args.append(value)
        sql += " ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(limit)
        return [
            AuditRow(row["id"], row["ts"], row["user_id"], row["chat_id"], row["event"], json.loads(row["details"]))
            for row in self._all(sql, *args)
        ]

    def backup(self, target: Path) -> None:
        """Копия базы средствами SQLite, без остановки службы. Ключ в копию не входит."""
        with self.lock:
            copy = sqlite3.connect(str(target))
            try:
                self.conn.backup(copy)
            finally:
                copy.close()
