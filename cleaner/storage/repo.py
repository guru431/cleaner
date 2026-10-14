"""Хранилище: содержимое зашифровано, у каждого чата свой ключ, состояние чата — одним столбцом."""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path

from cleaner.clock import Clock
from cleaner.core.types import ChatState, CustomPattern, DictEntry, EntityType, Policy, Settings, default_policies
from cleaner.storage import crypto
from cleaner.storage.codec import state_from_json, state_to_json
from cleaner.storage.db import transaction


class StaleState(Exception):
    """Состояние чата изменилось после чтения: работу нужно повторить на свежем."""


# Слои 4 и 5 по умолчанию для чатов без явного решения (FR-3.8). Слой 4 включает задача 18 — когда он есть.
DEFAULT_LAYERS = {"ner": False, "llm": False}


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


@dataclass(frozen=True)
class Chat:
    id: str
    user_id: str
    title: str
    updated_at: str


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
    risk_status: str = ""                                # "" | queued | running | done | failed


@dataclass(frozen=True)
class DictionaryRow:
    id: str
    list: str                     # always | never
    type: EntityType | None
    value: str
    aliases: tuple[str, ...]
    comment: str


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


class Repository:
    def __init__(self, conn: sqlite3.Connection, master_key: bytes, clock: Clock):
        self.conn = conn
        self.master = master_key
        self.clock = clock
        self.lock = threading.RLock()            # одно соединение на процесс: доступ по очереди
        self.global_key = self._load_global_key()

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
        self._run("UPDATE users SET password_hash = ? WHERE id = ?", password_hash, user_id)
        self._run("DELETE FROM sessions WHERE user_id = ?", user_id)

    def set_disabled(self, user_id: str, disabled: bool) -> None:
        self._run("UPDATE users SET disabled = ? WHERE id = ?", int(disabled), user_id)
        if disabled:
            self._run("DELETE FROM sessions WHERE user_id = ?", user_id)

    def create_session(self, token_hash: str, user_id: str, csrf: str) -> None:
        now = self._now()
        self._run(
            "INSERT INTO sessions(token_hash, user_id, csrf, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)",
            token_hash, user_id, csrf, now, now,
        )

    def session(self, token_hash: str) -> Session | None:
        row = self._one("SELECT * FROM sessions WHERE token_hash = ?", token_hash)
        return None if row is None else Session(row["token_hash"], row["user_id"], row["csrf"], row["last_seen_at"])

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

    def create_chat(self, user_id: str, title: str, label_style: str = "angle") -> str:
        chat_id = uuid.uuid4().hex
        dek = crypto.new_key()
        state = ChatState(chat_id=chat_id, net_key=os.urandom(32), label_style=label_style)
        now = self._now()
        self._run(
            "INSERT INTO chats(id, user_id, title_enc, dek_wrapped, state_enc, version, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
            chat_id, user_id,
            self._enc(dek, title, f"chats.title:{chat_id}"),
            crypto.seal(self.master, dek, f"chat-dek:{chat_id}"),
            crypto.seal(dek, state_to_json(state), f"chats.state:{chat_id}"),
            now, now,
        )
        return chat_id

    def _chat(self, row: sqlite3.Row) -> Chat:
        title = self._dec(self._dek(row["id"]), row["title_enc"], f"chats.title:{row['id']}")
        return Chat(row["id"], row["user_id"], title, row["updated_at"])

    def chat(self, chat_id: str) -> Chat | None:
        row = self._one("SELECT id, user_id, title_enc, updated_at FROM chats WHERE id = ?", chat_id)
        return None if row is None else self._chat(row)

    def chats(self, user_id: str) -> list[Chat]:
        rows = self._all(
            "SELECT id, user_id, title_enc, updated_at FROM chats WHERE user_id = ? ORDER BY updated_at DESC, id",
            user_id,
        )
        return [self._chat(row) for row in rows]

    def rename_chat(self, chat_id: str, title: str) -> None:
        self._run(
            "UPDATE chats SET title_enc = ?, updated_at = ? WHERE id = ?",
            self._enc(self._dek(chat_id), title, f"chats.title:{chat_id}"), self._now(), chat_id,
        )

    def delete_chat(self, chat_id: str) -> None:
        """Строки чата и его ключ удаляются; secure_delete перезаписывает их на диске (FR-1.4).

        Копии страниц с ключом чата остаются в файле журнала WAL до контрольной точки, а соединение
        службы живёт долго: контрольная точка с усечением журнала выполняется сразу.
        """
        with self.lock:
            self.conn.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def load_state(self, chat_id: str) -> tuple[ChatState, int]:
        row = self._one("SELECT state_enc, version FROM chats WHERE id = ?", chat_id)
        if row is None:
            raise KeyError(chat_id)
        raw = crypto.unseal(self._dek(chat_id), row["state_enc"], f"chats.state:{chat_id}")
        return state_from_json(raw), row["version"]

    def _item(self, row: sqlite3.Row, key: bytes) -> Item:
        sanitized = row["sanitized_enc"]
        return Item(
            id=row["id"], seq=row["seq"], kind=row["kind"],
            original=self._dec(key, row["original_enc"], f"items.original:{row['id']}"),
            sanitized=None if sanitized is None else self._dec(key, sanitized, f"items.sanitized:{row['id']}"),
            spans=json.loads(row["spans"]), notices=json.loads(row["notices"]), exposed=json.loads(row["exposed"]),
            created_at=row["created_at"], source=row["source"], status=row["status"], meta=json.loads(row["meta"]),
            model_spans=json.loads(row["model_spans"]), risk_status=row["risk_status"],
        )

    def items(self, chat_id: str) -> list[Item]:
        key = self._dek(chat_id)
        return [self._item(row, key) for row in self._all("SELECT * FROM items WHERE chat_id = ? ORDER BY seq", chat_id)]

    def item(self, chat_id: str, item_id: str) -> Item | None:
        row = self._one("SELECT * FROM items WHERE id = ? AND chat_id = ?", item_id, chat_id)
        return None if row is None else self._item(row, self._dek(chat_id))

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
        new_items: Iterable[Item] = (), updated_items: Iterable[Item] = (),
    ) -> None:
        """Состояние и элементы — одной транзакцией. StaleState, если чат успели изменить."""
        key = self._dek(chat_id)
        now = self._now()
        with self.lock, transaction(self.conn):
            cursor = self.conn.execute(
                "UPDATE chats SET state_enc = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?",
                (crypto.seal(key, state_to_json(state), f"chats.state:{chat_id}"), now, chat_id, version),
            )
            if cursor.rowcount != 1:
                raise StaleState(chat_id)
            seq = self.conn.execute("SELECT COALESCE(MAX(seq), 0) FROM items WHERE chat_id = ?", (chat_id,)).fetchone()[0]
            for item in new_items:
                seq += 1
                self._insert_item(key, chat_id, item, seq, now)
            for item in updated_items:
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

    def fail_interrupted(self, reason: str) -> int:
        """При старте службы: обработка, прерванная остановкой, — отказ с причиной (NFR-6). Число таких элементов."""
        with self.lock, transaction(self.conn):
            rows = self.conn.execute("SELECT id, meta FROM items WHERE status IN ('queued', 'running')").fetchall()
            for row in rows:
                meta = json.loads(row["meta"])
                meta.pop("progress", None)
                meta["error"] = reason
                self.conn.execute(
                    "UPDATE items SET status = 'failed', meta = ? WHERE id = ?",
                    (json.dumps(meta, ensure_ascii=False), row["id"]),
                )
            self.conn.execute("UPDATE items SET risk_status = 'failed' WHERE risk_status IN ('queued', 'running')")
        return len(rows)

    def set_item_risk_status(self, chat_id: str, item_id: str, status: str) -> None:
        if self._run("UPDATE items SET risk_status = ? WHERE id = ? AND chat_id = ?", status, item_id, chat_id) != 1:
            raise KeyError(item_id)

    def set_item_risk(self, chat_id: str, item_id: str, risk: dict) -> None:
        """Догадки локальной модели: верная догадка — это оригинал, поэтому они зашифрованы (FR-9.3)."""
        sealed = self._enc(self._dek(chat_id), json.dumps(risk, ensure_ascii=False), f"items.risk:{item_id}")
        changed = self._run(
            "UPDATE items SET risk_enc = ?, risk_status = 'done' WHERE id = ? AND chat_id = ?", sealed, item_id, chat_id
        )
        if changed != 1:
            raise KeyError(item_id)

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

    def add_gold(self, user_id: str | None, text: str, spans: list[dict]) -> str:
        gold_id = uuid.uuid4().hex
        key = self.global_key
        self._run(
            "INSERT INTO gold(id, user_id, text_enc, spans_enc, created_at) VALUES (?, ?, ?, ?, ?)",
            gold_id, user_id,
            self._enc(key, text, f"gold.text:{gold_id}"),
            self._enc(key, json.dumps(spans), f"gold.spans:{gold_id}"),
            self._now(),
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
            )
            for row in self._all("SELECT * FROM gold ORDER BY created_at, id")
        ]

    def delete_gold(self, gold_id: str) -> bool:
        return self._run("DELETE FROM gold WHERE id = ?", gold_id) == 1

    # --- словарь, шаблоны, политики -------------------------------------------

    def _insert_dictionary(
        self, list_: str, value: str, type_: EntityType | None, aliases: tuple[str, ...], comment: str
    ) -> str:
        entry_id = uuid.uuid4().hex
        key = self.global_key
        self.conn.execute(
            "INSERT INTO dictionary(id, list, type, value_enc, aliases_enc, comment_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                entry_id, list_, type_.value if type_ else None,
                self._enc(key, value, f"dictionary.value:{entry_id}"),
                self._enc(key, json.dumps(list(aliases), ensure_ascii=False), f"dictionary.aliases:{entry_id}"),
                self._enc(key, comment, f"dictionary.comment:{entry_id}"),
                self._now(),
            ),
        )
        return entry_id

    def add_dictionary(
        self, list_: str, value: str, type_: EntityType | None = None, aliases: tuple[str, ...] = (), comment: str = ""
    ) -> str:
        with self.lock:
            return self._insert_dictionary(list_, value, type_, aliases, comment)

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
                self._dec(key, row["comment_enc"], f"dictionary.comment:{row['id']}"),
            )
            for row in self._all("SELECT * FROM dictionary ORDER BY created_at, id")
        ]

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

    def delete_pattern(self, pattern_id: str) -> None:
        self._run("DELETE FROM patterns WHERE id = ?", pattern_id)

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
        always = tuple(DictEntry(r.type, r.value, r.aliases) for r in rows if r.list == "always" and r.type is not None)
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
        since: str | None = None, before: str | None = None, limit: int = 200,
    ) -> list[AuditRow]:
        """Свежие первыми. since и before — начало строки ISO: «2026-10-14» отбирает с начала суток (UTC)."""
        sql, args = "SELECT * FROM audit WHERE 1 = 1", []
        for condition, value in (("event = ?", event), ("user_id = ?", user_id), ("ts >= ?", since), ("ts < ?", before)):
            if value:
                sql += f" AND {condition}"
                args.append(value)
        sql += " ORDER BY id DESC LIMIT ?"
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
