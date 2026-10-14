"""Действия пользователя над чатами: ядро очистки плюс хранилище."""
from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from cleaner.core import leakcheck
from cleaner.core.entities import ops
from cleaner.core.leakcheck import Leak
from cleaner.core.match import normalize
from cleaner.core.pipeline import SanitizeResult, sanitize
from cleaner.core.restore import RestoreResult, restore
from cleaner.core.types import ChatState, EntityType, Policy, Settings
from cleaner.storage.repo import Item, Repository, StaleState

_ATTEMPTS = 3

Work = Callable[[ChatState, list[Item], Settings], tuple[list[Item], list[Item]]]


class TextTooLong(ValueError):
    """Текст длиннее допустимого (FR-2.1)."""


class EditRefused(ValueError):
    """Правка отклонена; текст сообщения можно показать пользователю — в нём нет его данных."""


@dataclass
class InputView:
    item: Item
    leaks: list[Leak]
    blocked: list[dict]                 # фрагменты типов с политикой «блокировать»

    @property
    def deliverable(self) -> bool:
        return not self.leaks and not self.blocked


@dataclass
class AnswerView:
    item: Item
    result: RestoreResult


@dataclass
class ChatView:
    state: ChatState
    settings: Settings
    items: list[InputView | AnswerView]


def _spans(result: SanitizeResult) -> list[dict]:
    return [
        {"start": s.start, "end": s.end, "entity_id": s.entity_id, "surrogate": s.surrogate, "sources": list(s.sources)}
        for s in result.spans
    ]


def _notices(result: SanitizeResult) -> list[dict]:
    return [{"code": n.code, "start": n.start, "end": n.end} for n in result.notices]


class ChatService:
    def __init__(self, repo: Repository, max_text_chars: int = 500_000):
        self.repo = repo
        self.max_text_chars = max_text_chars

    def _check_length(self, text: str) -> None:
        if len(text) > self.max_text_chars:
            raise TextTooLong(f"текст длиннее {self.max_text_chars} знаков")

    def _apply(self, chat_id: str, work: Work) -> list[Item]:
        """Работа над загруженным состоянием и запись одной транзакцией.

        Исключение ядра отбрасывает изменённое состояние: в базе ничего не меняется.
        Если чат успели изменить, работа повторяется на свежем состоянии.
        """
        for _ in range(_ATTEMPTS):
            state, version = self.repo.load_state(chat_id)
            new_items, updated = work(state, self.repo.items(chat_id), self.repo.settings())
            try:
                self.repo.commit_chat(chat_id, state, version, new_items, updated)
            except StaleState:
                continue
            return new_items
        raise StaleState(chat_id)

    def add_input(self, chat_id: str, user_id: str, text: str) -> Item:
        self._check_length(text)
        report: dict[str, object] = {}

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            result = sanitize(state, text, settings)
            report.update(
                replaced=dict(Counter(state.entities[s.entity_id].type.value for s in result.spans)),
                notices=len(result.notices), leaks=len(result.leaks), blocked=len(result.blocked),
            )
            return [Item(uuid.uuid4().hex, 0, "input", text, result.sanitized, _spans(result), _notices(result))], []

        [item] = self._apply(chat_id, work)
        self.repo.audit("sanitize", user_id, chat_id, **report)
        if report["leaks"]:
            self.repo.audit("leak", user_id, chat_id, count=report["leaks"])
        return item

    def add_answer(self, chat_id: str, user_id: str, text: str) -> Item:
        self._check_length(text)
        counters: dict[str, int] = {}

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            counters.update(restore(state, text, settings).counters)
            return [Item(uuid.uuid4().hex, 0, "answer", text, None)], []

        [item] = self._apply(chat_id, work)
        self.repo.audit("restore", user_id, chat_id, **counters)
        return item

    def view(self, chat_id: str) -> ChatView:
        state, _ = self.repo.load_state(chat_id)
        settings = self.repo.settings()
        views: list[InputView | AnswerView] = []
        for item in self.repo.items(chat_id):
            if item.kind == "input":
                leaks = leakcheck.check(item.sanitized or "", state, settings)
                blocked = [
                    span for span in item.spans
                    if span["entity_id"] in state.entities
                    and settings.policies.get(state.entities[span["entity_id"]].type) is Policy.BLOCK
                ]
                views.append(InputView(item, leaks, blocked))
            else:
                views.append(AnswerView(item, restore(state, item.original, settings)))
        return ChatView(state, settings, views)

    def _edit(self, chat_id: str, user_id: str, action: str, change: Callable[[ChatState, list[Item]], None]) -> None:
        """Правка состояния и повторная очистка входных текстов чата (FR-6.5, FR-6.8)."""
        leaks = Counter()

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            change(state, items)
            leaks.clear()                       # при повторе на свежем состоянии считаем заново
            pairs = []
            for item in items:
                if item.kind != "input":
                    continue
                result = sanitize(state, item.original, settings)
                leaks["count"] += len(result.leaks)
                if result.sanitized != item.sanitized:
                    fresh = Item(item.id, item.seq, "input", item.original, result.sanitized, _spans(result), _notices(result))
                    pairs.append((item, fresh))
            for old, fresh in pairs:
                opened = {leak.entity_id for leak in leakcheck.check(old.sanitized or "", state, settings) if leak.entity_id}
                fresh.exposed = sorted(set(old.exposed) | opened)
            return [], [fresh for _, fresh in pairs]

        self._apply(chat_id, work)
        self.repo.audit("edit", user_id, chat_id, action=action)
        if leaks["count"]:
            self.repo.audit("leak", user_id, chat_id, count=leaks["count"])

    def refresh(self, chat_id: str, user_id: str) -> None:
        self._edit(chat_id, user_id, "refresh", lambda state, items: None)

    def mask_value(self, chat_id: str, user_id: str, item_id: str, value: str, type_: EntityType) -> None:
        def change(state: ChatState, items: list[Item]) -> None:
            item = next((i for i in items if i.id == item_id and i.kind == "input"), None)
            cleaned = value.strip()
            if item is None or not cleaned:
                raise EditRefused("выделите фрагмент текста")
            if normalize(cleaned) not in normalize(item.original):
                raise EditRefused("такого фрагмента в тексте нет")
            ops.mask(state, cleaned, type_)

        self._edit(chat_id, user_id, "mask", change)

    def unmask(self, chat_id: str, user_id: str, values: Iterable[str]) -> None:
        """Снять замену со значений во всём чате (FR-6.2). Таблица чата передаёт все написания сущности."""
        cleaned = [value.strip() for value in values if value.strip()]
        if not cleaned:
            raise EditRefused("пустое значение")

        def change(state: ChatState, items: list[Item]) -> None:
            for value in cleaned:
                ops.unmask(state, value)

        self._edit(chat_id, user_id, "unmask", change)

    def retype(self, chat_id: str, user_id: str, entity_id: str, type_: EntityType) -> None:
        self._edit(chat_id, user_id, "retype", lambda state, items: ops.retype(state, entity_id, type_))

    def merge(self, chat_id: str, user_id: str, keep_id: str, drop_id: str) -> None:
        if keep_id == drop_id:
            raise EditRefused("выберите две разные сущности")

        def change(state: ChatState, items: list[Item]) -> None:
            if state.entities[keep_id].type is not state.entities[drop_id].type:
                raise EditRefused("объединять можно только сущности одного типа")
            ops.merge_entities(state, keep_id, drop_id)

        self._edit(chat_id, user_id, "merge", change)

    def set_restore_value(self, chat_id: str, user_id: str, entity_id: str, value: str) -> None:
        cleaned = value.strip()
        if not cleaned:
            raise EditRefused("пустое значение")
        self._edit(chat_id, user_id, "restore_value", lambda state, items: ops.set_restore_value(state, entity_id, cleaned))
