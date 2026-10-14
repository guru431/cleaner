"""Действия пользователя над чатами: ядро очистки плюс хранилище."""
from __future__ import annotations

import logging
import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any

from cleaner.core import leakcheck, risk
from cleaner.core.detect.base import DetectorError
from cleaner.core.entities import ops
from cleaner.core.leakcheck import Leak
from cleaner.core.match import normalize
from cleaner.core.pipeline import Layers, SanitizeResult, sanitize
from cleaner.core.restore import RestoreResult, restore
from cleaner.core.types import ChatState, EntityType, Policy, Settings, Span
from cleaner.storage.repo import Item, Repository, StaleState

log = logging.getLogger("cleaner.service")

_ATTEMPTS = 3
LAYERS = ("ner", "llm")          # слой 4 и слой 5; совпадают с источником их фрагментов
_INTERNAL = "Внутренняя ошибка очистки: текст не обработан и никуда не передан"
_BUSY = "Чат меняли одновременно, текст не обработан — запустите его ещё раз"

Work = Callable[[ChatState, list[Item], Settings], tuple[list[Item], list[Item]]]
Submit = Callable[..., None]


def run_now(fn: Callable[..., None], *args: Any) -> None:
    """Задание выполняется сразу, в том же потоке: для команд и тестов. Приложение передаёт Jobs.submit."""
    fn(*args)


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
        return self.item.status == "done" and not self.leaks and not self.blocked


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


def _model_spans(result: SanitizeResult) -> list[dict]:
    """Находки слоёв 4–5 — позиции и тип, без значений: хранятся открыто, как spans."""
    return [
        {"start": s.start, "end": s.end, "type": s.type.value, "source": s.source, "score": round(s.score, 4)}
        for s in result.model_spans
    ]


def _cached_layers(item: Item, on: dict[str, bool]) -> tuple[Layers, list[str]]:
    """Для повторной очистки после правки: находки слоёв, которые работали и всё ещё включены, — без моделей."""
    ran = [name for name in item.meta.get("layers", []) if on.get(name)]
    spans = tuple(
        Span(s["start"], s["end"], EntityType(s["type"]), s["source"], float(s.get("score", 1.0)))
        for s in item.model_spans if s["source"] in ran
    )
    return Layers(cached=spans), ran


class ChatService:
    def __init__(
        self, repo: Repository, max_text_chars: int = 500_000, engines: Any = None, submit: Submit = run_now,
    ):
        self.repo = repo
        self.max_text_chars = max_text_chars
        self.engines = engines          # cleaner.engines.Engines или заглушка тестов; None — без слоёв 4–5
        self.submit = submit

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

    # --- слои 4 и 5 (FR-3.8) ---------------------------------------------------------

    def layers(self, chat_id: str) -> dict[str, bool]:
        """Слои 4 и 5 чата: явное решение пользователя, иначе умолчание администратора."""
        chosen = self.repo.chat_layers(chat_id)
        return {name: chosen.get(name, default) for name, default in self.repo.layer_defaults().items()}

    def _enabled(self, chat_id: str) -> dict[str, bool]:
        return self.layers(chat_id) if self.engines is not None else {name: False for name in LAYERS}

    def set_layer(self, chat_id: str, user_id: str, layer: str, enabled: bool) -> None:
        if layer not in LAYERS:
            raise EditRefused("отключать можно только слои 4 и 5")
        self.repo.set_chat_layer(chat_id, layer, enabled)
        self.repo.audit("layer_changed", user_id, chat_id, layer=layer, enabled=enabled)

    def _live_layers(self, chat_id: str) -> tuple[Layers, list[str]]:
        """Слои для новой очистки: модели вызываются. Включённый, но недоступный слой — DetectorError (FR-3.7)."""
        on = self._enabled(chat_id)
        ner = self.engines.ner() if on["ner"] else None
        llm = self.engines.llm() if on["llm"] else None
        return Layers(ner=ner, llm=llm), [name for name in LAYERS if on[name]]

    # --- входные тексты: очередь и задание (раздел 14) ----------------------------

    def add_input(self, chat_id: str, user_id: str, text: str) -> Item:
        self._check_length(text)
        item = self.repo.add_item(chat_id, Item(uuid.uuid4().hex, 0, "input", text, None, source="paste", status="queued"))
        self.submit(self.process, chat_id, item.id, user_id)
        return self.repo.item(chat_id, item.id) or item

    def add_file(self, chat_id: str, user_id: str, filename: str, data: bytes) -> Item:
        """Файл — в очередь. Его байты живут только в памяти задания; имя нужно лишь для расширения (FR-2.7)."""
        item = self.repo.add_item(chat_id, Item(uuid.uuid4().hex, 0, "input", "", None, source="file", status="queued"))
        self.submit(self.process, chat_id, item.id, user_id, data, filename)
        return self.repo.item(chat_id, item.id) or item

    def process(self, chat_id: str, item_id: str, user_id: str, data: bytes | None = None, filename: str = "") -> None:
        """Задание: извлечь текст файла, очистить всеми включёнными слоями, записать. Отказ — элемент failed."""
        try:
            item = self.repo.item(chat_id, item_id)
            if item is None:
                return                                  # чат удалили, пока задание ждало очереди
            self.repo.set_item_status(chat_id, item_id, "running")
            if data is not None:
                item = self._extract(chat_id, item, data, filename)
            self._check_length(item.original)
            layers, ran = self._live_layers(chat_id)
            report = self._sanitize_item(chat_id, item, layers, ran)
        except KeyError as exc:
            if self.repo.chat(chat_id) is not None:       # чат на месте: KeyError пришёл из слоя или библиотеки
                self._failed(chat_id, item_id, user_id, exc)
            return
        except Exception as exc:
            self._failed(chat_id, item_id, user_id, exc)
            return
        self.repo.audit("sanitize", user_id, chat_id, **report)
        if report["leaks"]:
            self.repo.audit("leak", user_id, chat_id, count=report["leaks"])

    def _extract(self, chat_id: str, item: Item, data: bytes, filename: str) -> Item:
        """Текст из файла записывается сразу: если очистка не удастся, его можно очистить заново без файла."""
        from cleaner.ingest.extract import ExtractError, detect_kind

        if self.engines is None:
            raise ExtractError("Разбор файлов не подключён")
        if detect_kind(filename, data) == "text" and len(data) > 4 * self.max_text_chars:
            self._check_length(" " * (self.max_text_chars + 1))    # знак UTF-8 — не больше 4 байт: заведомо длиннее
        extracted = self.engines.extractor().extract(
            filename, data, lambda done, total: self.repo.set_item_progress(chat_id, item.id, f"{done}/{total}"),
        )
        # До записи: текст, который всё равно не очистить, не хранится, и повторить нечего (файл не хранится).
        self._check_length(extracted.text)
        meta: dict[str, object] = {"kind": extracted.kind}
        if extracted.pages:
            meta["pages"] = extracted.pages
        if extracted.ocr_pages:
            meta["ocr_pages"] = list(extracted.ocr_pages)
        if extracted.unread_pages:
            meta["unread_pages"] = list(extracted.unread_pages)
        self.repo.set_item_original(chat_id, item.id, extracted.text, meta)
        return replace(item, original=extracted.text, meta=meta)

    def _sanitize_item(self, chat_id: str, item: Item, layers: Layers, ran: list[str]) -> dict[str, object]:
        report: dict[str, object] = {}
        cache: tuple[Span, ...] | None = None

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            nonlocal cache
            # Модели — один раз: при повторе на свежем состоянии (StaleState) их находки берутся из первого прогона.
            result = sanitize(state, item.original, settings, layers if cache is None else Layers(cached=cache))
            cache = tuple(result.model_spans)
            report.clear()
            report.update(
                replaced=dict(Counter(state.entities[s.entity_id].type.value for s in result.spans)),
                notices=len(result.notices), leaks=len(result.leaks), blocked=len(result.blocked),
                source=item.source, layers=ran,
            )
            if item.meta.get("kind"):
                report["kind"] = item.meta["kind"]
            done = replace(
                item, sanitized=result.sanitized, spans=_spans(result), notices=_notices(result), status="done",
                meta={k: v for k, v in item.meta.items() if k not in ("error", "progress")} | {"layers": ran},
                model_spans=_model_spans(result),
            )
            return [], [done]

        self._apply(chat_id, work)
        return report

    def _failed(self, chat_id: str, item_id: str, user_id: str, exc: Exception) -> None:
        """Причина для пользователя — только из своих исключений: в чужих может оказаться его текст (SEC-11)."""
        from cleaner.ingest.extract import ExtractError

        if isinstance(exc, (ExtractError, DetectorError, TextTooLong)):
            reason = str(exc)
        elif isinstance(exc, StaleState):
            reason = _BUSY
        else:
            reason = _INTERNAL
        log.error("обработка текста: %s", type(exc).__name__)
        try:
            self.repo.set_item_status(chat_id, item_id, "failed", reason)
        except KeyError:
            return
        self.repo.audit("error", user_id, chat_id, kind=type(exc).__name__, stage="process")

    def retry(self, chat_id: str, user_id: str, item_id: str) -> None:
        """Очистить заново всеми включёнными слоями: после отказа, перезапуска или включения слоя."""
        item = self.repo.item(chat_id, item_id)
        if item is None or item.kind != "input":
            raise KeyError(item_id)
        if item.status in ("queued", "running"):
            raise EditRefused("текст ещё обрабатывается")
        if not item.original:
            raise EditRefused("текст файла не был извлечён, а сам файл не хранится: загрузите его ещё раз")
        self.repo.set_item_status(chat_id, item_id, "queued")
        self.submit(self.process, chat_id, item_id, user_id)

    # --- проверка остаточного риска (FR-9.3) ------------------------------------------

    def check_risk(self, chat_id: str, user_id: str, item_id: str) -> None:
        item = self.repo.item(chat_id, item_id)
        if item is None or item.kind != "input":
            raise KeyError(item_id)
        if item.status != "done":
            raise EditRefused("текст ещё не очищен")
        if item.risk_status in ("queued", "running"):
            raise EditRefused("проверка уже идёт")
        if self.engines is None:
            raise EditRefused("локальная модель не подключена")
        self.repo.set_item_risk_status(chat_id, item_id, "queued")
        self.submit(self.run_risk, chat_id, item_id, user_id)

    def run_risk(self, chat_id: str, item_id: str, user_id: str) -> None:
        """Задание: только очищенный текст и только локальной модели (FR-9.5)."""
        try:
            item = self.repo.item(chat_id, item_id)
            if item is None:
                return
            self.repo.set_item_risk_status(chat_id, item_id, "running")
            guesses = self.engines.risk()(item.sanitized or "")
            self.repo.set_item_risk(chat_id, item_id, risk.to_dict(guesses))
        except Exception as exc:
            if isinstance(exc, KeyError) and self.repo.chat(chat_id) is None:
                return                                    # чат удалили, пока шла проверка
            log.error("проверка риска: %s", type(exc).__name__)
            try:
                self.repo.set_item_risk_status(chat_id, item_id, "failed")
            except KeyError:
                return
            self.repo.audit("error", user_id, chat_id, kind=type(exc).__name__, stage="risk")
            return
        self.repo.audit("risk_check", user_id, chat_id, guesses=len(guesses))

    # --- ответы модели и вид чата ----------------------------------------------------

    def add_answer(self, chat_id: str, user_id: str, text: str) -> Item:
        self._check_length(text)
        counters: dict[str, int] = {}

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            counters.update(restore(state, text, settings).counters)
            return [Item(uuid.uuid4().hex, 0, "answer", text, None, source="pasted_answer")], []

        [item] = self._apply(chat_id, work)
        self.repo.audit("restore", user_id, chat_id, **counters)
        return item

    def view(self, chat_id: str) -> ChatView:
        state, _ = self.repo.load_state(chat_id)
        settings = self.repo.settings()
        views: list[InputView | AnswerView] = []
        for item in self.repo.items(chat_id):
            if item.kind == "input":
                if item.status != "done":
                    views.append(InputView(item, [], []))
                    continue
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

    # --- правки (FR-6) -------------------------------------------------------------

    def _edit(self, chat_id: str, user_id: str, action: str, change: Callable[[ChatState, list[Item]], None]) -> None:
        """Правка состояния и повторная очистка входных текстов чата (FR-6.5, FR-6.8). Модели не вызываются."""
        leaks = Counter()
        on = self._enabled(chat_id)

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            change(state, items)
            leaks.clear()                       # при повторе на свежем состоянии считаем заново
            pairs = []
            for item in items:
                if item.kind != "input" or item.status != "done":
                    continue
                layers, ran = _cached_layers(item, on)
                result = sanitize(state, item.original, settings, layers)
                leaks["count"] += len(result.leaks)
                if result.sanitized != item.sanitized or ran != item.meta.get("layers"):
                    fresh = replace(
                        item, sanitized=result.sanitized, spans=_spans(result), notices=_notices(result),
                        meta=item.meta | {"layers": ran},
                    )
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
            item = next((i for i in items if i.id == item_id and i.kind == "input" and i.status == "done"), None)
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

    # --- эталонный набор (FR-6.10, QA-1) --------------------------------------------------

    def save_gold(self, chat_id: str, user_id: str, item_id: str) -> str:
        """Проверенный пользователем текст и итоговая разметка — копией под общим ключом."""
        state, _ = self.repo.load_state(chat_id)
        item = self.repo.item(chat_id, item_id)
        if item is None or item.kind != "input":
            raise KeyError(item_id)
        if item.status != "done":
            raise EditRefused("текст ещё не очищен")
        numbers: dict[str, int] = {}
        spans = []
        for span in sorted(item.spans, key=lambda s: s["start"]):
            entity = state.entities.get(span["entity_id"])
            if entity is None:
                continue
            spans.append({
                "start": span["start"], "end": span["end"], "type": entity.type.value,
                "entity": numbers.setdefault(entity.id, len(numbers)), "origin": entity.origin,
            })
        gold_id = self.repo.add_gold(user_id, item.original, spans)
        self.repo.audit("gold_added", user_id, chat_id, spans=len(spans))
        return gold_id
