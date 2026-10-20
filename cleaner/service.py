"""Действия пользователя над чатами: ядро очистки плюс хранилище."""
from __future__ import annotations

import hashlib
import logging
import pickle
import threading
import uuid
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any

from cleaner.core import leakcheck, risk
from cleaner.core.detect.base import DetectorError
from cleaner.core.detect.llm import CompletionError
from cleaner.core.entities import ops
from cleaner.core.leakcheck import Leak
from cleaner.core.match import normalize
from cleaner.core.pipeline import (
    Layers, NotSendable, Outgoing, OutgoingContext, SanitizeResult, Turn, build_outgoing, probe_context, sanitize,
)
from cleaner.core.restore import RestoreResult, restore
from cleaner.core.types import ChatState, EntityType, Policy, Settings, Span
from cleaner.egress import ProviderError, cloud
from cleaner.storage.codec import state_to_json
from cleaner.storage.repo import Item, Provider, Repository, StaleState

log = logging.getLogger("cleaner.service")

_ATTEMPTS = 3
LAYERS = ("ner", "llm")          # слой 4 и слой 5; совпадают с источником их фрагментов
_INTERNAL = "Внутренняя ошибка очистки: текст не обработан и никуда не передан"
_BUSY = "Чат меняли одновременно, текст не обработан — запустите его ещё раз"
_IN_PROGRESS = "текст ещё обрабатывается"
_RISK_IDLE = ("", "done", "failed", "interrupted")     # состояния проверки риска, из которых её можно запустить
INPUT_SOURCES = ("paste", "instruction")                # вставленный текст и инструкция пользователя для модели (FR-8.5)
LOCAL_ANSWER_TOKENS = 4096
_SEND_INTERNAL = "Внутренняя ошибка отправки"
_STOPPED = "Остановлено"
_SERVICE_STOPPED = "Служба остановлена во время ответа: сохранена полученная часть"
# Итоги проверки утечек для вида чата в памяти процесса: не больше стольких итогов и находок в них всех вместе
# (находка — около 200 байт, 50 000 — около 10 МБ; один итог с тысячами находок иначе раздувал бы память).
_VIEW_RESULTS, _VIEW_FOUND = 1024, 50_000

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


def _in_request(items: list[Item]) -> list[int]:
    """«Замен в запросе» (FR-7.5) ответа на месте каждого элемента и ответа после всех: замены во входных текстах
    после предыдущего ответа, у первого — с начала чата. Отказ без текста и ответ, оборванный ошибкой провайдера
    (FR-8.9), границей не считаются: вопрос уходит снова, и в запросе следующего ответа — те же тексты."""
    counts, count = [], 0
    for item in items:
        counts.append(count)
        if item.kind == "input" and item.status == "done":
            count += len(item.spans)
        elif item.kind == "answer" and item.original and not item.meta.get("aborted"):
            count = 0
    return [*counts, count]


LOCAL_PENDING = "Предыдущий ответ локальной модели ещё идёт: дождитесь его"


def local_pending(items: Iterable[Item]) -> bool:
    """Ответ локальной модели в очереди или в работе: новый вопрос ей не задаётся (кнопка в чате и ask_local)."""
    return any(i.kind == "answer" and i.source == "local" and i.status in ("queued", "running") for i in items)


def _cached_layers(item: Item, on: dict[str, bool]) -> tuple[Layers, list[str]]:
    """Для повторной очистки после правки: находки слоёв, которые работали и всё ещё включены, — без моделей."""
    ran = [name for name in item.meta.get("layers", []) if on.get(name)]
    spans = tuple(
        Span(s["start"], s["end"], EntityType(s["type"]), s["source"], float(s.get("score", 1.0)))
        for s in item.model_spans if s["source"] in ran
    )
    return Layers(cached=spans), ran


class SendRefused(EditRefused):
    """Отправка невозможна; причина без данных пользователя."""


@dataclass
class Preview:
    """Экран подтверждения (FR-8.4): ровно то, что уйдёт, и что в запрос не вошло."""

    outgoing: Outgoing
    provider: Provider
    skipped: list[tuple[int, str]]      # номер элемента в чате и причина


class LiveAnswer:
    """Ответ облака, пока он идёт: фрагменты копятся в памяти, страница получает их событиями сервера."""

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._size = 0
        self._lock = threading.Lock()
        self.cancel = threading.Event()
        self.reason = ""                                 # почему ответ прерван: остановка, удаление чата, служба
        self._closer: Callable[[], None] | None = None
        self.finished = False

    def append(self, piece: str) -> None:
        with self._lock:
            self._parts.append(piece)
            self._size += len(piece)

    def text(self) -> str:
        with self._lock:
            return "".join(self._parts)

    def size(self) -> int:
        with self._lock:
            return self._size

    def on_open(self, closer: Callable[[], None]) -> None:
        """egress передаёт, чем закрыть соединение: остановка прерывает и ожидание молчащего провайдера."""
        with self._lock:
            self._closer = closer
        if self.cancel.is_set():
            self._close()

    def stop(self, reason: str) -> None:
        with self._lock:
            self.reason = self.reason or reason
        self.cancel.set()
        self._close()

    def _close(self) -> None:
        with self._lock:
            closer = self._closer
        if closer is not None:
            try:
                closer()
            except Exception:           # соединение уже закрыто или закрывается: читающий поток выйдет сам
                pass


class LiveAnswers:
    def __init__(self) -> None:
        self._answers: dict[str, LiveAnswer] = {}
        self._lock = threading.Lock()

    def start(self, item_id: str) -> LiveAnswer:
        with self._lock:
            return self._answers.setdefault(item_id, LiveAnswer())

    def get(self, item_id: str) -> LiveAnswer | None:
        with self._lock:
            return self._answers.get(item_id)

    def finish(self, item_id: str) -> None:
        with self._lock:
            answer = self._answers.pop(item_id, None)
        if answer is not None:
            answer.finished = True

    def cancel_all(self) -> None:
        """Остановка службы: идущие ответы прерываются и сохраняются неполными."""
        with self._lock:
            answers = list(self._answers.values())
        for answer in answers:
            answer.stop(_SERVICE_STOPPED)


def link(provider: Provider) -> cloud.Connection:
    return cloud.Connection(
        provider.protocol, provider.base_url, provider.auth_style, provider.api_key, provider.max_tokens,
        provider.extra_body,
    )


class ChatService:
    def __init__(
        self, repo: Repository, max_text_chars: int = 500_000, engines: Any = None, submit: Submit = run_now,
        send_submit: Submit = run_now, cloud_send: Callable[..., Iterable[str]] = cloud.send,
        file_submit: Submit = run_now,
    ):
        self.repo = repo
        self.max_text_chars = max_text_chars
        self.engines = engines          # cleaner.engines.Engines или заглушка тестов; None — без слоёв 4–5
        self.submit = submit
        self.send_submit = send_submit  # свой пул: облако не ждёт за очисткой и моделями в общем (раздел 14)
        self.file_submit = file_submit  # свой пул: вставленный текст не ждёт за распознаванием сканов (раздел 14)
        self.cloud_send = cloud_send
        self.live = LiveAnswers()
        self._view_leaks: OrderedDict[bytes, tuple[Leak, ...]] = OrderedDict()
        self._view_found = 0                    # находок во всех запомненных итогах
        self._view_leaks_lock = threading.Lock()

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

    def add_input(self, chat_id: str, user_id: str, text: str, source: str = "paste") -> Item:
        self._check_length(text)
        if source not in INPUT_SOURCES:
            raise EditRefused("неизвестный вид текста")
        item = self.repo.add_item(chat_id, Item(uuid.uuid4().hex, 0, "input", text, None, source=source, status="queued"))
        self.submit(self.process, chat_id, item.id, user_id)
        return self.repo.item(chat_id, item.id) or item

    def add_file(self, chat_id: str, user_id: str, filename: str, data: bytes) -> Item:
        """Файл — в очередь. Его байты живут только в памяти задания; имя нужно лишь для расширения (FR-2.7)."""
        item = self.repo.add_item(chat_id, Item(uuid.uuid4().hex, 0, "input", "", None, source="file", status="queued"))
        self.file_submit(self.process, chat_id, item.id, user_id, data, filename)
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
        if extracted.hidden_sheets:
            meta["hidden_sheets"] = extracted.hidden_sheets      # только число: имена листов — данные пользователя
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
            raise EditRefused(_IN_PROGRESS)
        if not item.original:
            raise EditRefused("текст файла не был извлечён, а сам файл не хранится: загрузите его ещё раз")
        if not self.repo.queue_item(chat_id, item_id):        # второе нажатие успело прочесть «готово» (m-10)
            raise EditRefused(_IN_PROGRESS)
        self.submit(self.process, chat_id, item_id, user_id)

    # --- проверка остаточного риска (FR-9.3) ------------------------------------------

    def check_risk(self, chat_id: str, user_id: str, item_id: str) -> None:
        item = self.repo.item(chat_id, item_id)
        if item is None or item.kind != "input":
            raise KeyError(item_id)
        if item.status != "done":
            raise EditRefused("текст ещё не очищен")
        if self.engines is None:
            raise EditRefused("локальная модель не подключена")
        job = self.repo.queue_risk(chat_id, item_id, _RISK_IDLE)       # одним UPDATE (m-10)
        if job is None:
            raise EditRefused("проверка уже идёт")
        self.submit(self.run_risk, chat_id, item_id, user_id, job)

    def run_risk(self, chat_id: str, item_id: str, user_id: str, job: str) -> None:
        """Задание: только очищенный текст и только локальной модели (FR-9.5).

        Сначала проверка переходит в работу, потом читается текст: если его изменят после этого, догадки
        не запишутся (set_item_risk), а не окажутся у нового текста. Каждый переход сверяет задание job:
        смена текста стирает его, и конец прежней проверки — догадки или отказ — не ложится на новую."""
        try:
            if not self.repo.set_item_risk_status(chat_id, item_id, job, "running", ("queued",)):
                return                                    # проверку отменила смена текста или чат удалён
            item = self.repo.item(chat_id, item_id)
            if item is None:
                return
            guesses = self.engines.risk()(item.sanitized or "")
            stored = self.repo.set_item_risk(chat_id, item_id, job, item.sanitized, risk.to_dict(guesses))
        except Exception as exc:
            if isinstance(exc, KeyError) and self.repo.chat(chat_id) is None:
                return                                    # чат удалили, пока шла проверка
            log.error("проверка риска: %s", type(exc).__name__)
            self.repo.set_item_risk_status(chat_id, item_id, job, "failed", ("running",))
            self.repo.audit("error", user_id, chat_id, kind=type(exc).__name__, stage="risk")
            return
        if stored:
            self.repo.audit("risk_check", user_id, chat_id, guesses=len(guesses))

    # --- ответы модели и вид чата ----------------------------------------------------

    def add_answer(self, chat_id: str, user_id: str, text: str) -> Item:
        self._check_length(text)
        counters: dict[str, int] = {}

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            counters.update(restore(state, text, settings).counters, in_request=_in_request(items)[-1])
            return [Item(uuid.uuid4().hex, 0, "answer", text, None, source="pasted_answer")], []

        [item] = self._apply(chat_id, work)
        self.repo.audit("restore", user_id, chat_id, **counters)
        return item

    def _view_leak_check(self, text: str, state: ChatState, settings: Settings, inputs: bytes) -> list[Leak]:
        """Проверка утечек для вида чата. Вид строится при каждой загрузке страниц чата, проверки и таблицы замен, а
        проверка линейна по тексту: пять текстов по 100 000 знаков — 0,45 с на загрузку, почти вся её цена. Итог
        зависит только от текста, состояния чата и настроек и запоминается по отпечатку всех троих (inputs — двух
        последних, от view); любое их изменение — другой ключ, и проверка идёт заново. В памяти процесса, давние
        вытесняются (_VIEW_RESULTS, _VIEW_FOUND); в итогах места и id сущностей, текстов нет."""
        key = inputs + hashlib.sha256(text.encode("utf-8")).digest()
        with self._view_leaks_lock:
            found = self._view_leaks.get(key)
            if found is not None:
                self._view_leaks.move_to_end(key)
                return list(found)
        found = tuple(leakcheck.check(text, state, settings))
        if len(found) > _VIEW_FOUND:
            return list(found)                  # не запоминается: вытеснил бы все остальные итоги
        with self._view_leaks_lock:
            # Тот же ключ мог успеть записать параллельный запрос: его находки не считаются дважды.
            self._view_found += len(found) - len(self._view_leaks.pop(key, ()))
            self._view_leaks[key] = found
            while len(self._view_leaks) > _VIEW_RESULTS or self._view_found > _VIEW_FOUND:
                self._view_found -= len(self._view_leaks.popitem(last=False)[1])
        return list(found)

    def view(self, chat_id: str, item_id: str | None = None) -> ChatView:
        """item_id — вид одного входного текста (экраны проверки и выгрузки): проверка утечек других текстов и
        восстановление ответов им не нужны, а после нового текста состояние другое, и запомненные итоги не годятся."""
        state, _ = self.repo.load_state(chat_id)
        settings = self.repo.settings()
        # Отпечаток состояния — его запись в базе (полнота записи проверяется тестом кодека), настроек — pickle:
        # точная запись любых полей, и новых тоже (repr, например, обрезает длинное выражение re.Pattern).
        inputs = hashlib.sha256(state_to_json(state)).digest() + hashlib.sha256(pickle.dumps(settings)).digest()
        views: list[InputView | AnswerView] = []
        items = self.repo.items(chat_id)
        for item, in_request in zip(items, _in_request(items)):
            if item_id is not None and item.id != item_id:
                continue
            if item.kind == "input":
                if item.status != "done":
                    views.append(InputView(item, [], []))
                    continue
                leaks = self._view_leak_check(item.sanitized or "", state, settings, inputs)
                blocked = [
                    span for span in item.spans
                    if span["entity_id"] in state.entities
                    and settings.policies.get(state.entities[span["entity_id"]].type) is Policy.BLOCK
                ]
                views.append(InputView(item, leaks, blocked))
            elif item.source == "local":
                # Локальная модель видела оригиналы: в её ответе нет замен, и «восстанавливать» в нём нечего —
                # настоящий адрес в выданной подсети иначе приняли бы за выведенный (FR-7.6).
                views.append(AnswerView(item, RestoreResult(item.original, [], {})))
            else:
                result = restore(state, item.original, settings)
                result.counters["in_request"] = in_request
                views.append(AnswerView(item, result))
        return ChatView(state, settings, views)

    # --- облачная модель (FR-8) и локальная вместо облачной (FR-9.4) --------------------------

    def _connection(self, chat_id: str) -> tuple[Provider, str]:
        provider_id, model = self.repo.chat_provider(chat_id)
        provider = self.repo.provider(provider_id) if provider_id else None
        if provider is None:
            raise SendRefused("Выберите подключение и модель для этого чата")
        if not provider.enabled:
            raise SendRefused(f"Подключение «{provider.name}» выключено администратором")
        if model not in provider.models:
            raise SendRefused("Этой модели больше нет в подключении: выберите модель заново")
        return provider, model

    def set_provider(self, chat_id: str, provider_id: str | None, model: str) -> None:
        """FR-8.3: подключение и модель чата; None — ручной режим."""
        if provider_id is not None:
            provider = self.repo.provider(provider_id)
            if provider is None or not provider.enabled or model not in provider.models:
                raise SendRefused("Такого подключения или модели нет")
        self.repo.set_chat_provider(chat_id, provider_id, model if provider_id else "")

    def _turns(self, chat_id: str, items: list[Item]) -> tuple[list[Turn], list[int], list[tuple[int, str]]]:
        """Ходы запроса из элементов чата, номера их элементов и то, что в запрос не войдёт, с причиной."""
        on = self._enabled(chat_id)
        turns, seqs, skipped = [], [], []
        for item in items:
            if item.kind == "input":
                if item.status in ("queued", "running"):
                    raise SendRefused(f"Текст {item.seq} ещё обрабатывается: дождитесь очистки")
                if item.status != "done":
                    skipped.append((item.seq, "текст не очищен"))
                    continue
                layers, _ = _cached_layers(item, on)
                role = "system" if item.source == "instruction" else "user"
                turns.append(Turn(role, item.original, layers.cached or ()))
            elif item.source == "local":
                skipped.append((item.seq, "ответ локальной модели: в нём оригиналы"))
                continue
            elif item.meta.get("aborted"):
                # Ответ, оборванный ошибкой провайдера, — не ход диалога: иначе повторить вопрос нельзя (FR-8.9).
                skipped.append((item.seq, "ответ оборван ошибкой провайдера"))
                continue
            elif item.status in ("done", "partial") and item.original:
                turns.append(Turn("assistant", item.original))
            else:
                skipped.append((item.seq, "ответа нет"))
                continue
            seqs.append(item.seq)
        return turns, seqs, skipped

    def _build(self, chat_id: str, state: ChatState, items: list[Item], settings: Settings, provider: Provider, model: str) -> Preview:
        turns, seqs, skipped = self._turns(chat_id, items)
        try:
            outgoing = build_outgoing(state, turns, settings, provider.id, model)
        except NotSendable as exc:
            raise SendRefused(str(exc)) from None
        skipped += [(seqs[number], "ответ до первого вопроса") for number in outgoing.skipped]
        return Preview(outgoing, provider, sorted(skipped))

    def outgoing(self, chat_id: str) -> Preview:
        """Экран подтверждения: запрос, как он уйдёт сейчас. Состояние чата не записывается."""
        provider, model = self._connection(chat_id)
        state, _ = self.repo.load_state(chat_id)
        return self._build(chat_id, state, self.repo.items(chat_id), self.repo.settings(), provider, model)

    def send(self, chat_id: str, user_id: str, digest: str) -> Item:
        """FR-8.4: запрос собирается заново и уходит, только если он совпал с показанным на экране подтверждения."""
        provider, model = self._connection(chat_id)
        built: dict[str, OutgoingContext] = {}
        in_request = 0

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            nonlocal in_request
            if any(i.kind == "answer" and i.source == "api" and i.status in ("queued", "running") for i in items):
                # Двойное нажатие прошло бы проверку отпечатка: идущий ответ в запрос не входит (оплаченный дубль).
                raise SendRefused("Предыдущий ответ облака ещё идёт: дождитесь его или остановите")
            outgoing = self._build(chat_id, state, items, settings, provider, model).outgoing
            if outgoing.context.digest() != digest:
                raise SendRefused("Запрос изменился после показа: проверьте его ещё раз")
            if not outgoing.sendable:
                raise SendRefused("В запросе найден оригинал или фрагмент запрещённого типа: отправка заблокирована")
            built["context"] = outgoing.context
            in_request = _in_request(items)[-1]
            meta = {"provider": provider.name, "model": model}
            return [Item(uuid.uuid4().hex, 0, "answer", "", None, source="api", status="running", meta=meta)], []

        [item] = self._apply(chat_id, work)
        context = built["context"]
        self.repo.audit(
            "cloud_send", user_id, chat_id, provider=provider.id, model=model, messages=len(context.messages),
            chars=sum(len(text) for text in context.texts()),
        )
        self.live.start(item.id)
        self.send_submit(self.run_send, chat_id, item.id, user_id, context, link(provider), in_request)
        return item

    def run_send(
        self, chat_id: str, item_id: str, user_id: str, context: OutgoingContext, connection: cloud.Connection,
        in_request: int,
    ) -> None:
        """Задание: поток ответа — в память для страницы, по окончании — в элемент чата. Обрыв сохраняет полученное.
        in_request — «замен в запросе» (FR-7.5) на момент отправки: для журнала, вместе со счётчиками восстановления."""
        live = self.live.start(item_id)
        outcome: dict = {}
        error, aborted = "", False
        state, settings = None, None
        try:
            state, _ = self.repo.load_state(chat_id)
            settings = self.repo.settings()
            stream = self.cloud_send(
                context, connection, state, settings, cancel=live.cancel, outcome=outcome, on_open=live.on_open,
            )
            for piece in stream:
                live.append(piece)
                if live.size() > self.max_text_chars:
                    live.stop(f"Ответ длиннее {self.max_text_chars} знаков: дальше он не читается")
            if live.cancel.is_set():
                error = live.reason or _STOPPED
            elif outcome.get("truncated"):
                error = "Ответ обрезан пределом длины, заданным в подключении"
        except cloud.LeakDetected as exc:
            error = "В исходящем тексте найден оригинал: запрос не отправлен"
            self.repo.audit("leak", user_id, chat_id, count=exc.count, stage="send")
        except ProviderError as exc:
            error, aborted = str(exc), True
            self.repo.audit("error", user_id, chat_id, kind="ProviderError", stage="send", status=exc.status)
        except Exception as exc:
            if isinstance(exc, KeyError) and self.repo.chat(chat_id) is None:
                self.live.finish(item_id)
                return                                    # чат удалили, пока шёл ответ
            log.error("отправка: %s", type(exc).__name__)
            error = _SEND_INTERNAL
            self.repo.audit("error", user_id, chat_id, kind=type(exc).__name__, stage="send")
        text = live.text()
        status = "done" if not error else "partial" if text else "failed"
        try:
            item = self.repo.item(chat_id, item_id)
            if item is not None:
                meta = {key: value for key, value in item.meta.items() if key not in ("error", "aborted")}
                meta |= ({"error": error} if error else {}) | ({"aborted": True} if aborted and text else {})
                self.repo.finish_answer(chat_id, item_id, text, status, meta)
        except KeyError:
            pass                                          # чат удалили
        finally:
            self.live.finish(item_id)
        if text and state is not None:
            self.repo.audit("restore", user_id, chat_id, **restore(state, text, settings).counters, in_request=in_request)

    def stop(self, chat_id: str, item_id: str) -> None:
        """FR-8.6: генерацию можно остановить; полученная часть сохраняется неполной."""
        item = self.repo.item(chat_id, item_id)
        live = self.live.get(item_id) if item is not None and item.source == "api" else None
        if live is None:
            raise KeyError(item_id)
        live.stop(_STOPPED)

    def stop_chat(self, chat_id: str) -> None:
        """Перед удалением чата: его идущие ответы прерываются, чтобы поток провайдера не читался впустую."""
        for item in self.repo.items(chat_id):
            live = self.live.get(item.id) if item.kind == "answer" and item.source == "api" else None
            if live is not None:
                live.stop("Чат удалён")

    def check_provider(self, provider: Provider, model: str) -> str:
        """FR-8.2: проверочный запрос без данных пользователя. ProviderError — отказ провайдера."""
        context = probe_context(provider.id, model)
        return "".join(self.cloud_send(context, link(provider), None, None))[:500]

    def _local_messages(self, chat_id: str, items: list[Item]) -> list[dict[str, str]]:
        """FR-9.4: локальной модели — оригиналы; ответы облака — восстановленными, локальные — как есть."""
        state, _ = self.repo.load_state(chat_id)
        settings = self.repo.settings()
        system, messages = [], []
        for item in items:
            if item.kind == "input":
                if not item.original:
                    continue
                if item.source == "instruction":
                    system.append(item.original)
                    continue
                role, text = "user", item.original
            elif item.original and item.status in ("done", "partial"):
                text = item.original if item.source == "local" else restore(state, item.original, settings).text
                role = "assistant"
            else:
                continue
            if messages and messages[-1]["role"] == role:
                messages[-1]["content"] += "\n\n" + text
            elif messages or role == "user":
                messages.append({"role": role, "content": text})
        if not messages or messages[-1]["role"] != "user":
            raise SendRefused("Последним в чате должен быть вопрос: вставьте текст")
        return ([{"role": "system", "content": "\n\n".join(system)}] if system else []) + messages

    def ask_local(self, chat_id: str, user_id: str) -> Item:
        """FR-9.4: вопрос локальной модели вместо облачной. Текст не очищается: он не покидает сервер.

        Проверка идущего ответа и запись нового — в одной работе над состоянием (_apply), как у отправки облаку:
        вторая вкладка, записавшая свой ответ между чтением и записью, меняет версию чата, и повтор его видит."""
        if self.engines is None:
            raise SendRefused("Локальная модель не подключена")
        built: dict[str, list[dict[str, str]]] = {}

        def work(state: ChatState, items: list[Item], settings: Settings) -> tuple[list[Item], list[Item]]:
            if local_pending(items):
                # Двойная отправка формы заняла бы оба потока общего пула одной генерацией, а очистка ждала бы.
                raise SendRefused(LOCAL_PENDING)
            built["messages"] = self._local_messages(chat_id, items)
            return [Item(uuid.uuid4().hex, 0, "answer", "", None, source="local", status="queued")], []

        [item] = self._apply(chat_id, work)
        messages = built["messages"]
        self.repo.audit("local_answer", user_id, chat_id, messages=len(messages))
        self.submit(self.run_local, chat_id, item.id, user_id, messages)
        return item

    def run_local(self, chat_id: str, item_id: str, user_id: str, messages: list[dict[str, str]]) -> None:
        try:
            self.repo.set_item_status(chat_id, item_id, "running")
            text, truncated = self.engines.client().answer(messages, max_tokens=LOCAL_ANSWER_TOKENS)
            if truncated:
                self.repo.finish_answer(chat_id, item_id, text, "partial", {"error": "Ответ обрезан пределом длины"})
            else:
                self.repo.finish_answer(chat_id, item_id, text, "done", {})
        except KeyError:
            return                                        # чат удалили, пока ждали модель
        except Exception as exc:
            reason = str(exc) if isinstance(exc, (DetectorError, CompletionError)) else _SEND_INTERNAL
            log.error("ответ локальной модели: %s", type(exc).__name__)
            try:
                self.repo.finish_answer(chat_id, item_id, "", "failed", {"error": reason})
            except KeyError:
                return
            self.repo.audit("error", user_id, chat_id, kind=type(exc).__name__, stage="local_answer")

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
                # Текст, очищенный до слоёв 4 и 5 (этап 1), отметки о них не получает: выключенными они не были (m-12).
                meta = (item.meta | {"layers": ran}) if "layers" in item.meta else item.meta
                if result.sanitized != item.sanitized or meta != item.meta:
                    fresh = replace(
                        item, sanitized=result.sanitized, spans=_spans(result), notices=_notices(result), meta=meta,
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
