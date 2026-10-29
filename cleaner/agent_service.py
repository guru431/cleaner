"""Шлюз для агентов (спецификация 2026-10-28, раздел 8): ключ → чат шлюза → блоки по журналу отправленного или очистка →
провайдер → восстановленный поток → журнал. Протокол — Anthropic Messages, доступ — по подключению Cleaner (план 5Б).

Тело запроса, ответ модели, ключ подключения и ключ Cleaner не попадают ни в журнал событий, ни в сообщения об ошибках
(SEC-11, FR-11.2): туда — идентификаторы, числа и коды."""
from __future__ import annotations

import json
import threading
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from cleaner.clock import Clock
from cleaner.core import pipeline
from cleaner.core.agent import ledger, walk
from cleaner.core.agent.stream import AnthropicStream
from cleaner.core.detect import dictionary
from cleaner.core.detect.base import DetectorError
from cleaner.core.types import ChatState, Policy, Settings
from cleaner.egress import ProviderError, cloud, forward as egress
from cleaner.storage.repo import ApiKey, CheckpointBusy, LedgerEntry, Provider, Repository, StaleState, User

AGENT_CHAT_DAYS = 30            # текущий чат ключа сменяется новым (6.3); постоянные, а не настройки: менять их некому
AGENT_CHAT_ENTITIES = 20_000
LEDGER_DAYS = 30                # разговор без запросов удаляется с журналом (7.3)
ATTEMPTS = 3                    # повторы при правке чата в интерфейсе посреди запроса (8.7)
PROTOCOL = "anthropic"
PRUNE_EVERY = timedelta(hours=1)
STATE_CACHE = 8                 # состояний чатов в памяти (раздел 13: загрузка 20 000 сущностей — 161 мс)
_BODY_BYTES = 32 * 1024 * 1024  # ответ без потока и ошибка провайдера
_RETRY = {"retry-after": "10"}


@dataclass(frozen=True)
class AgentCall:
    key: ApiKey
    user: User
    protocol: str                       # anthropic
    path: str                           # /v1/messages | /v1/messages/count_tokens
    query: str
    headers: Mapping[str, str]
    body: dict


@dataclass
class AgentReply:
    status: int
    headers: dict[str, str]
    body: bytes | None = None
    events: Iterator[bytes] | None = None       # готовые строки SSE «event: …\ndata: …\n\n»


class AgentRefused(Exception):
    """Отказ шлюза в виде ошибки протокола агента; message начинается с «Cleaner:» и не содержит данных запроса."""

    def __init__(self, status: int, kind: str, message: str, headers: dict[str, str] | None = None):
        super().__init__(message)
        self.status, self.kind, self.message, self.headers = status, kind, message, headers or {}


class _LayerDown(Exception):
    """Слой 5 недоступен посреди очистки: запрос не уходит, агент повторит (8.6)."""


class _Checked:
    """Слой 5, сбой которого — отказ 503, а не удержание блока: блок он не испортил, а модель недоступна."""

    def __init__(self, layer: Any):
        self.layer = layer

    def find(self, text: str, sanitized: str, state: ChatState) -> list:
        try:
            return self.layer.find(text, sanitized, state)
        except Exception as exc:
            raise _LayerDown() from exc


@dataclass
class _Prepared:
    """Итог работы под замком чата: что уходит провайдеру и что записать после."""

    secret: bytes
    settings: Settings
    repeated: dict[str, list[str]]      # направление → отпечатки повторённых блоков
    out: pipeline.AgentOutgoing | None = None
    state: ChatState | None = None      # снимок: поток ответа и egress читают его вне замка
    new: int = 0
    withheld: Counter = field(default_factory=Counter)
    replaced: Counter = field(default_factory=Counter)


def _snapshot(state: ChatState) -> ChatState:
    """Состояние для потока ответа и проверки в egress: таблицы — копиями, чтобы следующий запрос того же чата под замком
    не менял их посреди чтения."""
    return replace(
        state, entities=dict(state.entities), surrogates=dict(state.surrogates), issued=dict(state.issued),
        rules=list(state.rules), key_alias=dict(state.key_alias), foreign_labels=set(state.foreign_labels),
        counters=dict(state.counters), net6=dict(state.net6),
    )


def _placeholder(unit: walk.Unit, reason: str) -> object:
    """Пометка удержанного блока того же вида (7.4): у результата инструмента — его содержимым."""
    text = ledger.placeholder(reason)
    if unit.kind == "tool_result":
        return dict(unit.node, content=text)
    if unit.kind == "tool_use":
        return dict(unit.node, input={"cleaner": text})      # вызов остаётся вызовом: на его id ссылается результат
    if unit.kind == "tool_def":
        return dict(unit.node, description=text, input_schema={"type": "object"})
    return {"type": "text", "text": text}


def _json(node: object) -> str:
    return json.dumps(node, ensure_ascii=False, separators=(",", ":"))


def _sse(event: dict) -> bytes:
    return f"event: {event.get('type', 'message')}\ndata: {_json(event)}\n\n".encode("utf-8")


def gateway_access(repo: Repository, provider_id: str, models: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    """Доступ ключа шлюза: включённое подключение с протоколом Anthropic и модели из его списка. ValueError с причиной."""
    provider = repo.provider(provider_id)
    if provider is None or not provider.enabled:
        raise ValueError("подключение не найдено или выключено")
    if provider.protocol != PROTOCOL:
        raise ValueError("шлюз для агентов пока работает только с подключениями по протоколу Anthropic")
    unknown = [model for model in models if model not in provider.models]
    if unknown:
        raise ValueError("таких моделей нет в подключении")
    return f"provider:{provider.id}", tuple(dict.fromkeys(models))


class AgentService:
    def __init__(self, repo: Repository, engines: Any, clock: Clock, forward: Callable[..., egress.Upstream] = egress.forward):
        self.repo = repo
        self.engines = engines          # cleaner.engines.Engines или заглушка тестов; None — без слоёв 4–5
        self.clock = clock
        self.forward = forward
        self._guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._states: OrderedDict[str, tuple[int, ChatState]] = OrderedDict()
        self._pruned: datetime | None = None

    # --- служебное ---------------------------------------------------------------

    def _lock(self, name: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(name, threading.Lock())

    def _now(self) -> datetime:
        return self.clock.now()

    def _prune(self) -> None:
        """Раз в час — разговоры без запросов LEDGER_DAYS дней и осиротевшие чаты шлюза (7.3)."""
        now = self._now()
        with self._guard:
            if self._pruned is not None and now - self._pruned < PRUNE_EVERY:
                return
            self._pruned = now
        try:
            removed = self.repo.prune_agent((now - timedelta(days=LEDGER_DAYS)).isoformat(timespec="seconds"))
        except CheckpointBusy:
            removed = -1
        if removed:
            self.repo.audit("agent_pruned", chats=removed)

    def _load(self, chat_id: str) -> tuple[ChatState, int]:
        """Состояние из памяти, пока версия чата в базе та же, иначе — из базы. Вызывается под замком чата."""
        version = self.repo.chat_version(chat_id)
        with self._guard:
            cached = self._states.get(chat_id)
            if cached is not None and cached[0] == version:
                self._states.move_to_end(chat_id)
                return cached[1], version
        return self.repo.load_state(chat_id)

    def _remember(self, chat_id: str, version: int, state: ChatState | None) -> None:
        with self._guard:
            if state is None:
                self._states.pop(chat_id, None)
                return
            self._states[chat_id] = (version, state)
            self._states.move_to_end(chat_id)
            while len(self._states) > STATE_CACHE:
                self._states.popitem(last=False)

    # --- запрос ------------------------------------------------------------------------

    def _provider(self, call: AgentCall) -> Provider:
        upstream = call.key.upstream
        if not upstream:
            raise AgentRefused(403, "permission_error", "Cleaner: у ключа нет доступа к модели — он только для /api/v1")
        kind, _, provider_id = upstream.partition(":")
        provider = self.repo.provider(provider_id) if kind == "provider" else None
        if provider is None or not provider.enabled:
            raise AgentRefused(400, "invalid_request_error", "Cleaner: подключение ключа удалено или выключено")
        model = call.body.get("model")
        allowed = call.key.models or provider.models
        if allowed and model not in allowed:
            raise AgentRefused(400, "invalid_request_error", "Cleaner: эта модель ключу не разрешена")
        if provider.protocol != PROTOCOL or call.protocol != PROTOCOL:
            raise AgentRefused(400, "invalid_request_error", "Cleaner: протокол агента и подключения не совпадает")
        return provider

    def _layers(self, key: ApiKey) -> pipeline.Layers:
        """Слои 4 и 5 ключа (решение владельца 4): включённый, но недоступный — 503, агент повторит."""
        ner = llm = None
        try:
            if key.layers.get("ner"):
                if self.engines is None:
                    raise DetectorError("слоёв 4–5 в службе нет")
                ner = self.engines.ner()
            if key.layers.get("llm"):
                if self.engines is None:
                    raise DetectorError("слоёв 4–5 в службе нет")
                llm = _Checked(self.engines.llm())
        except DetectorError:
            raise AgentRefused(503, "overloaded_error", "Cleaner: включённый для ключа слой очистки недоступен", _RETRY) from None
        return pipeline.Layers(ner=ner, llm=llm)

    def _chat(self, key: ApiKey, conv_id: str, session: str) -> str:
        """Чат разговора: свой, если разговор уже идёт, иначе текущий чат ключа — или новый, если текущего нет или он
        старше AGENT_CHAT_DAYS (6.3). Под замком ключа: два новых разговора не заводят два чата."""
        conversation = self.repo.conversation(conv_id)
        if conversation is not None:
            return conversation.chat_id
        with self._lock(f"key:{key.id}"):
            current = self.repo.api_key(key.id).chat_id
            chat = self.repo.chat(current) if current else None
            fresh = chat is not None and chat.kind == "agent" and (
                self._now() - datetime.fromisoformat(chat.created_at) < timedelta(days=AGENT_CHAT_DAYS)
            )
            if not fresh:
                title = f"Агент: {key.name}, {self._now().strftime('%d.%m.%Y')}"
                current = self.repo.create_chat(key.user_id, title, kind="agent")
                self.repo.set_key_chat(key.id, current)
                self.repo.audit("agent_chat_created", key.user_id, current, key=key.id)
            return self.repo.add_conversation(conv_id, current, key.id, session).chat_id

    def handle(self, call: AgentCall) -> AgentReply:
        self._prune()
        provider = self._provider(call)
        conv_id = ledger.conversation_id(
            ledger.conversation_secret(self.repo.global_key), call.key.id, walk.first_user(call.body),
        )
        session = str(call.headers.get("x-claude-code-session-id", ""))[:200]
        layers = self._layers(call.key)
        chat_id = self._chat(call.key, conv_id, session)
        settings = self.repo.settings()
        with self._lock(chat_id):
            prepared = self._prepare(call, chat_id, conv_id, provider, settings, layers)
        self.repo.touch_conversation(conv_id, session)
        for direction, digests in prepared.repeated.items():
            if digests:
                self.repo.touch_ledger(chat_id, conv_id, direction, digests)
        if prepared.withheld:
            self.repo.audit("agent_withheld", call.user.id, chat_id, key=call.key.id, reasons=dict(prepared.withheld))
        return self._send(call, chat_id, conv_id, provider, prepared)

    def _prepare(
        self, call: AgentCall, chat_id: str, conv_id: str, provider: Provider, settings: Settings, layers: pipeline.Layers,
    ) -> _Prepared:
        """Шаги 5–7 раздела 8 под замком чата; StaleState — повтор до ATTEMPTS раз."""
        for _ in range(ATTEMPTS):
            state, version = self._load(chat_id)
            try:
                prepared, entries = self._clean(call, chat_id, conv_id, provider, state, settings, layers)
            except _LayerDown:
                self._remember(chat_id, version, None)
                raise AgentRefused(503, "overloaded_error", "Cleaner: локальная модель недоступна", _RETRY) from None
            except BaseException:
                self._remember(chat_id, version, None)          # состояние могло измениться наполовину
                raise
            if not entries:
                self._remember(chat_id, version, state)         # всё из журнала: состояние не менялось
                return prepared
            try:
                self.repo.commit_chat(chat_id, state, version, ledger=entries)
            except StaleState:
                self._remember(chat_id, version, None)
                continue
            self._remember(chat_id, version + 1, state)
            if len(state.entities) >= AGENT_CHAT_ENTITIES and self.repo.api_key(call.key.id).chat_id == chat_id:
                self.repo.set_key_chat(call.key.id, None)       # новые разговоры — в новый чат (6.3)
            return prepared
        raise AgentRefused(503, "overloaded_error", "Cleaner: чат шлюза меняют в интерфейсе, повторите запрос", _RETRY)

    def _clean(
        self, call: AgentCall, chat_id: str, conv_id: str, provider: Provider, state: ChatState, settings: Settings,
        layers: pipeline.Layers,
    ) -> tuple[_Prepared, list[LedgerEntry]]:
        secret = self.repo.chat_secret(chat_id)
        units = walk.anthropic_units(call.body)
        digests = {unit.path: ledger.block_digest(secret, PROTOCOL, unit.role, unit.kind, unit.node) for unit in units}
        groups: dict[str, list[walk.Unit]] = {"in": [], "out": []}
        for unit in units:
            if unit.kind != "opaque":       # рассуждения и блоки провайдера — как есть (7.2.3)
                groups["out" if unit.role == "assistant" and unit.kind in ("text", "tool_use") else "in"].append(unit)
        known = {
            direction: self.repo.ledger_get(chat_id, conv_id, direction, [digests[u.path] for u in group])
            for direction, group in groups.items()
        }
        replaced: dict[walk.Path, object] = {}
        entries: list[LedgerEntry] = []
        structural = walk.structural(call.body)
        checked = list(structural)
        result = _Prepared(secret=secret, settings=settings, repeated={"in": [], "out": []})
        for direction, group in groups.items():
            for unit in group:
                digest = digests[unit.path]
                entry = known[direction].get(digest)
                if entry is not None:
                    replaced[unit.path] = json.loads(entry.wire)
                    result.repeated[direction].append(digest)
                    continue
                node, withheld, counts = self._new(unit, direction, state, settings, layers)
                replaced[unit.path] = node
                checked += walk.strings_of(node)
                entries.append(LedgerEntry(conv_id, direction, digest, _json(unit.node), _json(node), withheld, counts))
                result.new += 1
                result.replaced.update(counts)
                if withheld:
                    result.withheld[withheld] += 1
        body = walk.rebuild(call.body, replaced)
        instruction = pipeline.system_prompt(state.label_style)
        system = body.get("system")
        if isinstance(system, list):
            body["system"] = [*system, {"type": "text", "text": instruction}]
        else:
            body["system"] = f"{system}\n\n{instruction}" if system else instruction
        out, leaks = pipeline.build_agent_outgoing(
            state, settings, chat_id=chat_id, provider_id=provider.id, path=call.path, query=call.query,
            headers=call.headers, body=body, checked=checked,
        )
        if leaks:
            in_service = bool(pipeline.checked_leaks(structural, state, settings))
            self.repo.audit(
                "agent_refused", call.user.id, chat_id, key=call.key.id,
                reason="leak_structural" if in_service else "leak", count=len(leaks),
            )
            where = "в служебном поле запроса (имя инструмента, metadata, модель)" if in_service else "в исходящем тексте"
            raise AgentRefused(
                400, "invalid_request_error",
                f"Cleaner: {where} найдено известное значение ({len(leaks)}), запрос не отправлен",
            )
        result.out, result.state = out, _snapshot(state)
        return result, entries

    def _new(
        self, unit: walk.Unit, direction: str, state: ChatState, settings: Settings, layers: pipeline.Layers,
    ) -> tuple[object, str, dict[str, int]]:
        """Новый блок: очищенный узел, причина удержания ("" — нет) и замены по типам. Блок агента — слоями ключа; блок
        модели, которого нет в журнале, — как ответ модели в чате: известные значения, словарь и правила (FR-8.11)."""
        if unit.kind == "media":
            return _placeholder(unit, ledger.REASONS["media"]), "media", {}
        blocked: list[str] = []
        counts: Counter = Counter()

        def clean(text: str) -> str:
            if direction == "out":
                found = pipeline.sanitize(state, text, settings, detectors=(dictionary,))
            else:
                found = pipeline.sanitize(state, text, settings, layers)
                # Замена сущности с «блокировать», вставленная агентом, держит блок, как оригинал (FR-4.2).
                blocked.extend(
                    type_.value for notice in found.blocked_surrogates for type_ in notice.held
                    if settings.policies.get(type_) is Policy.BLOCK
                )
            blocked.extend(state.entities[span.entity_id].type.value for span in found.blocked)
            counts.update(state.entities[span.entity_id].type.value for span in found.spans)
            return found.sanitized

        try:
            node = walk.sanitize_unit(unit, clean)
        except _LayerDown:
            raise
        except Exception:
            return _placeholder(unit, ledger.REASONS["failed"]), "failed", {}
        if blocked:
            return _placeholder(unit, ledger.REASONS["blocked"].format(type=blocked[0])), "blocked", {}
        if walk.contains_media(unit):
            return node, "media", dict(counts)
        return node, "", dict(counts)

    # --- отправка и ответ ---------------------------------------------------------------

    def _send(self, call: AgentCall, chat_id: str, conv_id: str, provider: Provider, prepared: _Prepared) -> AgentReply:
        connection = cloud.Connection(
            provider.protocol, provider.base_url, provider.auth_style, provider.api_key, provider.max_tokens,
            provider.extra_body,
        )
        audit = {
            "key": call.key.id, "model": str(call.body.get("model", ""))[:100], "blocks_new": prepared.new,
            "blocks_repeated": sum(len(d) for d in prepared.repeated.values()), "withheld": sum(prepared.withheld.values()),
            "replaced": dict(prepared.replaced),
        }
        try:
            upstream = self.forward(prepared.out, connection, prepared.state, prepared.settings)
        except cloud.LeakDetected as exc:
            self.repo.audit("agent_refused", call.user.id, chat_id, key=call.key.id, reason="leak_egress", count=exc.count)
            raise AgentRefused(
                400, "invalid_request_error",
                f"Cleaner: в исходящем тексте найдено известное значение ({exc.count}), запрос не отправлен",
            ) from None
        except egress.ProviderTimeout:
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=504)
            raise AgentRefused(504, "api_error", "Cleaner: провайдер не ответил вовремя") from None
        except (ProviderError, ValueError):
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=502)
            raise AgentRefused(502, "api_error", "Cleaner: провайдер недоступен") from None
        if upstream.status >= 300 or call.path.endswith("/count_tokens"):
            try:
                raw = upstream.read(_BODY_BYTES)
            finally:
                upstream.close()
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=upstream.status)
            return AgentReply(upstream.status, dict(upstream.headers), body=raw)
        stream = AnthropicStream(prepared.state, prepared.settings)
        if not call.body.get("stream"):
            try:
                raw = upstream.read(_BODY_BYTES)
            finally:
                upstream.close()
            try:
                message = stream.complete(json.loads(raw))
            except (ValueError, AttributeError):
                self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=502)
                raise AgentRefused(502, "api_error", "Cleaner: провайдер прислал не JSON") from None
            self._record(chat_id, conv_id, prepared, stream)
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=upstream.status)
            return AgentReply(upstream.status, {"content-type": "application/json"}, body=_json(message).encode("utf-8"))
        headers = {"content-type": "text/event-stream", "cache-control": "no-cache"}
        if "request-id" in upstream.headers:
            headers["request-id"] = upstream.headers["request-id"]
        return AgentReply(200, headers, events=self._events(call, chat_id, conv_id, prepared, upstream, stream, audit))

    def _record(self, chat_id: str, conv_id: str, prepared: _Prepared, stream: AnthropicStream) -> None:
        """Пары «отдано агенту — пришло от модели» — журнал out (7.2.2), своей транзакцией."""
        entries = [
            LedgerEntry(
                conv_id, "out", ledger.block_digest(prepared.secret, PROTOCOL, "assistant", local["type"], local),
                _json(local), _json(wire),
            )
            for local, wire in stream.pairs
        ]
        if entries:
            self.repo.add_ledger(chat_id, entries)

    def _events(
        self, call: AgentCall, chat_id: str, conv_id: str, prepared: _Prepared, upstream: egress.Upstream,
        stream: AnthropicStream, audit: dict,
    ) -> Iterator[bytes]:
        """События агенту по мере прихода; обрыв — уже восстановленная часть и событие error (раздел 12)."""
        finished = failed = False
        try:
            for line in upstream.lines():
                if not line.startswith("data:"):
                    continue
                try:
                    event = json.loads(line[5:])
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                finished = finished or event.get("type") == "message_stop"
                failed = failed or event.get("type") == "error"
                for out in stream.feed(event):
                    yield _sse(out)
        except ProviderError:
            pass
        finally:
            upstream.close()
            self._record(chat_id, conv_id, prepared, stream)
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=200, finished=finished)
        if not finished:
            for out in stream.cut():
                yield _sse(out)
            if not failed:
                yield _sse({"type": "error", "error": {"type": "api_error", "message": "Cleaner: поток ответа провайдера оборвался"}})
