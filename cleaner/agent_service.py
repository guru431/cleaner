"""Шлюз для агентов (спецификация 2026-10-28, раздел 8): ключ → чат шлюза → блоки по журналу отправленного или очистка →
провайдер → восстановленный поток → журнал. Всё, что зависит от протокола агента, — объект протокола
(core/agent/protocol.py); доступ — по подключению Cleaner.

Тело запроса, ответ модели, ключ подключения и ключ Cleaner не попадают ни в журнал событий, ни в сообщения об ошибках
(SEC-11, FR-11.2): туда — идентификаторы, числа и коды."""
from __future__ import annotations

import json
import re
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from cleaner.clock import Clock
from cleaner.core import pipeline
from cleaner.core.agent import ledger, walk
from cleaner.core.agent.protocol import PROTOCOLS, GatewayProtocol, ProtocolStream
from cleaner.core.detect import dictionary
from cleaner.core.detect.base import DetectorError
from cleaner.core.restore import RestoreLimit, SecretGuard
from cleaner.core.types import ChatState, Entity, Policy, Settings
from cleaner.egress import ProviderError, cloud, forward as egress
from cleaner.storage.repo import ApiKey, CheckpointBusy, LedgerEntry, Repository, StaleState, User

AGENT_CHAT_DAYS = 30            # текущий чат ключа сменяется новым (6.3); постоянные, а не настройки: менять их некому
AGENT_CHAT_ENTITIES = 20_000
LEDGER_DAYS = 30                # разговор без запросов удаляется с журналом (7.3)
ATTEMPTS = 3                    # повторы при правке чата в интерфейсе посреди запроса (8.7)
PRUNE_EVERY = timedelta(hours=1)
STATE_CACHE = 8                 # состояний чатов в памяти (раздел 13: загрузка 20 000 сущностей — 161 мс)
_BODY_BYTES = 32 * 1024 * 1024  # ответ без потока и ошибка провайдера
_RETRY = {"retry-after": "10"}
_CLEANER_KEY = "ck_"            # начало ключа доступа (web.auth.API_KEY_PREFIX)
# Доступ по подписке (9.4): протокол и адрес закреплены в коде — ключ Cleaner, попавший к постороннему, не направит
# чужой токен на произвольный адрес. Настройки, переменной окружения и поля базы для них нет.
SUBSCRIPTIONS = {
    "claude-subscription": ("anthropic", "https://api.anthropic.com"),
    "chatgpt-subscription": ("responses", "https://chatgpt.com/backend-api/codex"),
}


@dataclass(frozen=True)
class AgentCall:
    key: ApiKey
    user: User
    protocol: str                       # ключ PROTOCOLS: anthropic | chat | responses
    path: str                           # путь у провайдера: /v1/messages, /chat/completions, /responses…
    query: str
    headers: Mapping[str, str] = field(repr=False)       # бывает токен подписки агента (SEC-18)
    body: dict = field(repr=False)


@dataclass(frozen=True)
class _Access:
    """Куда и с чем уходит запрос: подключение Cleaner или подписка агента."""

    id: str                             # id подключения или вид подписки
    connection: cloud.Connection
    headers: frozenset[str]             # заголовки агента к провайдеру


@dataclass
class AgentReply:
    status: int
    headers: dict[str, str]
    body: bytes | None = None
    events: Iterator[bytes] | None = None       # готовые строки SSE «event: …\ndata: …\n\n»
    stop: Callable[[], None] | None = None      # агент ушёл: оборвать ожидание провайдера (из другого потока)
    # Закрыть поток, начат он или нет: ответ провайдера, журнал out, agent_send — один раз. Не во время чужого next.
    close: Callable[[], None] | None = None


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
    blocks: list[dict] = field(default_factory=list)
    guard: SecretGuard | None = None    # секреты в адресах чужих узлов в аргументах ответа (настройка ключа)
    unfamiliar: list[str] = field(default_factory=list)     # формы незнакомых полей и блоков: пути и type, без данных
    model_blocks: int = 0               # блоков модели в истории запроса
    model_fresh: int = 0                # из них не найдено в журнале out


# Имя поля или значение type, которое можно показать в квитанции: имя протокола, а не данные пользователя.
_SHAPE_NAME = re.compile(r"[A-Za-z_$][\w.$-]{0,63}")


def _shape(unit: walk.Unit) -> str:
    """Форма незнакомого поля или блока (8.3) для квитанции: путь в теле с [] вместо номеров и значение type. Имя, не
    похожее на имя поля протокола (ключ — значение пользователя), — «?»."""
    path = "".join(
        "[]" if isinstance(step, int) else ("." if i else "") + (step if _SHAPE_NAME.fullmatch(step) else "?")
        for i, step in enumerate(unit.path)
    )
    type_ = unit.node.get("type") if isinstance(unit.node, dict) else None
    return f"{path} type={type_}" if isinstance(type_, str) and _SHAPE_NAME.fullmatch(type_) else path


def _snapshot(state: ChatState) -> ChatState:
    """Состояние для потока ответа и проверки в egress: таблицы — копиями, чтобы следующий запрос того же чата под замком
    не менял их посреди чтения."""
    return replace(
        state, entities={key: Entity(entity.id, entity.type, entity.number, entity.key, entity.restore_value, entity.origin,
                                     entity.forms.copy(), entity.parts.copy(), entity.words.copy(), entity.restore_rank)
                         for key, entity in state.entities.items()},
        surrogates=dict(state.surrogates), issued=dict(state.issued),
        rules=list(state.rules), key_alias=dict(state.key_alias), foreign_labels=set(state.foreign_labels),
        counters=dict(state.counters), net6=dict(state.net6),
    )


def _json(node: object) -> str:
    return json.dumps(node, ensure_ascii=False, separators=(",", ":"))


def _digest(secret: bytes, proto: GatewayProtocol, role: str, kind: str, node: object) -> str:
    """Отпечаток блока в журнале — по узлу, сведённому протоколом (ledger_node): так его ищут и так записывают."""
    return ledger.block_digest(secret, proto.name, role, kind, proto.ledger_node(role, kind, node))


def _ms(since: float) -> int:
    """Миллисекунды от since по time.perf_counter — длительность, а не время суток (AC-5.7)."""
    return int((time.perf_counter() - since) * 1000)


GATEWAY_PROTOCOLS = frozenset(proto.provider_protocol for proto in PROTOCOLS.values())   # протоколы подключений шлюза


def gateway_access(
    repo: Repository, access: str, models: tuple[str, ...], *, admin: bool,
) -> tuple[str, tuple[str, ...]]:
    """Доступ ключа шлюза: включённое подключение с протоколом, на котором говорит шлюз, и модели из его списка, или
    подписка — только у администратора (SEC-20), модели любые (пусто — все). ValueError с причиной."""
    if access in SUBSCRIPTIONS:
        if not admin:
            raise ValueError("доступ по подписке — только у администратора")
        return access, tuple(dict.fromkeys(model for model in models if model))
    provider = repo.provider(access)
    if provider is None or not provider.enabled:
        raise ValueError("подключение не найдено или выключено")
    if provider.protocol not in GATEWAY_PROTOCOLS:
        raise ValueError("шлюз для агентов не работает с протоколом этого подключения")
    unknown = [model for model in models if model not in provider.models]
    if unknown:
        raise ValueError("таких моделей нет в подключении")
    return f"provider:{provider.id}", tuple(dict.fromkeys(models))


class AgentService:
    def __init__(
        self, repo: Repository, engines: Any, clock: Clock, forward: Callable[..., egress.Upstream] = egress.forward,
        subscription_urls: Mapping[str, str] | None = None,
    ):
        self.repo = repo
        self.engines = engines          # cleaner.engines.Engines или заглушка тестов; None — без слоёв 4–5
        self.clock = clock
        self.forward = forward
        # Только для тестов: заглушка вместо закреплённых адресов подписок.
        self.subscription_urls = {access: url for access, (_, url) in SUBSCRIPTIONS.items()} | dict(subscription_urls or {})
        self._guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._states: OrderedDict[str, tuple[int, ChatState]] = OrderedDict()
        repo.on_chat_deleted(self.forget_chat)
        self._pruned: datetime | None = None

    # --- служебное ---------------------------------------------------------------

    def forget_chat(self, chat_id: str) -> None:
        self._remember(chat_id, 0, None)

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

    def _refuse(
        self, call: AgentCall, status: int, kind: str, message: str, reason: str, headers: dict | None = None,
        *, chat_id: str | None = None,
    ) -> AgentRefused:
        """Отказ шлюза — событие agent_refused с причиной (раздел 12): пользователь, чат, если уже известен, id ключа."""
        self.repo.audit("agent_refused", call.user.id, chat_id, key=call.key.id, reason=reason)
        refused = AgentRefused(status, kind, message, headers)
        refused.reason = reason
        return refused

    # --- запрос ------------------------------------------------------------------------

    def _subscription(self, call: AgentCall, proto: GatewayProtocol, access: str) -> _Access:
        """Подписка (9.4): роль администратора — на момент запроса (SEC-20); вход агента — его Authorization, к провайдеру
        уходит он, а не ключ подключения."""
        if call.user.role != "admin":
            raise self._refuse(
                call, 403, "permission_error", "Cleaner: доступ по подписке — только у администратора", "subscription_role",
            )
        if proto.name != SUBSCRIPTIONS[access][0]:
            raise self._refuse(call, 400, "invalid_request_error", "Cleaner: протокол агента и подписки не совпадает", "protocol")
        login = str(call.headers.get("authorization", "")).partition(" ")[2].strip()
        if not login or login.startswith(_CLEANER_KEY):         # ключ Cleaner на месте входа ушёл бы провайдеру
            raise self._refuse(call, 401, "authentication_error", "Cleaner: агент не прислал вход подписки", "subscription_login")
        if call.key.models and call.body.get("model") not in call.key.models:
            raise self._refuse(call, 400, "invalid_request_error", "Cleaner: эта модель ключу не разрешена", "model")
        connection = cloud.Connection(proto.provider_protocol, self.subscription_urls[access], "passthrough", "", 0)
        return _Access(access, connection, proto.headers | proto.subscription_headers)

    def _access(self, call: AgentCall, proto: GatewayProtocol) -> _Access:
        upstream = call.key.upstream
        if not upstream:
            raise self._refuse(
                call, 403, "permission_error", "Cleaner: у ключа нет доступа к модели — он только для /api/v1", "no_upstream",
            )
        if upstream in SUBSCRIPTIONS:
            return self._subscription(call, proto, upstream)
        kind, _, provider_id = upstream.partition(":")
        provider = self.repo.provider(provider_id) if kind == "provider" else None
        if provider is None or not provider.enabled:
            raise self._refuse(
                call, 400, "invalid_request_error", "Cleaner: подключение ключа удалено или выключено", "connection_gone",
            )
        model = call.body.get("model")
        allowed = provider.allowed_models(call.key.models)
        if model not in allowed:
            raise self._refuse(call, 400, "invalid_request_error", "Cleaner: эта модель ключу не разрешена", "model")
        if provider.protocol != proto.provider_protocol:
            raise self._refuse(
                call, 400, "invalid_request_error", "Cleaner: протокол агента и подключения не совпадает", "protocol",
            )
        connection = cloud.Connection(
            provider.protocol, provider.base_url, provider.auth_style, provider.api_key, provider.max_tokens,
            provider.extra_body,
        )
        return _Access(provider.id, connection, proto.headers)     # Authorization и x-api-key агента не уходят никогда

    def _layers(self, call: AgentCall) -> pipeline.Layers:
        """Слои 4 и 5 ключа (решение владельца 4): включённый, но недоступный — 503, агент повторит."""
        key = call.key
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
            raise self._refuse(
                call, 503, "overloaded_error", "Cleaner: включённый для ключа слой очистки недоступен", "layer_down", _RETRY,
            ) from None
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
        started = time.perf_counter()
        self._prune()
        proto = PROTOCOLS[call.protocol]
        access = self._access(call, proto)
        identity = call.headers.get("x-cleaner-conversation-id", "") or (
            call.headers.get("thread-id", "") if proto.name == "responses" else ""
        ) or call.headers.get(proto.session_header, "")
        if not isinstance(identity, str) or len(identity) > 1024:
            raise self._refuse(call, 400, "invalid_request_error", "Cleaner: неверный идентификатор разговора", "session")
        if identity and proto.name == "anthropic":
            identity = _json([identity, call.headers.get("x-claude-code-agent-id", ""), call.headers.get("x-claude-code-parent-agent-id", "")])
        conv_id = ledger.conversation_id(
            ledger.conversation_secret(self.repo.global_key), call.key.id, proto.first_user(call.body),
            session=identity, epoch=self.repo.api_key(call.key.id).agent_epoch,
        )
        # Upgrade compatibility: versions through 31.10 ignored session ids in the digest but retained the first
        # supplied id in the conversation row. Adopt that history only when its actual client id matches; a new
        # session with an identical first message must never inherit it. Explicit Cleaner ids always start a namespace.
        legacy_safe = not (proto.name == "anthropic" and call.headers.get("x-claude-code-agent-id"))
        if identity and legacy_safe and not call.headers.get("x-cleaner-conversation-id") and self.repo.conversation(conv_id) is None:
            legacy_id = ledger.conversation_id(ledger.conversation_secret(self.repo.global_key), call.key.id, proto.first_user(call.body))
            legacy = self.repo.conversation(legacy_id)
            client_ids = {call.headers.get(proto.session_header, ""), call.headers.get("thread-id", "")}
            if legacy is not None and legacy.session and legacy.session in client_ids:
                conv_id = legacy_id
        session = f"session:{conv_id[:12]}" if identity else ""
        layers = self._layers(call)
        chat_id = self._chat(call.key, conv_id, session)
        settings = self.repo.settings()
        prepared = None
        try:
            with self._lock(chat_id):
                prepared = self._prepare(call, proto, chat_id, conv_id, access, settings, layers)
            return self._dispatch(call, proto, chat_id, conv_id, access, prepared, started)
        except AgentRefused as exc:
            self._receipt(call, proto, chat_id, conv_id, access, prepared, started, exc.status, getattr(exc, "reason", exc.kind))
            raise

    def _dispatch(
        self, call: AgentCall, proto: GatewayProtocol, chat_id: str, conv_id: str, access: _Access,
        prepared: _Prepared, started: float,
    ) -> AgentReply:
        self.repo.touch_conversation(conv_id, "")
        for direction, digests in prepared.repeated.items():
            if digests:
                self.repo.touch_ledger(chat_id, conv_id, direction, digests)
        if prepared.withheld:
            self.repo.audit("agent_withheld", call.user.id, chat_id, key=call.key.id, reasons=dict(prepared.withheld))
        reply = self._send(call, proto, chat_id, conv_id, access, prepared, started)
        if reply.events is None:
            self._receipt(call, proto, chat_id, conv_id, access, prepared, started, reply.status)
        return reply

    def _receipt(
        self, call: AgentCall, proto: GatewayProtocol, chat_id: str, conv_id: str, access: _Access,
        prepared: _Prepared | None, started: float, status: int, reason: str = "",
    ) -> None:
        """Whole-request boundary, under the chat key; credential values and arbitrary header/query values are absent."""
        out = prepared.out if prepared else None
        self.repo.add_agent_receipt(chat_id, conv_id, {
            "protocol": proto.name, "access": access.id, "model": str(call.body.get("model", ""))[:100],
            "status": status, "reason": reason, "ms_total": _ms(started),
            "layers": [1, 2, 3] + ([4] if call.key.layers.get("ner") else []) + ([5] if call.key.layers.get("llm") else []),
            "new": prepared.new if prepared else 0,
            "repeated": sum(map(len, prepared.repeated.values())) if prepared else 0,
            "withheld": dict(prepared.withheld) if prepared else {}, "blocks": prepared.blocks if prepared else [],
            # Секреты и учётные записи, оставленные заменой в адресах чужих узлов в аргументах инструментов.
            "held_secrets": prepared.guard.held if prepared and prepared.guard else 0,
            # Новые формы запросов агента (риск 7): незнакомые поля и блоки, блоки модели вне журнала out.
            "unfamiliar": prepared.unfamiliar if prepared else [],
            "model_blocks": prepared.model_blocks if prepared else 0,
            "model_fresh": prepared.model_fresh if prepared else 0,
            "channels": ["JSON: новые значения и ключи объектов", "JSON: служебные параметры", "URL: разобранные параметры", "HTTP: разрешённые заголовки"],
            "headers": sorted(name for name, _ in out.headers) if out else [],
            "parameters": ["beta"] if out and out.query else [],
            "credential_channel": "Authorization подписки" if call.key.upstream in SUBSCRIPTIONS else "ключ подключения",
        })

    def _prepare(
        self, call: AgentCall, proto: GatewayProtocol, chat_id: str, conv_id: str, access: _Access, settings: Settings,
        layers: pipeline.Layers,
    ) -> _Prepared:
        """Шаги 5–7 раздела 8 под замком чата; StaleState — повтор до ATTEMPTS раз."""
        for _ in range(ATTEMPTS):
            state, version = self._load(chat_id)
            try:
                prepared, entries = self._clean(call, proto, chat_id, conv_id, access, state, settings, layers)
            except _LayerDown:
                self._remember(chat_id, version, None)
                raise self._refuse(
                    call, 503, "overloaded_error", "Cleaner: локальная модель недоступна", "layer_down", _RETRY, chat_id=chat_id,
                ) from None
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
        raise self._refuse(
            call, 503, "overloaded_error", "Cleaner: чат шлюза меняют в интерфейсе, повторите запрос", "busy", _RETRY,
            chat_id=chat_id,
        )

    def _clean(
        self, call: AgentCall, proto: GatewayProtocol, chat_id: str, conv_id: str, access: _Access, state: ChatState,
        settings: Settings, layers: pipeline.Layers,
    ) -> tuple[_Prepared, list[LedgerEntry]]:
        secret = self.repo.chat_secret(chat_id)
        from cleaner.core.agent import coverage
        try:
            coverage.validate(call.body)
        except ValueError:
            raise self._refuse(call, 400, "invalid_request_error", "Cleaner: неверный cache_control", "cache_control", chat_id=chat_id) from None
        units = proto.units(call.body)
        digests = {unit.path: _digest(secret, proto, unit.role, unit.kind, unit.node) for unit in units}
        # Записи до сведения узлов (ledger_node) — под прежним отпечатком: разговор, начатый до него, повторяется дословно.
        legacy = {
            unit.path: digest for unit in units
            if (digest := ledger.block_digest(secret, proto.name, unit.role, unit.kind, unit.node)) != digests[unit.path]
        }
        groups: dict[str, list[walk.Unit]] = {"in": [], "out": []}
        for unit in units:
            try:
                coverage.validate_opaque(unit)
            except ValueError:
                raise self._refuse(call, 400, "invalid_request_error", "Cleaner: неверный непрозрачный блок", "opaque", chat_id=chat_id) from None
            groups["out" if proto.is_model_block(unit) or unit.kind == "opaque" and unit.role == "assistant" else "in"].append(unit)
        known = {
            direction: self.repo.ledger_get(
                chat_id, conv_id, direction, [digests[u.path] for u in group] + [legacy[u.path] for u in group if u.path in legacy],
            )
            for direction, group in groups.items()
        }
        repeated: dict[walk.Path, object] = {}
        fresh: list[tuple[str, walk.Unit]] = []
        structural = proto.structural(call.body)
        # Заголовок сессии провайдера (OpenCode Go) — из отпечатка разговора; присланный агентом заменяется.
        session = cloud.session_headers(access.connection.base_url, conv_id)
        result = _Prepared(secret=secret, settings=settings, repeated={"in": [], "out": []})
        for direction, group in groups.items():
            for unit in group:
                digest = digests[unit.path]
                entry = known[direction].get(digest)
                if entry is None and unit.path in legacy:
                    digest = legacy[unit.path]
                    entry = known[direction].get(digest)
                if entry is not None:
                    repeated[unit.path] = json.loads(entry.wire)
                    result.repeated[direction].append(digest)
                else:
                    fresh.append((direction, unit))
        # Блоки очищаются по одному: значение, найденное в позднем блоке (учётная запись из пути профиля в описании
        # инструмента), в раннем осталось бы открытым, и проверка отказывала бы запросу при каждом повторе агента.
        # Второй проход очищает новые блоки с уже полным состоянием чата.
        for _ in range(2):
            replaced, checked, entries = dict(repeated), list(structural), []
            result.new, result.replaced, result.withheld = 0, Counter(), Counter()
            for direction, unit in fresh:
                node, withheld, counts = self._new(proto, unit, direction, state, settings, layers)
                replaced[unit.path] = node
                # Opaque Responses items may contain a separately cleaned summary. Inspect their final
                # rebuilt representation in coverage.checked, after all child replacements are applied.
                if unit.kind != "opaque":
                    checked += walk.checked_strings(unit.kind, node)
                # The unfamiliar envelope name is outside unit.node. Check it for new units, while a frozen
                # unit (including its original field name) retains the conversation's existing exception.
                if unit.kind == "other" and isinstance(unit.path[-1], str):
                    checked.append(unit.path[-1])
                entries.append(LedgerEntry(
                    conv_id, direction, digests[unit.path], _json(unit.node), _json(node), withheld, counts,
                ))
                result.new += 1
                result.replaced.update(counts)
                if withheld:
                    result.withheld[withheld] += 1
            body = proto.rebuild(call.body, replaced)
            frozen = [coverage.identity(unit) for unit in proto.units(body) if unit.path in repeated]
            instruction = pipeline.system_prompt(state.label_style)
            body = proto.add_instruction(body, instruction)
            for unit in proto.units(body):
                if unit.kind == "text" and isinstance(unit.node, dict) and unit.node.get("text") == instruction:
                    frozen.append(coverage.identity(unit))
                elif proto.name == "anthropic" and unit.path == ("system",) and unit.path in repeated:
                    frozen.append(coverage.identity(unit))
            try:
                out, leaks = pipeline.build_agent_outgoing(
                    state, settings, chat_id=chat_id, provider_id=access.id, path=call.path, query=call.query,
                    headers={**call.headers, **session}, allowed=access.headers | session.keys(), prefixes=proto.header_prefixes,
                    body=body, checked=checked, protocol=proto.name, frozen=tuple(frozen),
                )
            except ValueError:
                raise self._refuse(call, 400, "invalid_request_error", "Cleaner: неподдерживаемые параметры URL", "query", chat_id=chat_id) from None
            if not leaks:
                break
        if leaks:
            in_service = bool(pipeline.checked_leaks(structural, state, settings))
            self.repo.audit(
                "agent_refused", call.user.id, chat_id, key=call.key.id,
                reason="leak_structural" if in_service else "leak", count=len(leaks),
            )
            where = "в служебном поле запроса (имя инструмента, metadata, модель)" if in_service else "в исходящем тексте"
            refused = AgentRefused(
                400, "invalid_request_error",
                f"Cleaner: {where} найдено известное значение ({len(leaks)}), запрос не отправлен",
            )
            refused.reason = "leak_structural" if in_service else "leak"
            raise refused
        result.out, result.state = out, _snapshot(state)
        result.unfamiliar = sorted({_shape(unit) for unit in units if unit.kind == "other"})
        result.model_blocks = len(groups["out"])
        result.model_fresh = sum(1 for direction, _ in fresh if direction == "out")
        held = {entry.digest for entry in entries if entry.withheld}
        result.blocks = [
            {"direction": direction, "digest": digests[unit.path], "kind": unit.kind,
             "status": "повторён" if unit.path in repeated else "удержан" if digests[unit.path] in held else "новый"}
            for direction, group in groups.items() for unit in group
        ]
        return result, entries

    def _new(
        self, proto: GatewayProtocol, unit: walk.Unit, direction: str, state: ChatState, settings: Settings,
        layers: pipeline.Layers,
    ) -> tuple[object, str, dict[str, int]]:
        """Новый блок: очищенный узел, причина удержания ("" — нет) и замены по типам. Блок агента — слоями ключа; блок
        модели, которого нет в журнале, — слоями 1–3. Известных значений и словаря ему мало: агент держит его с
        оригиналами, которые восстановление вывело само (FR-7.6: адрес в фиктивной подсети, имя в фиктивном домене), —
        сущностями чата они не стали, а после истечения журнала или «Начать заново» и чат новый. Слои 4–5 не нужны:
        это текст модели, а не пользователя, и ждать локальную модель на каждом сжатии истории агента незачем.
        Неподписанные рассуждения агент получает как пришли, без восстановления (7.2.3): выведенных оригиналов в них
        нет — по-прежнему известные значения и словарь."""
        if unit.kind == "media":
            return proto.placeholder(unit, ledger.REASONS["media"]), "media", {}
        nested = False
        if unit.kind not in ("opaque", "reasoning"):
            # Изображение или файл глубже известных мест (блок незнакомого вида, computer_call_output) — тоже пометкой.
            node, nested = walk.hold_media(unit.node, "input_text" if proto.name == "responses" else "text")
            if nested:
                unit = replace(unit, node=node)
        blocked: list[str] = []
        counts: Counter = Counter()
        detectors = (dictionary,) if unit.kind == "reasoning" else pipeline.DETECTORS

        def clean(text: str) -> str:
            if direction == "out":
                found = pipeline.sanitize(state, text, settings, detectors=detectors)
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
            node = proto.sanitize_unit(unit, clean)
        except _LayerDown:
            raise
        except Exception:
            return proto.placeholder(unit, ledger.REASONS["failed"]), "failed", {}
        if blocked:
            return proto.placeholder(unit, ledger.REASONS["blocked"].format(type=blocked[0])), "blocked", {}
        if nested or proto.contains_media(unit):
            return node, "media", dict(counts)
        return node, "", dict(counts)

    # --- отправка и ответ ---------------------------------------------------------------

    def _send(
        self, call: AgentCall, proto: GatewayProtocol, chat_id: str, conv_id: str, access: _Access, prepared: _Prepared,
        started: float,
    ) -> AgentReply:
        connection = access.connection
        audit = {
            "key": call.key.id, "access": access.id, "model": str(call.body.get("model", ""))[:100], "blocks_new": prepared.new,
            "blocks_repeated": sum(len(d) for d in prepared.repeated.values()), "withheld": sum(prepared.withheld.values()),
            "replaced": dict(prepared.replaced), "ms_prepare": _ms(started),
        }
        sent = time.perf_counter()
        try:
            upstream = self.forward(prepared.out, connection, prepared.state, prepared.settings, passed=proto.passed_back)
        except cloud.LeakDetected as exc:
            self.repo.audit("agent_refused", call.user.id, chat_id, key=call.key.id, reason="leak_egress", count=exc.count)
            refused = AgentRefused(
                400, "invalid_request_error",
                f"Cleaner: в исходящем тексте найдено известное значение ({exc.count}), запрос не отправлен",
            )
            refused.reason = "leak_egress"
            raise refused from None
        except egress.ProviderTimeout:
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, ms_upstream=_ms(sent), status=504)
            raise AgentRefused(504, "api_error", "Cleaner: провайдер не ответил вовремя") from None
        except (ProviderError, ValueError):
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, ms_upstream=_ms(sent), status=502)
            raise AgentRefused(502, "api_error", "Cleaner: провайдер недоступен") from None
        audit["ms_upstream"] = _ms(sent)
        if upstream.status >= 300 or call.path.endswith("/count_tokens"):
            try:
                raw = upstream.read(_BODY_BYTES)
            finally:
                upstream.close()
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=upstream.status)
            return AgentReply(upstream.status, dict(upstream.headers), body=raw)
        stream = proto.stream(prepared.state, prepared.settings)
        if call.key.hold_secrets:
            stream.budget.guard = prepared.guard = SecretGuard(prepared.out.body)
        if not call.body.get("stream"):
            try:
                raw = upstream.read(_BODY_BYTES)
            finally:
                upstream.close()
            try:
                reply = json.loads(raw)
                message = stream.complete(reply)
            except RestoreLimit:
                raise self._refuse(call, 502, "api_error", "Cleaner: превышен предел размера восстановленного ответа",
                                   "response_limit", chat_id=chat_id) from None
            except (ValueError, AttributeError):
                self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=502)
                raise AgentRefused(502, "api_error", "Cleaner: провайдер прислал не JSON") from None
            self._record(proto, chat_id, conv_id, prepared, stream)
            self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=upstream.status, usage=proto.usage(reply))
            return AgentReply(upstream.status, {"content-type": "application/json"}, body=_json(message).encode("utf-8"))
        headers = {"content-type": "text/event-stream", "cache-control": "no-cache"}
        headers.update((name, value) for name, value in upstream.headers.items() if name not in ("content-type", "retry-after"))
        once = threading.Lock()         # не отпускается: конец ответа — один раз, из какого бы потока его ни позвали

        def end(finished: bool, usage: dict[str, int]) -> None:
            nonlocal upstream, prepared, stream, call
            if not once.acquire(blocking=False):
                return
            try:
                upstream.close()
                self._record(proto, chat_id, conv_id, prepared, stream)
                self.repo.audit("agent_send", call.user.id, chat_id, **audit, status=200, finished=finished, usage=usage)
                self._receipt(call, proto, chat_id, conv_id, access, prepared, started, 200 if finished else 502,
                              "" if finished else getattr(stream, "failure_reason", "stream_interrupted"))
            finally:
                # close живёт до уничтожения HTTP-ответа: после записи он не должен держать тело запроса и снимок
                # из 20 000 сущностей (и заставлять GC обходить их на следующих запросах).
                del upstream, prepared, stream, call

        events = self._events(proto, upstream, stream, end)

        def close() -> None:
            # Начатый генератор кончается своим finally; не начатый его не выполнит — тогда конец здесь (агент ушёл
            # раньше первого чтения), иначе соединение пула и вход агента остались бы заняты навсегда.
            events.close()
            end(False, {})

        return AgentReply(200, headers, events=events, stop=upstream.abort, close=close)

    def _record(
        self, proto: GatewayProtocol, chat_id: str, conv_id: str, prepared: _Prepared, stream: ProtocolStream,
    ) -> None:
        """Пары «отдано агенту — пришло от модели» — журнал out (7.2.2), своей транзакцией."""
        entries = [
            LedgerEntry(
                conv_id, "out",
                _digest(prepared.secret, proto, "assistant", proto.model_kind(local), local),
                _json(local), _json(wire),
            )
            for local, wire in stream.pairs
        ]
        if entries:
            self.repo.add_ledger(chat_id, entries)

    @staticmethod
    def _events(
        proto: GatewayProtocol, upstream: egress.Upstream, stream: ProtocolStream, end: Callable[[bool, dict], None],
    ) -> Iterator[bytes]:
        """События агенту по мере прихода; обрыв — уже восстановленная часть и событие error (раздел 12). usage —
        последние числа провайдера по каждому имени: у Anthropic message_delta несёт нарастающий итог."""
        finished = done = failed = False
        limited = False
        tail: list[dict] = []
        usage: dict[str, int] = {}
        try:
            try:
                for line in upstream.lines():
                    if not line.startswith("data:"):
                        continue
                    if line[5:].strip() == "[DONE]":        # конец ответа OpenAI-совместимого провайдера
                        done = True
                        continue
                    try:
                        event = json.loads(line[5:])
                    except ValueError:
                        continue
                    if not isinstance(event, dict):
                        continue
                    failed = failed or event.get("type") == "error" or "error" in event
                    usage.update(proto.usage(event))
                    for out in stream.feed(event):
                        yield proto.sse(out)
                    finished = finished or stream.finished(event)
            except egress.ProviderLimit:
                raise
            except ProviderError:
                pass
            if not finished:
                tail = stream.cut()       # budget also covers the unfinished label flushed at [DONE] or disconnect
        except (RestoreLimit, egress.ProviderLimit):
            limited = True
            finished = done = False
            stream.failure_reason = "response_limit"
        finally:
            end(finished or done, usage)
        if limited:
            yield proto.sse(proto.error_event("Cleaner: превышен предел размера ответа или аргументов инструмента"))
            return
        for out in tail:
            yield proto.sse(out)
        if finished or done:
            if end := proto.end():
                yield end
            return
        if not failed:
            yield proto.sse(proto.error_event("Cleaner: поток ответа провайдера оборвался"))
