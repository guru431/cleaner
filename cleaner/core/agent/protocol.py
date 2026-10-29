"""Протокол агента в шлюзе (спецификация 2026-10-28, раздел 9): всё, что в общем пути шлюза зависит от протокола, —
обход тела, вставка служебной инструкции, пометки удержания, восстановление потока, вид событий и ошибок, списки
заголовков. AgentService зовёт объект протокола, а не знает протоколы сам."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from cleaner.core.agent import chat, stream, walk
from cleaner.core.agent.walk import Unit
from cleaner.core.types import ChatState, Settings


class ProtocolStream(Protocol):
    """Восстановление ответа провайдера для агента. pairs — пары «блок, как агент пришлёт его в истории — блок, как его
    прислала модель» (журнал out, 7.2)."""

    pairs: list[tuple[dict, dict]]

    def feed(self, event: dict) -> list[dict]: ...

    def cut(self) -> list[dict]: ...

    def complete(self, body: dict) -> dict: ...

    def finished(self, event: dict) -> bool: ...


@dataclass(frozen=True)
class GatewayProtocol:
    name: str                               # anthropic | chat | responses — и протокол в отпечатках журнала
    provider_protocol: str                  # Provider.protocol подключения, с которым он работает
    headers: frozenset[str]                 # заголовки агента к провайдеру — по списку
    header_prefixes: tuple[str, ...]        # и по началу имени
    subscription_headers: frozenset[str]    # добавка при доступе по подписке
    passed_back: tuple[str, ...]            # заголовки провайдера агенту
    session_header: str                     # сессия агента — для просмотра; "" — у протокола её нет
    units: Callable[[dict], list[Unit]]
    first_user: Callable[[dict], object]
    structural: Callable[[dict], list[str]]
    sanitize_unit: Callable[[Unit, Callable[[str], str]], object]
    contains_media: Callable[[Unit], bool]
    is_model_block: Callable[[Unit], bool]
    model_kind: Callable[[dict], str]       # вид блока модели (text | tool_use) по узлу из pairs — для отпечатка
    rebuild: Callable[[dict, dict], dict]
    add_instruction: Callable[[dict, str], dict]        # после rebuild
    placeholder: Callable[[Unit, str], object]
    stream: Callable[[ChatState, Settings], ProtocolStream]
    sse: Callable[[dict], bytes]
    end: Callable[[], bytes]                # после последнего события
    error_event: Callable[[str], dict]
    usage: Callable[[dict], dict[str, int]]


# Заголовки агента к провайдеру (9.1); остальные отбрасываются — ключи агента и X-Cleaner-Key тоже.
ANTHROPIC = GatewayProtocol(
    name="anthropic", provider_protocol="anthropic",
    headers=frozenset({
        "anthropic-version", "anthropic-beta", "content-type", "accept",
        "x-claude-code-session-id", "x-claude-code-agent-id", "x-claude-code-parent-agent-id",
    }),
    header_prefixes=(),
    subscription_headers=frozenset({"authorization", "user-agent", "x-app"}),
    passed_back=("content-type", "request-id", "retry-after"),
    session_header="x-claude-code-session-id",
    units=walk.anthropic_units, first_user=walk.first_user, structural=walk.structural, sanitize_unit=walk.sanitize_unit,
    contains_media=walk.contains_media, is_model_block=walk.is_model_block, model_kind=lambda node: node["type"],
    rebuild=walk.rebuild, add_instruction=walk.add_instruction, placeholder=walk.placeholder,
    stream=stream.AnthropicStream, sse=stream.anthropic_sse, end=lambda: b"", error_event=stream.anthropic_error,
    usage=stream.anthropic_usage,
)

# Chat Completions (9.2): OpenCode шлёт сессию в x-session-affinity (проверка 18.1c 5В) — она и для просмотра.
CHAT = GatewayProtocol(
    name="chat", provider_protocol="openai",
    headers=frozenset({"content-type", "accept", "x-session-affinity"}),
    header_prefixes=(),
    subscription_headers=frozenset(),
    passed_back=("content-type", "x-request-id", "retry-after"),
    session_header="x-session-affinity",
    units=chat.chat_units, first_user=walk.first_user, structural=chat.structural, sanitize_unit=chat.sanitize_unit,
    contains_media=chat.contains_media, is_model_block=walk.is_model_block, model_kind=chat.model_kind,
    rebuild=walk.rebuild, add_instruction=chat.add_instruction, placeholder=chat.placeholder,
    stream=chat.ChatStream, sse=chat.sse, end=lambda: b"data: [DONE]\n\n", error_event=chat.error_event, usage=chat.usage,
)

PROTOCOLS: dict[str, GatewayProtocol] = {"anthropic": ANTHROPIC, "chat": CHAT}
