"""Отправка облачной модели (раздел 10.3): OutgoingContext из ядра → провайдер, фрагменты ответа → обратно.

Принимает только OutgoingContext, собранный pipeline (SEC-1), и сам повторяет проверку утечек (SEC-2).
Только текст: без инструментов, файлов и поиска провайдера (FR-8.8). HTTPS, кроме петли (SEC-13);
сертификаты проверяются, переадресации и повторы не выполняются, прокси из окружения не читается.
Тело запроса, ответ и ключ не попадают ни в логи, ни в сообщения об ошибках.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from cleaner.core import leakcheck
from cleaner.core.pipeline import OutgoingContext
from cleaner.core.types import ChatState, Settings
from cleaner.egress import ProviderError, StreamEnd
from cleaner.egress.protocols import anthropic, openai, provider_error, responses

PROTOCOLS = {"openai": openai, "anthropic": anthropic, "responses": responses}
# passthrough — доступ шлюза по подписке: ключа подключения нет, вход агента уже в заголовках запроса (раздел 9.4).
AUTH_STYLES = ("bearer", "x-api-key", "passthrough")
# Поля, которыми дополнительные параметры подключения могли бы заменить сам запрос или добавить к нему
# инструменты, файлы и поиск провайдера (FR-8.8). У Responses запрос — input и instructions, а
# previous_response_id и conversation подтянули бы историю, хранящуюся у провайдера.
FORBIDDEN_EXTRA = frozenset({
    "model", "messages", "system", "stream", "tools", "tool_choice", "functions", "function_call",
    "input", "instructions", "previous_response_id", "conversation",
    "attachments", "files", "web_search_options", "mcp_servers", "container",
    # поиск и надстройки маршрутизаторов и провайдеров: OpenRouter, xAI, DashScope
    "plugins", "search_parameters", "enable_search", "web_search", "search_options", "documents", "file_ids",
})
# Узел адреса подключения → заголовок сессии, который провайдер требует: OpenCode Go без x-opencode-session отвечает
# 400 MissingSessionID по всем трём протоколам (проба 30.10.2026).
# Значение — UUID из отпечатка разговора или чата: постоянное в пределах разговора ради кэша промпта провайдера,
# своё у каждого субагента и ничего не говорит о самом разговоре. Заголовок агента с тем же именем заменяется.
SESSION_HEADERS: dict[str, str] = {"opencode.ai": "x-opencode-session"}
_ERROR_BYTES = 8192
_TIMEOUT = httpx.Timeout(30.0, read=180.0)          # модели с рассуждениями молчат минутами до первого слова


class LeakDetected(Exception):
    """В исходящем тексте найден оригинал: запрос не отправлен."""

    def __init__(self, count: int):
        super().__init__(f"в исходящем тексте найдено оригиналов: {count}")
        self.count = count


@dataclass(frozen=True)
class Connection:
    protocol: str
    base_url: str
    auth_style: str
    api_key: str
    max_tokens: int
    extra_body: Mapping = field(default_factory=dict)

    def __repr__(self) -> str:          # ключ не попадает ни в логи, ни в тексты исключений
        return f"Connection(protocol={self.protocol!r}, base_url={self.base_url!r})"


def check_url(url: str) -> None:
    """SEC-13: HTTPS для любого узла, HTTP — только для петли. ValueError с причиной."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host or parts.scheme not in ("https", "http"):
        raise ValueError("нужен адрес вида https://узел/путь")
    if parts.scheme == "https":
        return
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise ValueError("без TLS (http://) допускается только петлевой адрес")


def check_extra_body(extra: object) -> None:
    if not isinstance(extra, dict):
        raise ValueError("дополнительные параметры — объект JSON")
    forbidden = sorted(set(extra) & FORBIDDEN_EXTRA)
    if forbidden:
        raise ValueError(f"эти поля задаёт сам Cleaner или они запрещены: {', '.join(forbidden)}")


def session_headers(base_url: str, seed: str) -> dict[str, str]:
    """Заголовок сессии провайдера (SESSION_HEADERS) со значением из seed; у прочих узлов — ничего."""
    name = SESSION_HEADERS.get((urlsplit(base_url).hostname or "").lower())
    if name is None:
        return {}
    return {name: str(uuid.UUID(hex=hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32], version=4))}


def _headers(connection: Connection) -> dict[str, str]:
    if connection.auth_style == "passthrough":
        return {}
    if connection.auth_style == "x-api-key":
        return {"x-api-key": connection.api_key}
    return {"Authorization": f"Bearer {connection.api_key}"}


def _scrub(error: ProviderError, key: str) -> ProviderError:
    """Ключ из сообщения провайдера — прочь: некоторые повторяют его в тексте ошибки."""
    if key and key in error.detail:
        error.detail = error.detail.replace(key, "***")
    return error


def _error(response: httpx.Response, key: str) -> ProviderError:
    if 300 <= response.status_code < 400:
        return ProviderError("провайдер ответил переадресацией — она не выполняется", status=response.status_code)
    raw = b""
    for chunk in response.iter_bytes():
        raw += chunk
        if len(raw) >= _ERROR_BYTES:
            break
    try:
        body = json.loads(raw[:_ERROR_BYTES])
    except ValueError:
        body = raw[:300].decode("utf-8", "replace").strip()
    if isinstance(body, dict):
        body = body.get("error") or body
    return _scrub(provider_error(body, response.status_code), key)


_DONE: dict = {}          # «data: [DONE]» — конец ответа OpenAI-совместимого провайдера


def _events(lines: Iterator[str]) -> Iterator[dict]:
    """События потокового ответа: строки «data: {…}»; «data: [DONE]» отдаётся как _DONE."""
    for line in lines:
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            yield _DONE
            return
        try:
            event = json.loads(data)
        except ValueError:
            continue
        if isinstance(event, dict):
            yield event


def send(
    ctx: OutgoingContext, connection: Connection, state: ChatState | None, settings: Settings | None, *,
    cancel: threading.Event | None = None, transport: httpx.BaseTransport | None = None, outcome: dict | None = None,
    on_open: Callable[[Callable[[], None]], None] | None = None,
) -> Iterator[str]:
    """Фрагменты ответа по мере получения. state — для проверки утечек (у проверки подключения его нет).
    outcome получает {"truncated": True}, если провайдер остановился по пределу длины ответа. on_open получает
    функцию, закрывающую соединение: «Остановить» прерывает и ожидание провайдера, который молчит."""
    if not isinstance(ctx, OutgoingContext):
        raise TypeError("egress принимает только OutgoingContext, собранный pipeline")
    if state is not None:
        leaks = sum(len(leakcheck.check(text, state, settings)) for text in ctx.texts())
        if leaks:
            raise LeakDetected(leaks)
    check_url(connection.base_url)
    check_extra_body(dict(connection.extra_body))
    protocol = PROTOCOLS[connection.protocol]
    url, headers, body = protocol.request(ctx, connection)
    # Пустой chat_id — у проверки подключения: сессия на один запрос.
    headers = {**headers, **session_headers(connection.base_url, ctx.chat_id or secrets.token_hex(16))}
    key = connection.api_key
    if cancel is not None and cancel.is_set():
        return                                      # остановили, пока задание ждало в пуле: запрос не уходит
    with httpx.Client(transport=transport, trust_env=False, follow_redirects=False, timeout=_TIMEOUT) as client:
        try:
            with client.stream("POST", url, json=body, headers={**headers, **_headers(connection)}) as response:
                if on_open is not None:
                    on_open(response.close)
                if response.status_code >= 300:
                    raise _error(response, key)
                ended = False
                for event in _events(response.iter_lines()):
                    if cancel is not None and cancel.is_set():
                        return
                    if event is _DONE or protocol.finished(event):
                        ended = True
                    if outcome is not None and protocol.stopped_by_length(event):
                        outcome["truncated"] = True
                    try:
                        piece = protocol.text(event) if event is not _DONE else None
                    except StreamEnd:
                        return
                    except ProviderError as exc:
                        raise _scrub(exc, key) from None
                    if piece:
                        yield piece
                if not ended:
                    # Соединение закрылось без признака конца: это обрыв, а не весь ответ (раздел 16).
                    raise ProviderError("поток ответа оборвался до конца")
        except httpx.TimeoutException:
            if cancel is not None and cancel.is_set():
                return
            raise ProviderError("провайдер не ответил вовремя") from None
        except (httpx.HTTPError, httpx.StreamError):
            if cancel is not None and cancel.is_set():
                return                              # соединение закрыла остановка
            raise ProviderError("соединение с провайдером не удалось или оборвалось") from None
