"""Отправка запроса шлюза агентов (спецификация 2026-10-28, разделы 5, 8.9, 9.1): AgentOutgoing из ядра → провайдер,
поток байтов ответа → обратно, без разбора.

Принимает только AgentOutgoing, собранный pipeline (SEC-1), и сам повторяет проверку утечек по новым и служебным строкам
(SEC-2). Ключ — подключения Cleaner по его способу; ключи агента сюда не доходят: заголовки отобрал pipeline. HTTPS, кроме
петли (SEC-13); переадресации и повторы не выполняются, прокси из окружения не читается. Тело запроса, ответ и ключ не
попадают ни в логи, ни в сообщения об ошибках."""
from __future__ import annotations

import socket
import sys
import threading
from collections.abc import Iterator
from http.cookiejar import CookieJar, DefaultCookiePolicy
from urllib.parse import urlsplit

import httpx

from cleaner.core.pipeline import AgentOutgoing, checked_leaks
from cleaner.core.types import ChatState, Settings
from cleaner.egress import ProviderError
from cleaner.egress.cloud import Connection, LeakDetected, _headers, check_url

_TIMEOUT = httpx.Timeout(30.0, read=300.0)          # агент с рассуждениями молчит минутами до первого слова
_PASSED = ("content-type", "request-id", "retry-after")      # заголовки провайдера агенту, если протокол не задал свои
_LIMITS = httpx.Limits(max_connections=32, max_keepalive_connections=16, keepalive_expiry=60.0)

# Соединения с провайдером переиспользуются (замер 30.10.2026: установка TLS — 0,19–0,43 с на ход агента). Клиент — на
# источник scheme://host:port, общий для потоков пула шлюза. Вход агента по подписке — заголовок запроса, не клиента.
_clients: dict[str, httpx.Client] = {}
_clients_lock = threading.Lock()


def _client(url: str) -> httpx.Client:
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.hostname}:{parts.port or (443 if parts.scheme == 'https' else 80)}"
    with _clients_lock:
        client = _clients.get(origin)
        if client is None:
            # Cookie провайдера (__cf_bm и другие) не хранятся: общий клиент отдал бы их запросам других агентов и входов.
            client = _clients[origin] = httpx.Client(
                trust_env=False, follow_redirects=False, timeout=_TIMEOUT, limits=_LIMITS,
                verify=parts.scheme != "http",  # HTTP разрешён только на петле: TLS и загрузка CA ему не нужны.
                cookies=CookieJar(DefaultCookiePolicy(allowed_domains=[])),
            )
        return client


def close_clients() -> None:
    """Закрыть клиенты пула — при остановке службы (после пула шлюза) и в тестах."""
    with _clients_lock:
        clients = list(_clients.values())
        _clients.clear()
    for client in clients:
        client.close()


class ProviderTimeout(ProviderError):
    """Провайдер не ответил вовремя (агенту — 504, а не 502)."""

    def __init__(self) -> None:
        super().__init__("провайдер не ответил вовремя")


class Upstream:
    """Ответ провайдера: код, разрешённые заголовки и тело — строками потока или байтами. owns_client — клиент свой
    (тесты с transport) и закрывается с ответом; клиент пула общий и не закрывается."""

    def __init__(
        self, client: httpx.Client, response: httpx.Response, secrets: tuple[str, ...], passed: tuple[str, ...] = _PASSED,
        *, owns_client: bool,
    ):
        self._client = client
        self._owns_client = owns_client
        self._response = response
        self._lock = threading.Lock()
        self._closed = False
        # Длинные первыми: «Bearer <токен>» убирается целиком, а не оставляет «Bearer ***».
        self._secrets = sorted({secret.encode("utf-8") for secret in secrets if secret}, key=len, reverse=True)
        self.status = response.status_code
        self.headers = {name: response.headers[name] for name in passed if name in response.headers}

    def lines(self) -> Iterator[str]:
        secrets = tuple(secret.decode("utf-8") for secret in self._secrets)
        try:
            for line in self._response.iter_lines():
                for secret in secrets:
                    line = line.replace(secret, "***")
                yield line
        except httpx.TimeoutException:
            raise ProviderTimeout() from None
        except (httpx.HTTPError, httpx.StreamError):
            raise ProviderError("соединение с провайдером оборвалось") from None

    def read(self, limit: int) -> bytes:
        """Тело до limit байт — ответ без потока или ошибка провайдера; ключ подключения и вход агента по подписке, если
        провайдер их повторил, — прочь."""
        raw = b""
        try:
            for chunk in self._response.iter_bytes():
                raw += chunk
                if len(raw) >= limit:
                    break
        except httpx.TimeoutException:
            raise ProviderTimeout() from None
        except (httpx.HTTPError, httpx.StreamError):
            raise ProviderError("соединение с провайдером оборвалось") from None
        raw = raw[:limit]
        for secret in self._secrets:
            raw = raw.replace(secret, b"***")
        return raw

    def abort(self) -> None:
        """Агент ушёл: оборвать ответ из другого потока. Поток, который ждёт молчащего провайдера, получает обрыв сразу, а
        не через 300 с; соединение с недочитанным ответом httpx закрывает, в пул оно не возвращается. После close и
        после конца ответа (httpx отметил закрытие раньше, чем вернул соединение в пул) — ничего: соединение уже могло
        уйти другому запросу.

        Linux: shutdown сокета будит recv другого потока (close — нет), а закрывает всё сам поток чтения: состояние httpx
        из чужого потока не трогается. Windows: shutdown не будит select, будит только закрытие сокета — response.close,
        как «Остановить» в cloud.send; сокет там закрывается последним, после отметок httpx о закрытии."""
        with self._lock:
            if self._closed or self._response.is_closed:
                return
            stream = self._response.extensions.get("network_stream")
            sock = stream.get_extra_info("socket") if stream is not None else None
            if sock is None or sys.platform == "win32":        # без сокета — transport тестов
                self._response.close()
                return
            try:
                # Метод socket, а не SSLSocket: тот обнулил бы _sslobj под читающим потоком.
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            self._closed = True
        self._response.close()
        if self._owns_client:
            self._client.close()


def forward(
    out: AgentOutgoing, connection: Connection, state: ChatState, settings: Settings, *,
    passed: tuple[str, ...] = _PASSED, transport: httpx.BaseTransport | None = None,
) -> Upstream:
    """passed — заголовки ответа провайдера, которые уходят агенту (по протоколу)."""
    if not isinstance(out, AgentOutgoing):
        raise TypeError("egress.forward принимает только AgentOutgoing, собранный pipeline")
    leaks = checked_leaks(out.checked, state, settings)
    if leaks:
        raise LeakDetected(len(leaks))
    check_url(connection.base_url)
    url = f"{connection.base_url.rstrip('/')}{out.path}" + (f"?{out.query}" if out.query else "")
    owns = transport is not None
    if owns:
        client = httpx.Client(transport=transport, trust_env=False, follow_redirects=False, timeout=_TIMEOUT,
                             verify=urlsplit(url).scheme != "http")
    else:
        client = _client(url)
    try:
        request = client.build_request("POST", url, content=out.body, headers={**dict(out.headers), **_headers(connection)})
        response = client.send(request, stream=True)
    except httpx.TimeoutException:
        if owns:
            client.close()
        raise ProviderTimeout() from None
    except httpx.HTTPError:
        if owns:
            client.close()
        raise ProviderError("соединение с провайдером не удалось") from None
    if 300 <= response.status_code < 400:
        response.close()
        if owns:
            client.close()
        raise ProviderError("провайдер ответил переадресацией — она не выполняется", status=response.status_code)
    agent = dict(out.headers).get("authorization", "")        # вход агента по подписке
    return Upstream(client, response, (connection.api_key, agent, agent.partition(" ")[2]), passed, owns_client=owns)
