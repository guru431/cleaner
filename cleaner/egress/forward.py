"""Отправка запроса шлюза агентов (спецификация 2026-10-28, разделы 5, 8.9, 9.1): AgentOutgoing из ядра → провайдер,
поток байтов ответа → обратно, без разбора.

Принимает только AgentOutgoing, собранный pipeline (SEC-1), и сам повторяет проверку утечек по новым и служебным строкам
(SEC-2). Ключ — подключения Cleaner по его способу; ключи агента сюда не доходят: заголовки отобрал pipeline. HTTPS, кроме
петли (SEC-13); переадресации и повторы не выполняются, прокси из окружения не читается. Тело запроса, ответ и ключ не
попадают ни в логи, ни в сообщения об ошибках."""
from __future__ import annotations

from collections.abc import Iterator

import httpx

from cleaner.core.pipeline import AgentOutgoing, checked_leaks
from cleaner.core.types import ChatState, Settings
from cleaner.egress import ProviderError
from cleaner.egress.cloud import Connection, LeakDetected, _headers, check_url

_TIMEOUT = httpx.Timeout(30.0, read=300.0)          # агент с рассуждениями молчит минутами до первого слова
_PASSED = ("content-type", "request-id", "retry-after")      # заголовки провайдера агенту, если протокол не задал свои


class ProviderTimeout(ProviderError):
    """Провайдер не ответил вовремя (агенту — 504, а не 502)."""

    def __init__(self) -> None:
        super().__init__("провайдер не ответил вовремя")


class Upstream:
    """Ответ провайдера: код, разрешённые заголовки и тело — строками потока или байтами."""

    def __init__(
        self, client: httpx.Client, response: httpx.Response, secrets: tuple[str, ...], passed: tuple[str, ...] = _PASSED,
    ):
        self._client = client
        self._response = response
        # Длинные первыми: «Bearer <токен>» убирается целиком, а не оставляет «Bearer ***».
        self._secrets = sorted({secret.encode("utf-8") for secret in secrets if secret}, key=len, reverse=True)
        self.status = response.status_code
        self.headers = {name: response.headers[name] for name in passed if name in response.headers}

    def lines(self) -> Iterator[str]:
        try:
            yield from self._response.iter_lines()
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

    def close(self) -> None:
        self._response.close()
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
    client = httpx.Client(transport=transport, trust_env=False, follow_redirects=False, timeout=_TIMEOUT)
    try:
        request = client.build_request("POST", url, content=out.body, headers={**dict(out.headers), **_headers(connection)})
        response = client.send(request, stream=True)
    except httpx.TimeoutException:
        client.close()
        raise ProviderTimeout() from None
    except httpx.HTTPError:
        client.close()
        raise ProviderError("соединение с провайдером не удалось") from None
    if 300 <= response.status_code < 400:
        response.close()
        client.close()
        raise ProviderError("провайдер ответил переадресацией — она не выполняется", status=response.status_code)
    agent = dict(out.headers).get("authorization", "")        # вход агента по подписке
    return Upstream(client, response, (connection.api_key, agent, agent.partition(" ")[2]), passed)
