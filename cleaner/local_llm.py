"""Клиент шлюза сервера: чат-запросы локальной модели и распознавание страниц ocr-ru (разделы 9 и 11).

Единственный, кроме egress, модуль пакета с сетевой библиотекой (SEC-1). Адрес — петлевой, частный
или явно доверенный (SEC-12). Прокси из окружения не используется: запрос с данными чата уходит только
по заданному адресу.
"""
from __future__ import annotations

import base64
import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from cleaner.core.detect.llm import CompletionError

OCR_MODEL = "ocr-ru"
OCR_TIMEOUT = 1300.0                    # у сквозного маршрута шлюза — 1260 с (CURRENT-STATE.md vLLM)
_OCR_MAX_BYTES = 20 * 1024 * 1024       # предел ocr-ru на поле image
_OCR_ATTEMPTS = 10                      # очередь ocr-ru — две задачи, дальше 503 с Retry-After
_OCR_MIMES = frozenset({"image/png", "image/jpeg"})
_OCR_CODES = {413: "ocr_too_large", 422: "ocr_empty", 400: "ocr_bad_image"}
_OCR_MESSAGES = {
    "ocr_too_large": "изображение страницы больше пределов распознавания (20 МБ, 12 000 точек по стороне)",
    "ocr_empty": "на странице не распознано ни одного знака",
    "ocr_bad_image": "распознавание не приняло изображение",
}


class LocalLLMError(CompletionError):
    """Шлюз недоступен, отказал или ответил не по правилам."""


@dataclass(frozen=True)
class LocalLLMConfig:
    base_url: str          # OpenAI-совместимый адрес до /v1, например http://127.0.0.1:30000/v1
    model: str
    api_key: str
    timeout: float = 300.0

    def __repr__(self) -> str:          # ключ не попадает ни в логи, ни в тексты исключений
        return f"LocalLLMConfig(base_url={self.base_url!r}, model={self.model!r})"


def check_address(url: str, trusted: frozenset[str]) -> None:
    """SEC-12: только петлевой, частный или доверенный адрес. ValueError с причиной, если нет."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("нужен адрес вида http://узел:порт/v1")
    host = parts.hostname.lower()
    if host == "localhost" or host in trusted:
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"узла {host} нет в списке доверенных") from None
    if not (address.is_loopback or address.is_private):
        raise ValueError(f"{host} — не петлевой и не частный адрес, и его нет в списке доверенных")


def _code(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return ""
    return str(body.get("code", "")) if isinstance(body, dict) else ""


def _retry_after(response: httpx.Response) -> float:
    try:
        return float(min(60, max(1, int(response.headers.get("Retry-After", "10")))))
    except ValueError:
        return 10.0


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code in (401, 403):
        raise LocalLLMError("auth", f"шлюз отклонил ключ ({response.status_code})")
    if response.status_code >= 400:
        raise LocalLLMError("http", f"шлюз ответил {response.status_code}")


class LocalLLM:
    def __init__(
        self, config: LocalLLMConfig, transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config
        self._sleep = sleep
        self._client = httpx.Client(
            transport=transport, trust_env=False, follow_redirects=False,
            headers={"Authorization": f"Bearer {config.api_key}"},
        )

    @property
    def _base(self) -> str:
        return self.config.base_url.rstrip("/")

    @property
    def ocr_url(self) -> str:
        """Распознавание — сквозной маршрут шлюза вне /v1: http://узел:30000/pages/ocr."""
        root = self._base[:-3] if self._base.endswith("/v1") else self._base
        return f"{root}/pages/ocr"

    def _post(self, url: str, body: dict, timeout: float) -> httpx.Response:
        try:
            return self._client.post(url, json=body, timeout=timeout)
        except httpx.TimeoutException:
            raise LocalLLMError("unavailable", "локальная модель не ответила вовремя") from None
        except httpx.HTTPError:
            raise LocalLLMError("unavailable", "локальная модель недоступна") from None

    def complete(
        self, messages: list[dict[str, str]], *, max_tokens: int, json_schema: dict | None = None,
        truncated_ok: bool = False,
    ) -> str:
        """Ответ модели одним текстом; температура 0; схема JSON — параметром response_format (раздел 11).
        truncated_ok — ответ на вопрос пользователя (FR-9.4): обрезанный по длине отдаётся, а не отклоняется."""
        body: dict = {"model": self.config.model, "messages": messages, "temperature": 0, "max_tokens": max_tokens}
        if json_schema is not None:
            body["response_format"] = {
                "type": "json_schema", "json_schema": {"name": "cleaner", "schema": json_schema, "strict": True},
            }
        response = self._post(f"{self._base}/chat/completions", body, self.config.timeout)
        _raise_for_status(response)
        try:
            choice = response.json()["choices"][0]
            content, finish = choice["message"].get("content"), choice.get("finish_reason")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise LocalLLMError("bad_response", "ответ шлюза не разбирается") from None
        if finish == "length" and not truncated_ok:
            raise LocalLLMError("length", "ответ локальной модели обрезан по длине")
        if not isinstance(content, str) or not content.strip():
            raise LocalLLMError("empty", "локальная модель вернула пустой ответ")
        return content

    def ocr_page(self, image: bytes, mime: str) -> str:
        """Markdown одной страницы. Очередь занята или модель грузится — ждём Retry-After и повторяем (раздел 9)."""
        if mime not in _OCR_MIMES:
            raise LocalLLMError("ocr_format", "распознаются только изображения PNG и JPEG")
        if len(image) > _OCR_MAX_BYTES:
            raise LocalLLMError("ocr_too_large", _OCR_MESSAGES["ocr_too_large"])
        body = {"model": OCR_MODEL, "image": base64.b64encode(image).decode("ascii")}
        for _ in range(_OCR_ATTEMPTS):
            response = self._post(self.ocr_url, body, OCR_TIMEOUT)
            if response.status_code == 503 and _code(response) in ("overloaded", "loading"):
                self._sleep(_retry_after(response))
                continue
            code = _OCR_CODES.get(response.status_code)
            if code:
                raise LocalLLMError(code, _OCR_MESSAGES[code])
            _raise_for_status(response)
            try:
                markdown = response.json()["markdown"]
            except (ValueError, KeyError, TypeError):
                raise LocalLLMError("bad_response", "ответ распознавания не разбирается") from None
            return markdown if isinstance(markdown, str) else ""
        raise LocalLLMError("unavailable", "очередь распознавания занята слишком долго")
