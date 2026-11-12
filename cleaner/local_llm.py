"""Клиент шлюза сервера: чат-запросы локальной модели и распознавание страниц — службой ocr-ru или моделью зрения
с ответом OpenAI (разделы 9 и 11).

Единственный, кроме egress, модуль пакета с сетевой библиотекой (SEC-1). Адрес — петлевой, частный
или явно доверенный (SEC-12). Прокси из окружения не используется: запрос с данными чата уходит только
по заданному адресу.
"""
from __future__ import annotations

import base64
import ipaddress
import json
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
# Модель зрения с ответом OpenAI (HunyuanOCR на local-gateway): системная часть пустая, изображение — первым, указание — вторым,
# как её учили. Указание — из translate (prompts/ocr_extract_hunyuan_v1.txt), проверенное на его корпусе страниц.
_OCR_PROMPT = (
    "Extract all information from the document image and represent it as Markdown.\n"
    "Tables must be expressed in HTML with <table>/<tr>/<td>; use colspan/rowspan for merged cells.\n"
    "Formulas must use LaTeX inline (e.g. $E=mc^2$).\n"
    "Preserve the original languages — do NOT translate.\n"
    "Follow the natural reading order (top-to-bottom, left-to-right; for multi-column layouts complete one column "
    "before moving to the next).\n"
    "For text visible under stamps or seals, transcribe it normally.\n"
    "Output only the Markdown body — no preamble, no commentary."
)
_OCR_MAX_TOKENS = 16384                 # у HunyuanOCR на local-gateway контекст 32768, страница-картинка — несколько тысяч


class LocalLLMError(CompletionError):
    """Шлюз недоступен, отказал или ответил не по правилам."""


@dataclass(frozen=True)
class LocalLLMConfig:
    base_url: str          # OpenAI-совместимый адрес до /v1, например http://127.0.0.1:30000/v1
    model: str
    api_key: str
    # Шлюз llm_routers (local-gateway) держит запрос local-chat, пока модель возвращается на карту после слота по требованию
    # (распознавание скана снимает её) — до 420 с; клиент ждёт дольше.
    timeout: float = 450.0
    ocr_model: str = ""    # модель зрения с ответом OpenAI на маршруте /pages/ocr; пусто — служба ocr-ru

    def __repr__(self) -> str:          # ключ не попадает ни в логи, ни в тексты исключений
        return f"LocalLLMConfig(base_url={self.base_url!r}, model={self.model!r}, ocr_model={self.ocr_model!r})"


def check_address(url: str, trusted: frozenset[str]) -> None:
    """SEC-12: только петлевой, частный или доверенный адрес. ValueError с причиной, если нет.
    Логин и пароль в адресе — тоже отказ: адрес уходит владельцам ключей в /api/v1, а httpx по ним заменил бы
    Bearer с ключом шлюза на Basic, и шлюз ответил бы 401."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("нужен адрес вида http://узел:порт/v1")
    if "@" in parts.netloc:
        raise ValueError("логин и пароль в адресе не указываются: ключ шлюза задаётся окружением службы")
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

    def complete(self, messages: list[dict[str, str]], *, max_tokens: int, json_schema: dict | None = None) -> str:
        """Ответ модели одним текстом; температура 0; схема JSON — параметром response_format (раздел 11)."""
        content, truncated = self._chat(messages, max_tokens, json_schema)
        if truncated:
            raise LocalLLMError("length", "ответ локальной модели обрезан по длине")
        return content

    def answer(self, messages: list[dict[str, str]], *, max_tokens: int) -> tuple[str, bool]:
        """Ответ на вопрос пользователя (FR-9.4) и признак обрезки по длине: обрезанный ответ полезнее отказа."""
        return self._chat(messages, max_tokens, None)

    def answer_stream(self, messages, *, max_tokens, cancel, outcome, on_open):
        """Explicit local consultation, bounded SSE with the same cancellation contract as cloud answers."""
        from cleaner.egress import cloud
        from cleaner.egress import ProviderError
        from cleaner.egress.protocols import openai
        if cancel.is_set():
            return
        body = {"model": self.config.model, "messages": messages, "temperature": 0,
                "max_tokens": max_tokens, "stream": True}
        try:
            with self._client.stream("POST", f"{self._base}/chat/completions", json=body, timeout=self.config.timeout) as response:
                on_open(response.close)
                if response.status_code >= 300:
                    raise LocalLLMError("http", f"локальная модель ответила {response.status_code}")
                ended = False
                for event in cloud._events(cloud._lines(response.iter_bytes())):
                    if cancel.is_set():
                        return
                    if event is cloud._DONE or openai.finished(event):
                        ended = True
                    if openai.stopped_by_length(event):
                        outcome["truncated"] = True
                    if event is not cloud._DONE:
                        piece = openai.text(event)
                        if piece:
                            yield piece
                if not ended:
                    raise LocalLLMError("unavailable", "поток локальной модели оборвался")
        except (httpx.HTTPError, httpx.StreamError):
            if not cancel.is_set():
                raise LocalLLMError("unavailable", "локальная модель недоступна") from None
        except ProviderError:
            raise LocalLLMError("bad_response", "локальная модель отказала или превысила предел ответа") from None

    def _chat(self, messages: list[dict[str, str]], max_tokens: int, json_schema: dict | None) -> tuple[str, bool]:
        body: dict = {"model": self.config.model, "messages": messages, "temperature": 0, "max_tokens": max_tokens}
        if json_schema is not None:
            body["response_format"] = {
                "type": "json_schema", "json_schema": {"name": "cleaner", "schema": json_schema, "strict": True},
            }
        response = self._post(f"{self._base}/chat/completions", body, self.config.timeout)
        _raise_for_status(response)
        content, finish = _message(response)
        if not isinstance(content, str) or not content.strip():
            if finish == "length":
                raise LocalLLMError("length", "ответ локальной модели обрезан по длине")
            raise LocalLLMError("empty", "локальная модель вернула пустой ответ")
        return content, finish == "length"

    def ocr_page(self, image: bytes, mime: str) -> str:
        """Markdown одной страницы: службой ocr-ru или, если задана модель распознавания, моделью зрения (_ocr_chat). Очередь
        ocr-ru занята или модель грузится — ждём Retry-After и повторяем (раздел 9)."""
        if mime not in _OCR_MIMES:
            raise LocalLLMError("ocr_format", "распознаются только изображения PNG и JPEG")
        if len(image) > _OCR_MAX_BYTES:
            raise LocalLLMError("ocr_too_large", _OCR_MESSAGES["ocr_too_large"])
        if self.config.ocr_model:
            return self._ocr_chat(image, mime)
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

    def _ocr_chat(self, image: bytes, mime: str) -> str:
        """Страница — сообщением с изображением на маршрут /pages/ocr: на local-gateway он ведёт в /v1/chat/completions HunyuanOCR, а
        слот модели поднимает и ждёт шлюз. Обрезанный по длине ответ — отказ, а не половина страницы; пустой ответ и карта
        блоков без текста (_layout_only) — страница без знаков, как у ocr-ru."""
        body = {
            "model": self.config.ocr_model, "temperature": 0, "max_tokens": _OCR_MAX_TOKENS,
            "messages": [
                {"role": "system", "content": ""},
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{base64.b64encode(image).decode('ascii')}"}},
                    {"type": "text", "text": _OCR_PROMPT},
                ]},
            ],
        }
        response = self._post(self.ocr_url, body, OCR_TIMEOUT)
        if response.status_code == 413:
            raise LocalLLMError("ocr_too_large", _OCR_MESSAGES["ocr_too_large"])
        _raise_for_status(response)
        content, finish = _message(response)
        if finish == "length":
            raise LocalLLMError("ocr_truncated", "распознанный текст страницы обрезан по длине ответа модели")
        if not isinstance(content, str) or not content.strip() or _layout_only(content):
            raise LocalLLMError("ocr_empty", _OCR_MESSAGES["ocr_empty"])
        return content


def _message(response: httpx.Response) -> tuple[object, object]:
    """Текст первого варианта ответа OpenAI и причина его конца."""
    try:
        choice = response.json()["choices"][0]
        return choice["message"].get("content"), choice.get("finish_reason")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise LocalLLMError("bad_response", "ответ шлюза не разбирается") from None


def _layout_only(text: str) -> bool:
    """Ответ HunyuanOCR — карта блоков с координатами без содержимого, а не текст страницы: такой отказ модели на сложных
    сканах замерил translate (ocr_router.looks_like_layout_json). Проверка узкая — массив объектов без поля с текстом."""
    text = text.strip()
    if not text.startswith("[") or "layout_type" not in text:
        return False
    try:
        blocks = json.loads(text)
    except ValueError:
        return '"text"' not in text and '"content"' not in text      # оборванный JSON того же вида
    return isinstance(blocks, list) and bool(blocks) and all(
        isinstance(block, dict) and not any(str(block.get(key) or "").strip() for key in ("text", "content", "markdown"))
        for block in blocks
    )
