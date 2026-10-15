"""Выход к облачным моделям (раздел 10): единственное место пакета, кроме local_llm.py, с сетевой библиотекой (SEC-1)."""
from __future__ import annotations

import re

_STATUS_TEXT = {
    400: "провайдер отклонил запрос", 401: "провайдер отклонил ключ подключения",
    403: "провайдер отклонил ключ подключения", 404: "у провайдера нет такого адреса или модели",
    408: "провайдер не ответил вовремя", 413: "запрос слишком длинный для провайдера",
    429: "превышен предел запросов или средств у провайдера",
}
_KIND = re.compile(r"[\w.-]{1,40}")


class ProviderError(Exception):
    """Провайдер отказал или поток оборвался.

    str() — постоянное объяснение с кодом ответа и видом ошибки провайдера: его можно хранить и показывать
    (FR-8.9). detail — сообщение самого провайдера без ключа: оно может повторять текст запроса, поэтому
    не записывается ни в базу открыто, ни в журнал, а показывается только при проверке подключения.
    """

    def __init__(self, reason: str = "", *, status: int | None = None, kind: str = "", detail: str = ""):
        if not reason:
            reason = _STATUS_TEXT.get(status or 0, "сбой на стороне провайдера" if (status or 0) >= 500 else "провайдер прервал ответ ошибкой")
        kind = kind if _KIND.fullmatch(kind or "") else ""
        extra = ", ".join(part for part in (f"код {status}" if status else "", kind) if part)
        super().__init__(f"{reason} ({extra})" if extra else reason)
        self.status, self.kind, self.detail = status, kind, detail


class StreamEnd(Exception):
    """Провайдер сообщил о конце ответа."""
