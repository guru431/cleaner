"""Адаптеры протоколов: тело запроса из OutgoingContext и разбор событий потокового ответа."""
from __future__ import annotations

from cleaner.egress import ProviderError


def provider_error(error: object, status: int | None = None) -> ProviderError:
    """Ошибка из объекта провайдера: {"type": …, "message": …} или строка."""
    if isinstance(error, dict):
        kind, message = str(error.get("type") or error.get("code") or ""), str(error.get("message") or "")
    else:
        kind, message = "", str(error or "")
    return ProviderError(status=status, kind=kind, detail=message[:300])
