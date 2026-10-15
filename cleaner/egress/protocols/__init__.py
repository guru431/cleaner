"""Адаптеры протоколов: тело запроса из OutgoingContext и разбор событий потокового ответа."""
from __future__ import annotations


def error_text(error: object) -> str:
    """Сообщение из объекта ошибки провайдера: {"message": …} или строка."""
    if isinstance(error, dict):
        return str(error.get("message") or error.get("type") or "ошибка без описания")
    return str(error or "ошибка без описания")
