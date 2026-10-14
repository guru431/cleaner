"""Слой 5: второй проход локальной модели (раздел 5.6). Здесь же — общее для запросов к ней из ядра.

Ядро сети не касается: модель приходит объектом с методом complete (cleaner/local_llm.py).
"""
from __future__ import annotations

from typing import Protocol


class CompletionError(Exception):
    """Ответ локальной модели не получен или не годится. Сообщение — без текста запроса и ответа.

    code: unavailable | auth | http | length | empty | bad_response | ocr_format | ocr_too_large | ocr_empty | ocr_bad_image.
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class Completer(Protocol):
    def complete(self, messages: list[dict[str, str]], *, max_tokens: int, json_schema: dict | None = None) -> str: ...
