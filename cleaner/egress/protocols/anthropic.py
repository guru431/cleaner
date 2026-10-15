"""Anthropic-совместимый протокол: POST {адрес}/v1/messages, ответ — события content_block_delta, конец — message_stop."""
from __future__ import annotations

from typing import TYPE_CHECKING

from cleaner.egress import StreamEnd
from cleaner.egress.protocols import provider_error

if TYPE_CHECKING:
    from cleaner.core.pipeline import OutgoingContext
    from cleaner.egress.cloud import Connection

VERSION = "2023-06-01"


def request(ctx: OutgoingContext, connection: Connection) -> tuple[str, dict[str, str], dict]:
    body = {
        **connection.extra_body, "model": ctx.model, "max_tokens": connection.max_tokens,
        "messages": [{"role": message.role, "content": message.text} for message in ctx.messages], "stream": True,
    }
    if ctx.system:
        body["system"] = ctx.system
    return f"{connection.base_url.rstrip('/')}/v1/messages", {"anthropic-version": VERSION}, body


def text(event: dict) -> str | None:
    """Фрагмент ответа. Блоки рассуждений (thinking_delta) не показываются."""
    kind = event.get("type")
    if kind == "error":
        raise provider_error(event.get("error"))
    if kind == "message_stop":
        raise StreamEnd()
    if kind == "content_block_delta":
        delta = event.get("delta") or {}
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            return delta["text"] or None
    return None


def stopped_by_length(event: dict) -> bool:
    return event.get("type") == "message_delta" and (event.get("delta") or {}).get("stop_reason") == "max_tokens"
