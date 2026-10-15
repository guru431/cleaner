"""OpenAI-совместимый протокол: POST {адрес}/chat/completions, ответ — события «data: {…}», конец — «data: [DONE]»."""
from __future__ import annotations

from typing import TYPE_CHECKING

from cleaner.egress.protocols import provider_error

if TYPE_CHECKING:
    from cleaner.core.pipeline import OutgoingContext
    from cleaner.egress.cloud import Connection


def request(ctx: OutgoingContext, connection: Connection) -> tuple[str, dict[str, str], dict]:
    messages = [{"role": "system", "content": ctx.system}] if ctx.system else []
    messages += [{"role": message.role, "content": message.text} for message in ctx.messages]
    body = {
        **connection.extra_body, "model": ctx.model, "messages": messages,
        "max_tokens": connection.max_tokens, "stream": True,
    }
    return f"{connection.base_url.rstrip('/')}/chat/completions", {}, body


def text(event: dict) -> str | None:
    """Фрагмент ответа. Рассуждения модели (reasoning_content у DeepSeek) не показываются."""
    if "error" in event:
        raise provider_error(event["error"])
    choices = event.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return None
    content = (choices[0].get("delta") or {}).get("content")
    return content if isinstance(content, str) and content else None


def stopped_by_length(event: dict) -> bool:
    choices = event.get("choices") or []
    return bool(choices) and isinstance(choices[0], dict) and choices[0].get("finish_reason") == "length"
