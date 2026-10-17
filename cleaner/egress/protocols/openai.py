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
    body = {**connection.extra_body, "model": ctx.model, "messages": messages, "stream": True}
    # Рассуждающие модели OpenAI отвергают max_tokens и ждут max_completion_tokens: если он (или max_tokens) задан в
    # дополнительных параметрах подключения, предел подключения не дописывается.
    if "max_completion_tokens" not in body and "max_tokens" not in body:
        body["max_tokens"] = connection.max_tokens
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


def finished(event: dict) -> bool:
    """Провайдер назвал причину остановки: ответ кончился, а не оборвался."""
    choices = event.get("choices") or []
    return bool(choices) and isinstance(choices[0], dict) and bool(choices[0].get("finish_reason"))


def stopped_by_length(event: dict) -> bool:
    choices = event.get("choices") or []
    return bool(choices) and isinstance(choices[0], dict) and choices[0].get("finish_reason") == "length"
