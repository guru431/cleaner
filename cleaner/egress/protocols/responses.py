"""OpenAI Responses: POST {адрес}/responses, ответ — события response.output_text.delta, конец — response.completed
(план 5В: подключения OpenAI API и моделей OpenCode Go, которые отвечают только на /v1/responses)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from cleaner.egress.protocols import provider_error

if TYPE_CHECKING:
    from cleaner.core.pipeline import OutgoingContext
    from cleaner.egress.cloud import Connection


def request(ctx: OutgoingContext, connection: Connection) -> tuple[str, dict[str, str], dict]:
    # Системная часть — сообщением developer; ответ у провайдера не хранится (store: false).
    items = [{"role": "developer", "content": ctx.system}] if ctx.system else []
    items += [{"role": message.role, "content": message.text} for message in ctx.messages]
    body = {**connection.extra_body, "model": ctx.model, "input": items, "stream": True, "store": False}
    if "max_output_tokens" not in body:
        body["max_output_tokens"] = connection.max_tokens
    return f"{connection.base_url.rstrip('/')}/responses", {}, body


def text(event: dict) -> str | None:
    """Фрагмент ответа. Рассуждения (reasoning_*) не показываются."""
    kind = event.get("type")
    if kind == "error":
        raise provider_error({"code": event.get("code"), "message": event.get("message")})
    if kind == "response.failed":
        raise provider_error((event.get("response") or {}).get("error"))
    if kind == "response.output_text.delta":
        delta = event.get("delta")
        return delta if isinstance(delta, str) and delta else None
    return None


def finished(event: dict) -> bool:
    return event.get("type") in ("response.completed", "response.incomplete")


def stopped_by_length(event: dict) -> bool:
    details = (event.get("response") or {}).get("incomplete_details") or {}
    return event.get("type") == "response.incomplete" and details.get("reason") == "max_output_tokens"
