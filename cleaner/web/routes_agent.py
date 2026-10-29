"""Шлюз для агентов, протокол Anthropic Messages (спецификация 2026-10-28, разделы 8, 9.1, 12): Claude Code и другие
агенты задают ANTHROPIC_BASE_URL=https://<cleaner>:5464/agent/anthropic. Открывается только ключом доступа с доступом к
модели; ошибки — в виде Anthropic (обработчики — app.py)."""
from __future__ import annotations

import asyncio
import json
import zlib
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import Executor

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from cleaner.agent_service import AgentCall, AgentRefused, AgentReply, AgentService
from cleaner.web.deps import AGENT_BODY_BYTES, ApiCaller, get_api_caller, repo_of

router = APIRouter(prefix="/agent/anthropic")
MAX_BODY = AGENT_BODY_BYTES         # и после распаковки (8.2)
_END = object()


def _refused(status: int, message: str) -> AgentRefused:
    return AgentRefused(status, "request_too_large" if status == 413 else "invalid_request_error", f"Cleaner: {message}")


def _inflate(raw: bytes, encoding: str) -> bytes:
    """gzip и deflate (zlib или без обёртки) с пределом распакованного: сжатая «бомба» не распаковывается целиком."""
    for wbits in ((31,) if encoding == "gzip" else (15, -15)):
        decoder = zlib.decompressobj(wbits)
        try:
            out = decoder.decompress(raw, MAX_BODY + 1)
        except zlib.error:
            continue
        if len(out) > MAX_BODY or decoder.unconsumed_tail:
            raise _refused(413, f"тело запроса после распаковки больше {MAX_BODY // (1024 * 1024)} МиБ")
        return out
    raise _refused(400, "тело запроса не распаковывается")


async def _body(request: Request) -> dict:
    raw = await request.body()          # сжатое тело ограничивает app.BodyLimit
    encoding = request.headers.get("content-encoding", "").strip().lower()
    if encoding in ("gzip", "deflate"):
        raw = _inflate(raw, encoding)
    elif encoding not in ("", "identity"):
        raise AgentRefused(
            415, "invalid_request_error", "Cleaner: такое сжатие тела не поддерживается — выключите его в агенте или выберите gzip",
        )
    try:
        body = json.loads(raw)
        # Строка с «\ud800» без пары — допустимый JSON, но её не записать ни в базу, ни в запрос к провайдеру.
        json.dumps(body, ensure_ascii=False).encode("utf-8")
    except (ValueError, UnicodeEncodeError, RecursionError):
        raise _refused(400, "тело запроса — не JSON в UTF-8") from None
    if not isinstance(body, dict):
        raise _refused(400, "тело запроса — не объект JSON")
    return body


def _agent(request: Request) -> AgentService:
    return request.app.state.agent


async def _in_pool(pool: Executor, events: Iterator[bytes]) -> AsyncIterator[bytes]:
    """Поток ответа читается в пуле шлюза, а не в общем; агент закрыл соединение — генератор закрывается там же, и журнал
    out и событие agent_send записываются."""
    loop = asyncio.get_running_loop()
    try:
        while (chunk := await loop.run_in_executor(pool, next, events, _END)) is not _END:
            yield chunk
    finally:
        await loop.run_in_executor(pool, events.close)


async def _handle(request: Request, caller: ApiCaller, path: str) -> Response:
    body = await _body(request)
    call = AgentCall(
        caller.key, caller.user, "anthropic", path, request.url.query, dict(request.headers.items()), body,
    )
    pool = request.app.state.agent_pool
    reply: AgentReply = await asyncio.get_running_loop().run_in_executor(pool, _agent(request).handle, call)
    if reply.events is not None:
        return StreamingResponse(_in_pool(pool, reply.events), status_code=reply.status, headers=reply.headers)
    return Response(reply.body or b"", status_code=reply.status, headers=reply.headers)


@router.post("/v1/messages")
async def messages(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    return await _handle(request, caller, "/v1/messages")


@router.post("/v1/messages/count_tokens")
async def count_tokens(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Та же очистка; провайдер без этого маршрута отвечает 404, и Claude Code считает сам (9.1)."""
    return await _handle(request, caller, "/v1/messages/count_tokens")


@router.get("/v1/models")
def models(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Модели ключа, а если у ключа их нет в списке — все модели подключения."""
    kind, _, provider_id = (caller.key.upstream or "").partition(":")
    provider = repo_of(request).provider(provider_id) if kind == "provider" else None
    if provider is None:
        raise AgentRefused(403, "permission_error", "Cleaner: у ключа нет доступа к модели — он только для /api/v1")
    names = list(caller.key.models or provider.models)
    data = [{"type": "model", "id": name, "display_name": name, "created_at": "1970-01-01T00:00:00Z"} for name in names]
    return JSONResponse({
        "data": data, "has_more": False, "first_id": names[0] if names else None, "last_id": names[-1] if names else None,
    })


@router.api_route("/api/hello", methods=["GET", "HEAD"], status_code=204)
def hello() -> Response:
    """Проверка связи Claude Code при запуске (HEAD) — без ключа и без обращения к провайдеру."""
    return Response(status_code=204)
