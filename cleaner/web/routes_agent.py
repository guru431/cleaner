"""Шлюз для агентов (спецификация 2026-10-28, разделы 8, 9, 12). Anthropic Messages: Claude Code и другие агенты задают
ANTHROPIC_BASE_URL=https://<cleaner>:5464/agent/anthropic. OpenAI Chat Completions и Responses: OpenCode, Codex, SDK
OpenAI — base_url https://<cleaner>:5464/agent/openai/v1. Открывается только ключом доступа с доступом к модели;
ошибки — в виде протокола (обработчики — app.py)."""
from __future__ import annotations

import asyncio
import functools
import json
import zlib
from collections.abc import AsyncIterator, Callable
from concurrent.futures import Executor, Future

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Receive, Scope, Send

from cleaner.agent_service import SUBSCRIPTIONS, AgentCall, AgentRefused, AgentReply, AgentService
from cleaner.web.deps import AGENT_BODY_BYTES, ApiCaller, get_api_caller, repo_of

router = APIRouter(prefix="/agent/anthropic")
openai_router = APIRouter(prefix="/agent/openai")
MAX_BODY = AGENT_BODY_BYTES         # и после распаковки (8.2)
MAX_DEPTH = 64                      # обходы очистки рекурсивны: тело у предела разбора JSON уронило бы их (500)
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


def _too_deep(value: object) -> bool:
    """Объекты и списки вложены глубже MAX_DEPTH (само тело — уровень 1); обход без рекурсии. В стек — только объекты и
    списки: плоский массив под пределом тела иначе стоил бы секунды цикла событий и гигабайт памяти."""
    stack = [(value, 1)] if isinstance(value, (dict, list)) else []
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            return True
        children = node.values() if isinstance(node, dict) else node
        stack.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    return False


async def _body(request: Request) -> dict:
    try:
        raw = await request.body()      # сжатое тело ограничивает app.BodyLimit
    except StarletteHTTPException as exc:
        if exc.status_code != 413:
            raise
        raise _refused(413, f"тело запроса больше {MAX_BODY // (1024 * 1024)} МиБ") from None     # отказ по телу (12)
    encoding = request.headers.get("content-encoding", "").strip().lower()
    if encoding in ("gzip", "deflate"):
        raw = _inflate(raw, encoding)
    elif encoding not in ("", "identity"):
        raise AgentRefused(
            415, "invalid_request_error", "Cleaner: такое сжатие тела не поддерживается — выключите его в агенте или выберите gzip",
        )
    try:
        body = json.loads(raw)
        if _too_deep(body):
            raise _refused(400, f"тело запроса вложено глубже {MAX_DEPTH} уровней")
        # Строка с «\ud800» без пары — допустимый JSON, но её не записать ни в базу, ни в запрос к провайдеру.
        json.dumps(body, ensure_ascii=False).encode("utf-8")
    except (ValueError, UnicodeEncodeError, RecursionError):
        raise _refused(400, "тело запроса — не JSON в UTF-8") from None
    if not isinstance(body, dict):
        raise _refused(400, "тело запроса — не объект JSON")
    return body


def _agent(request: Request) -> AgentService:
    return request.app.state.agent


class _Stream(StreamingResponse):
    """Поток ответа агенту. Агент ушёл раньше первого чтения (Starlette отменил отправку, пока шлюз очищал запрос или ждал
    заголовков провайдера): _in_pool не начинался, и поток закрывается здесь — в пуле, ждать в finally нельзя."""

    def __init__(self, pool: Executor, reply: AgentReply):
        self._pool, self._events, self._stop = pool, reply.events, reply.stop
        self._close: Callable[[], None] = reply.close or reply.events.close
        self._taken = False                     # закрытие взял на себя _in_pool
        super().__init__(self._in_pool(), status_code=reply.status, headers=reply.headers)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            if not self._taken:
                self._pool.submit(self._close)

    async def _in_pool(self) -> AsyncIterator[bytes]:
        """Поток ответа читается в пуле шлюза, а не в общем; агент закрыл соединение — поток закрывается там же, и журнал
        out и событие agent_send записываются.

        Агент ушёл, пока next ждёт провайдера: stop() рвёт соединение с провайдером, и поток пула свободен сразу, а не
        через 300 с. Поток закрывает тот же поток пула, когда начатый next вернётся (done-callback), — два потока в
        генераторе не бывают («generator already executing»). Next отменён, не начавшись (пул занят), — закрытие сразу.
        Ждать в finally нельзя: Starlette отменяет чтение областью anyio, и любой await там отменяется сразу."""
        self._taken = True
        pool, events, close = self._pool, self._events, self._close
        reading: Future | None = None
        try:
            while (chunk := await asyncio.wrap_future(reading := pool.submit(next, events, _END))) is not _END:
                yield chunk
            reading = None                          # генератор кончился сам
        finally:
            if reading is not None and not reading.done():
                if self._stop is not None:
                    self._stop()
                reading.add_done_callback(lambda _: close())
            elif reading is not None:
                pool.submit(close)


async def _handle(request: Request, caller: ApiCaller, path: str, protocol: str = "anthropic") -> Response:
    """path — путь у провайдера: у Anthropic — /v1/… к адресу без /v1, у OpenAI — к base_url, который кончается на /v1."""
    try:
        body = await _body(request)
    except AgentRefused:
        # Отказ по телу — тоже событие (раздел 12); запись — вне цикла событий: замок базы бывает занят очисткой.
        audit = functools.partial(repo_of(request).audit, "agent_refused", caller.user.id, key=caller.key.id, reason="body")
        await asyncio.get_running_loop().run_in_executor(None, audit)
        raise
    call = AgentCall(
        caller.key, caller.user, protocol, path, request.url.query, dict(request.headers.items()), body,
    )
    pool = request.app.state.agent_pool
    reply: AgentReply = await asyncio.get_running_loop().run_in_executor(pool, _agent(request).handle, call)
    if reply.events is not None:
        return _Stream(pool, reply)
    return Response(reply.body or b"", status_code=reply.status, headers=reply.headers)


@router.post("/v1/messages")
async def messages(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    return await _handle(request, caller, "/v1/messages")


@router.post("/v1/messages/count_tokens")
async def count_tokens(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Та же очистка; провайдер без этого маршрута отвечает 404, и Claude Code считает сам (9.1)."""
    return await _handle(request, caller, "/v1/messages/count_tokens")


def _model_names(request: Request, caller: ApiCaller) -> list[str]:
    """Модели ключа, а если у ключа их нет в списке — все модели подключения. У подписки списка нет: Claude Code и Codex
    его у шлюза не спрашивают (проверки 18.1a 5Б и 5В), а модели подписки знает провайдер."""
    if caller.key.upstream in SUBSCRIPTIONS:
        raise AgentRefused(404, "not_found_error", "Cleaner: у ключа с подпиской списка моделей нет")
    kind, _, provider_id = (caller.key.upstream or "").partition(":")
    provider = repo_of(request).provider(provider_id) if kind == "provider" else None
    if provider is None:
        raise AgentRefused(403, "permission_error", "Cleaner: у ключа нет доступа к модели — он только для /api/v1")
    return list(provider.allowed_models(caller.key.models))


@router.get("/v1/models")
def models(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    names = _model_names(request, caller)
    data = [{"type": "model", "id": name, "display_name": name, "created_at": "1970-01-01T00:00:00Z"} for name in names]
    return JSONResponse({
        "data": data, "has_more": False, "first_id": names[0] if names else None, "last_id": names[-1] if names else None,
    })


def _check(request: Request, caller: ApiCaller, family: str) -> Response:
    """Самопроверка агента (раздел 14): ключ, доступ, протокол, модель (?model=…), слои, TLS и доступность провайдера —
    без текста пользователя. Вход подписки — Authorization, если это не сам ключ Cleaner."""
    login = request.headers.get("authorization", "").strip().partition(" ")[2].strip()
    result = _agent(request).check(
        caller.key, caller.user, family, model=request.query_params.get("model", "")[:200],
        tls=request.url.scheme == "https", login=bool(login) and not login.startswith("ck_"),
    )
    return JSONResponse(result, headers={"cache-control": "no-store"})


@router.get("/v1/cleaner/check")
def anthropic_check(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    return _check(request, caller, "anthropic")


@openai_router.get("/v1/cleaner/check")
def openai_check(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    return _check(request, caller, "openai")


@router.api_route("/api/hello", methods=["GET", "HEAD"], status_code=204)
def hello() -> Response:
    """Проверка связи Claude Code при запуске (HEAD) — без ключа и без обращения к провайдеру."""
    return Response(status_code=204)


@openai_router.post("/v1/chat/completions")
async def chat_completions(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    return await _handle(request, caller, "/chat/completions", "chat")


@openai_router.post("/v1/responses")
async def responses(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Codex — только HTTP с потоком событий: у своего провайдера WebSocket он не открывает (проверка 18.1a 5В)."""
    return await _handle(request, caller, "/responses", "responses")


@openai_router.get("/v1/models")
def openai_models(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    data = [{"id": name, "object": "model", "created": 0, "owned_by": "cleaner"} for name in _model_names(request, caller)]
    return JSONResponse({"object": "list", "data": data})
