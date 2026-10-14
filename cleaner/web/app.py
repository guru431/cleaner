"""Сборка веб-приложения: маршруты, заголовки безопасности, страницы ошибок."""
from __future__ import annotations

import logging
from datetime import timezone, tzinfo
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cleaner.clock import Clock
from cleaner.service import ChatService
from cleaner.storage.repo import Repository
from cleaner.web import auth, routes_auth, routes_chats, routes_review, routes_settings
from cleaner.web.deps import MAX_BODY_BYTES, LoginRequired, page

log = logging.getLogger("cleaner.web")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
# Только по TLS: браузер запомнит, что этот узел открывается лишь по HTTPS. Без includeSubDomains.
HSTS = "max-age=31536000"
_STATUS_TEXT = {404: "Страница не найдена", 405: "Такое действие здесь не поддерживается"}


class BodyLimit:
    """Предел тела запроса для всех маршрутов, вход тоже. Считаются принятые байты, а не заголовок
    Content-Length: у тела, присланного частями (chunked), этого заголовка нет."""

    def __init__(self, app: ASGIApp, limit: int = MAX_BODY_BYTES):
        self.app = app
        self.limit = limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        received = 0

        async def limited() -> Message:
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > self.limit:
                raise StarletteHTTPException(413, "Слишком большой запрос")
            return message

        await self.app(scope, limited, send)


def create_app(
    repo: Repository, clock: Clock, *, secure_cookies: bool, max_text_chars: int = 500_000, tz: tzinfo = timezone.utc
) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.repo = repo
    app.state.clock = clock
    app.state.service = ChatService(repo, max_text_chars)
    app.state.throttle = auth.Throttle(clock)
    app.state.secure_cookies = secure_cookies
    app.state.tz = tz
    app.mount("/static", StaticFiles(directory=Path(__file__).with_name("static")), name="static")
    app.include_router(routes_auth.router)
    app.include_router(routes_chats.router)
    app.include_router(routes_review.router)
    app.include_router(routes_settings.router)

    @app.exception_handler(LoginRequired)
    async def to_login(request: Request, exc: LoginRequired) -> Response:
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        message = _STATUS_TEXT.get(exc.status_code, exc.detail)
        return page(request, "error.html", None, status_code=exc.status_code, code=exc.status_code, message=message)

    @app.exception_handler(RequestValidationError)
    async def bad_request(request: Request, exc: RequestValidationError) -> Response:
        # Стандартный ответ FastAPI повторяет присланные значения — здесь их нет.
        return page(request, "error.html", None, status_code=400, code=400, message="Неверный запрос")

    # Раньше guard: так предел оказывается внутри него, и отказ 413 доходит до обработчика ошибок.
    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def guard(request: Request, call_next) -> Response:
        try:
            response = await call_next(request)
        except Exception as exc:
            # Только вид ошибки и путь: в тексте исключения может оказаться текст пользователя (SEC-11).
            log.error("ошибка %s при %s %s", type(exc).__name__, request.method, request.url.path)
            repo.audit("error", kind=type(exc).__name__, path=request.url.path)
            response = page(
                request, "error.html", None, status_code=500, code=500,
                message="Внутренняя ошибка. Текст не обработан и никуда не передан.",
            )
        response.headers.update(SECURITY_HEADERS)
        if secure_cookies:
            response.headers["Strict-Transport-Security"] = HSTS
        return response

    return app
