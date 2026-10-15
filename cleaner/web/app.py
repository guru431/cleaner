"""Сборка веб-приложения: маршруты, заголовки безопасности, страницы ошибок."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import timezone, tzinfo
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cleaner.clock import Clock
from cleaner.egress import cloud
from cleaner.service import ChatService
from cleaner.storage.repo import Repository
from cleaner.web import auth, routes_auth, routes_chats, routes_review, routes_send, routes_settings
from cleaner.web.deps import MAX_BODY_BYTES, LoginRequired, page
from cleaner.web.jobs import INTERRUPTED, Jobs

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
SEND_WORKERS = 4
# Распознавание сканов ждёт шлюз, а не процессор; запросов распознавания одновременно столько же, сколько было
# при общем пуле, — служба OCR сервера держит ограниченную очередь.
FILE_WORKERS = 2


_UPLOAD_HEADROOM = 1024 * 1024      # поля формы и заголовки частей multipart сверх самого файла


class BodyLimit:
    """Предел тела запроса для всех маршрутов, вход тоже. Считаются принятые байты, а не заголовок
    Content-Length: у тела, присланного частями (chunked), этого заголовка нет."""

    def __init__(self, app: ASGIApp, limit: int = MAX_BODY_BYTES):
        self.app = app
        self.limit = limit

    def _limit(self, scope: Scope) -> int:
        """У загрузки файла свой предел — max_file_mb (FR-2.2); у остальных запросов — общий."""
        if scope["path"].endswith("/upload"):
            return scope["app"].state.max_file_bytes + _UPLOAD_HEADROOM
        return self.limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        received = 0
        limit = self._limit(scope)

        async def limited() -> Message:
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > limit:
                raise StarletteHTTPException(413, "Слишком большой запрос")
            return message

        await self.app(scope, limited, send)


def _interrupt(repo: Repository) -> None:
    """Всё, что осталось в очереди или в работе, — отказ «прервано» с кнопкой повтора (NFR-6)."""
    interrupted = repo.fail_interrupted(INTERRUPTED)
    if interrupted:
        repo.audit("jobs_interrupted", count=interrupted)


def create_app(
    repo: Repository, clock: Clock, *, secure_cookies: bool, max_text_chars: int = 500_000,
    tz: tzinfo = timezone.utc, engines: Any = None, jobs: Jobs | None = None, max_file_mb: int = 50,
    sends: Jobs | None = None, cloud_send: Any = None, files: Jobs | None = None,
) -> FastAPI:
    jobs = jobs or Jobs()
    # Отправки облаку и разбор файлов — свои пулы: скан идёт минуту на страницу, и в общем пуле из двух потоков
    # два скана держали бы десятки минут и ответы облака, и каждый вставленный текст (раздел 14).
    sends = sends or Jobs(ThreadPoolExecutor(max_workers=SEND_WORKERS, thread_name_prefix="cleaner-send"))
    files = files or Jobs(ThreadPoolExecutor(max_workers=FILE_WORKERS, thread_name_prefix="cleaner-file"))
    service = ChatService(
        repo, max_text_chars, engines, submit=jobs.submit, send_submit=sends.submit, cloud_send=cloud_send or cloud.send,
        file_submit=files.submit,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        # Остановка: соединение с базой закрывается после этого (__main__). Недождавшиеся задания помечаются
        # здесь, пока оно открыто, — а не случайной ошибкой записи в закрытую базу и пометкой при следующем старте.
        service.live.cancel_all()            # идущие ответы облака сохраняются неполными
        jobs.shutdown()
        sends.shutdown()
        files.shutdown()
        _interrupt(repo)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.repo = repo
    app.state.clock = clock
    app.state.engines = engines                      # cleaner.engines.Engines; в тестах — заглушка
    app.state.jobs = jobs
    app.state.max_file_bytes = max_file_mb * 1024 * 1024
    app.state.service = service
    app.state.throttle = auth.Throttle(clock)
    app.state.secure_cookies = secure_cookies
    app.state.tz = tz
    _interrupt(repo)            # служба одна, очередь в памяти: всё «в работе» прервано (остановка без lifespan, сбой)
    app.mount("/static", StaticFiles(directory=Path(__file__).with_name("static")), name="static")
    app.include_router(routes_auth.router)
    app.include_router(routes_chats.router)
    app.include_router(routes_review.router)
    app.include_router(routes_send.router)
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
