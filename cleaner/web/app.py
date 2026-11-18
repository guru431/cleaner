"""Сборка веб-приложения: маршруты, заголовки безопасности, страницы ошибок."""
from __future__ import annotations

import asyncio
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import timezone, tzinfo
from http import HTTPStatus
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cleaner.agent_service import PRUNE_EVERY, AgentRefused, AgentService
from cleaner.clock import Clock
from cleaner.egress import cloud, forward
from cleaner.queueing import QueueFull
from cleaner.service import ChatService
from cleaner.storage.repo import Repository
from cleaner.web import (
    auth, routes_agent, routes_api, routes_auth, routes_chats, routes_keys, routes_review, routes_send, routes_settings,
)
from cleaner.web.deps import AGENT_BODY_BYTES, MAX_BODY_BYTES, LoginRequired, Viewer, get_viewer, page
from cleaner.web.drain import AgentExecutor, UpdateDrain
from cleaner.web.jobs import FILE_INTERRUPTED, INTERRUPTED, Jobs, shutdown

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
_INTERNAL = "Внутренняя ошибка. Текст не обработан и никуда не передан."
SEND_WORKERS = 4
# Распознавание сканов ждёт шлюз, а не процессор; запросов распознавания одновременно столько же, сколько было
# при общем пуле, — служба OCR сервера держит ограниченную очередь.
FILE_WORKERS = 2
# Шлюз агентов — свой пул (спецификация 2026-10-28, раздел 13): запросы агентов не ждут за очисткой текстов интерфейса и
# отправками чата, и наоборот. Поток держится и всё время ответа провайдера.
AGENT_WORKERS = 8


_UPLOAD_HEADROOM = 1024 * 1024      # поля формы и заголовки частей multipart сверх самого файла
# Пауза в приёме тела запроса: дольше без единого куска — 408, и резерв бюджета отпущен. У uvicorn своего срока приёма
# тела нет. Срок на паузу, а не на всё тело: медленная, но идущая загрузка большого файла не обрывается. 60 с — как
# client_body_timeout у nginx: живой клиент столько не молчит посреди тела.
BODY_PAUSE = 60.0
# Резерв входного бюджета берётся до проверки входа и ключа, поэтому — под адресом клиента с личным пределом в четверть
# общего бюджета (512 МиБ): зависшие тела с одного узла не занимают весь бюджет, и вход, ввод текста и /api/v1
# остальных принимаются. Четверти хватает на четыре запроса агента по 32 МиБ.
ADDRESS_BODY_BYTES = 128 * 1024 * 1024
# Форма входа — логин, пароль и токен формы. 64 КиБ uvicorn и так держит в буфере каждого соединения (предел управления
# потоком), поэтому вход общий бюджет не резервирует и при занятом бюджете не получает 503.
LOGIN_BODY_BYTES = 64 * 1024
_UPLOAD_PATH = re.compile(r"(?:/chats/[^/]+/upload|/api/v1/chats/[^/]+/files)")
_CERT_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----", re.DOTALL)


class AgentSlots:
    """Одновременные запросы агентов (POST /agent/…) — от приёма тела до конца потока ответа. Поток ответа держится
    минуты; без своего предела 16 таких запросов занимали общий входной бюджет, и вход и /api/v1 отвечали 503.
    Сверх предела — сразу 429 в виде протокола агента: агент повторит по Retry-After. Счётчики читает панель
    состояния: busy — занято сейчас, refused — отказов с запуска службы. Только цикл событий — замок не нужен."""

    def __init__(self, limit: int):
        self.limit = limit
        self.busy = 0
        self.refused = 0

    def acquire(self) -> bool:
        if self.busy >= self.limit:
            self.refused += 1
            return False
        self.busy += 1
        return True

    def release(self) -> None:
        self.busy -= 1


def _agent_busy(scope: Scope, limit: int) -> Response:
    message = f"шлюз агентов занят: одновременно идут {limit} запросов, повторите позже"
    headers = {"Retry-After": "5"}
    if scope["path"].startswith("/agent/openai/"):
        return _openai_error(429, message, headers)
    return _agent_error(429, message, headers)


def _declared_length(scope: Scope) -> int | None:
    """Заголовок Content-Length, если он есть и это число; у тела частями (chunked) его нет."""
    for name, value in scope.get("headers", ()):
        if name == b"content-length":
            return int(value) if value.isdigit() else None
    return None


class BodyLimit:
    """Предел тела запроса для всех маршрутов, вход тоже. Считаются принятые байты, а не заголовок
    Content-Length: у тела, присланного частями (chunked), этого заголовка нет.

    Резерв общего бюджета — объём из Content-Length (без него — предел маршрута), под адресом клиента
    (ADDRESS_BODY_BYTES) и только на время приёма тела: принятое тело дальше ограничивают очередь заданий и предел
    запросов агентов (AgentSlots), а не бюджет. Пауза в приёме тела дольше BODY_PAUSE — отказ 408."""

    def __init__(self, app: ASGIApp, limit: int = MAX_BODY_BYTES):
        self.app = app
        self.limit = limit

    def _limit(self, scope: Scope) -> int:
        """У загрузки файла (страница и /api/v1) свой предел — max_file_mb (FR-2.2); у шлюза агентов — 32 МиБ (вся
        история разговора); у входа — LOGIN_BODY_BYTES; у остальных запросов — общий."""
        if scope["path"].startswith("/agent/"):
            return AGENT_BODY_BYTES
        if scope["path"] == "/login":
            return LOGIN_BODY_BYTES
        if _UPLOAD_PATH.fullmatch(scope["path"]):
            return scope["app"].state.max_file_bytes + _UPLOAD_HEADROOM
        return self.limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        received = 0
        limit = self._limit(scope)
        reservation = None
        complete = False

        async def limited() -> Message:
            nonlocal received, complete
            if complete:
                return await receive()          # после тела ответ ждёт разрыва соединения минутами: без срока
            try:
                async with asyncio.timeout(BODY_PAUSE):
                    message = await receive()
            except TimeoutError:
                raise StarletteHTTPException(408, "Тело запроса не пришло вовремя") from None
            received += len(message.get("body", b""))
            if received > limit:
                raise StarletteHTTPException(413, "Слишком большой запрос")
            if message["type"] == "http.disconnect" or not message.get("more_body", False):
                complete = True
                if reservation:
                    reservation.release()       # тело принято целиком: поток ответа резерв не держит
            return message

        writing = scope.get("method") in ("POST", "PUT", "PATCH")
        slots = scope["app"].state.agent_slots if writing and scope["path"].startswith("/agent/") else None
        if slots is not None and not slots.acquire():
            await _agent_busy(scope, slots.limit)(scope, receive, send)
            return
        try:
            if writing and not _UPLOAD_PATH.fullmatch(scope["path"]) and scope["path"] != "/login":
                # FastAPI читает JSON до проверки dependency ключа. Общий входной бюджет нужен уже здесь:
                # число и объём синхронных API-запросов ограничены и до их разбора, не только у service.add_*.
                # Тело сверх заявленного (заголовок вместе с chunked) — тоже отказ 413: резерв меньше принятого не бывает.
                declared = _declared_length(scope)
                limit = limit if declared is None else min(declared, limit)
                client = scope.get("client")
                address = f"адрес {client[0] if client else ''}"
                try:
                    reservation = scope["app"].state.jobs.budget.reserve(
                        address, limit, count=0, user_bytes=ADDRESS_BODY_BYTES)
                except QueueFull as exc:
                    await _queue_error(Request(scope), exc)(scope, receive, send)
                    return
            try:
                await self.app(scope, limited, send)
            finally:
                if reservation:
                    reservation.release()
        finally:
            if slots is not None:
                slots.release()


def _for_program(request: Request) -> bool:
    """Запрос программы: ошибки — JSON, а не страница (спецификация 2026-10-28, раздел 15)."""
    return request.url.path.startswith("/api/")


def _json_error(code: int, message: str, headers: dict[str, str] | None = None) -> Response:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=code, headers=headers)


def _for_agent(request: Request) -> bool:
    """Запрос агента: ошибки — в виде протокола Anthropic (спецификация 2026-10-28, раздел 12)."""
    return request.url.path.startswith("/agent/anthropic/")


_AGENT_KINDS = {
    400: "invalid_request_error", 401: "authentication_error", 403: "permission_error", 404: "not_found_error",
    413: "request_too_large", 415: "invalid_request_error", 429: "rate_limit_error", 503: "overloaded_error",
}


def _cleaner_message(message: str) -> str:
    """Сообщение начинается с «Cleaner:» — агент показывает его пользователю, и видно, кто отказал."""
    return message if message.startswith("Cleaner:") else f"Cleaner: {message[:1].lower()}{message[1:]}"


def _agent_error(code: int, message: str, headers: dict[str, str] | None = None, kind: str = "") -> Response:
    error = {"type": kind or _AGENT_KINDS.get(code, "api_error"), "message": _cleaner_message(message)}
    return JSONResponse({"type": "error", "error": error}, status_code=code, headers=headers)


def _for_openai_agent(request: Request) -> bool:
    """Запрос агента по протоколам OpenAI: ошибки — в виде OpenAI (спецификация 2026-10-28, раздел 12)."""
    return request.url.path.startswith("/agent/openai/")


_OPENAI_KINDS = {
    400: "invalid_request_error", 401: "authentication_error", 403: "permission_error", 404: "not_found_error",
    405: "invalid_request_error", 413: "invalid_request_error", 415: "invalid_request_error", 429: "rate_limit_error",
}


def _openai_error(code: int, message: str, headers: dict[str, str] | None = None) -> Response:
    kind = _OPENAI_KINDS.get(code, "server_error" if code >= 500 else "invalid_request_error")
    error = {"message": _cleaner_message(message), "type": kind, "code": None}
    return JSONResponse({"error": error}, status_code=code, headers=headers)


def _signed_in(request: Request) -> Viewer | None:
    """Вошедший — для шапки страницы ошибки (меню, тема, выход). Нет сессии или её не прочитать (ошибка могла случиться
    в самой базе) — страница без шапки, как вход."""
    try:
        return get_viewer(request)
    except Exception:
        return None


# Разделы настроек со своей страницей: ошибка формы раздела возвращает к нему.
_SETTINGS_PAGES = frozenset({"providers", "local-llm", "policies", "dictionary", "patterns", "builtin", "gold", "users", "audit"})


def _back(request: Request, viewer: Viewer | None) -> tuple[str, str] | None:
    """Куда вернуться со страницы ошибки, кроме списка чатов. Адреса, откуда пришли, браузер не присылает
    (Referrer-Policy: no-referrer), поэтому — по пути запроса: свой чат, раздел настроек, ключи, своя страница.
    Та же страница, что открывалась (GET), — не ссылка: там та же ошибка."""
    if viewer is None:
        return None
    path = request.url.path
    parts = path.strip("/").split("/")
    if parts[0] == "chats" and len(parts) > 1:
        chat = request.app.state.repo.chat(parts[1])
        if chat is None or chat.user_id != viewer.user.id:
            return None
        target, label = f"/chats/{parts[1]}", "Вернуться в чат"
    elif parts[0] == "settings" and viewer.is_admin:
        section = parts[1] if len(parts) > 1 and parts[1] in _SETTINGS_PAGES else ""
        target, label = f"/settings/{section}".rstrip("/"), "Вернуться в настройки"
    elif parts[0] == "keys":
        target, label = "/keys", "Вернуться к ключам"
    elif parts[0] == "account" and len(parts) > 1:
        target, label = f"/account/{parts[1]}", "Вернуться"
    else:
        return None
    return None if request.method == "GET" and path == target else (target, label)


def _error_page(request: Request, status: int, message: str) -> Response:
    """Страница ошибки с шапкой вошедшего. Не собралась шапка (внутренняя ошибка могла быть в ней) — без шапки."""
    viewer = _signed_in(request)
    if viewer is not None:
        try:
            return page(request, "error.html", viewer, status_code=status, code=status, message=message,
                        back=_back(request, viewer))
        except Exception:
            pass
    return page(request, "error.html", None, status_code=status, code=status, message=message, back=None)


def _queue_error(request: Request, exc: QueueFull) -> Response:
    headers = {"Retry-After": str(exc.retry_after)}
    if _for_openai_agent(request):
        return _openai_error(exc.status, str(exc), headers)
    if _for_agent(request):
        return _agent_error(exc.status, str(exc), headers)
    if _for_program(request):
        return _json_error(exc.status, str(exc), headers)
    response = _error_page(request, exc.status, str(exc))
    response.headers.update(headers)
    return response


class UpdateAdmission:
    """Считает весь HTTP-запрос до отдачи последней части ответа, включая SSE."""

    def __init__(self, app: ASGIApp, drain: UpdateDrain, secure: bool):
        self.app, self.drain, self.secure = app, drain, secure

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"].startswith("/static/"):
            await self.app(scope, receive, send)
            return
        if self.drain.client is not None:
            request = Request(scope)
            message = "Служба готовится к обновлению. Повторите запрос позже."
            if _for_openai_agent(request):
                response = _openai_error(503, message)
            elif _for_agent(request):
                response = _agent_error(503, message)
            elif _for_program(request):
                response = _json_error(503, message)
            else:
                response = page(request, "error.html", None, status_code=503, code=503, message=message, back=None)
            response.headers.update(SECURITY_HEADERS)
            response.headers["Retry-After"] = "5"
            if self.secure:
                response.headers["Strict-Transport-Security"] = HSTS
            await response(scope, receive, send)
            return
        self.drain.requests += 1
        try:
            await self.app(scope, receive, send)
        finally:
            self.drain.requests -= 1


def _interrupt(repo: Repository) -> None:
    """Всё, что осталось в очереди или в работе, — отказ «прервано» с кнопкой повтора (NFR-6)."""
    interrupted = repo.fail_interrupted(INTERRUPTED, FILE_INTERRUPTED)
    if interrupted:
        repo.audit("jobs_interrupted", count=interrupted)


def create_app(
    repo: Repository, clock: Clock, *, secure_cookies: bool, max_text_chars: int = 500_000,
    tz: tzinfo = timezone.utc, engines: Any = None, jobs: Jobs | None = None, max_file_mb: int = 50,
    sends: Jobs | None = None, cloud_send: Any = None, files: Jobs | None = None, measures: Jobs | None = None,
    cert_file: str = "",
) -> FastAPI:
    jobs = jobs or Jobs()
    # Отправки облаку и разбор файлов — свои пулы: скан идёт минуту на страницу, и в общем пуле из двух потоков
    # два скана держали бы десятки минут и ответы облака, и каждый вставленный текст (раздел 14).
    sends = sends or Jobs(ThreadPoolExecutor(max_workers=SEND_WORKERS, thread_name_prefix="cleaner-send"))
    files = files or Jobs(ThreadPoolExecutor(max_workers=FILE_WORKERS, thread_name_prefix="cleaner-file"))
    # Замер эталонного набора идёт минуты и в общем пуле занял бы поток очистки текстов пользователей.
    measures = measures or Jobs(ThreadPoolExecutor(max_workers=1, thread_name_prefix="cleaner-eval"))
    for pool in (jobs, sends, files, measures):
        pool.budget = jobs.budget
        pool.now = clock.now
    service = ChatService(
        repo, max_text_chars, engines, submit=jobs.submit, send_submit=sends.submit, cloud_send=cloud_send or cloud.send,
        file_submit=files.submit, budget=jobs.budget,
    )
    agent_pool = AgentExecutor(AGENT_WORKERS)
    update = UpdateDrain(jobs.budget, agent_pool, os.environ.get("CLEANER_DRAIN_SOCKET", ""))
    agent = AgentService(repo, engines, clock)

    async def prune_agent_until(stopping: asyncio.Event) -> None:
        while not stopping.is_set():
            try:
                await asyncio.to_thread(agent._prune)
            except Exception as exc:
                log.error("Agent retention cleanup failed: kind=%s", type(exc).__name__)
            try:
                await asyncio.wait_for(stopping.wait(), timeout=PRUNE_EVERY.total_seconds())
            except TimeoutError:
                continue

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with update.listen():
            stopping = asyncio.Event()
            retention = asyncio.create_task(prune_agent_until(stopping))
            try:
                yield
            finally:
                stopping.set()
                await retention
        agent_pool.shutdown(wait=False, cancel_futures=True)       # ответы агентам рвутся с остановкой; агент повторит
        forward.close_clients()                                     # соединения с провайдерами
        # Остановка: соединение с базой закрывается после этого (__main__). Недождавшиеся задания помечаются
        # здесь, пока оно открыто, — а не случайной ошибкой записи в закрытую базу и пометкой при следующем старте.
        # Их потоки процесс не ждёт: по SIGTERM uvicorn сразу после этого повторяет сигнал, и процесс кончается,
        # а если uvicorn.run вернулся (Ctrl+C), serve выходит по unfinished_jobs, закрыв базу (раздел 14).
        service.live.cancel_all()            # идущие ответы облака сохраняются неполными
        app.state.unfinished_jobs = shutdown(jobs, sends, files, measures)
        _interrupt(repo)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.repo = repo
    app.state.issued_keys = routes_keys.IssuedKeys(clock, repo.global_key)
    app.state.manual_copies = routes_send.ManualCopies(clock)
    app.state.clock = clock
    app.state.engines = engines                      # cleaner.engines.Engines; в тестах — заглушка
    app.state.jobs = jobs
    app.state.job_pools = (jobs, files, sends, measures)
    app.state.measures = measures
    # Состояние замера — в памяти процесса: после перезапуска прерванного замера нет, а итог пишет само задание.
    app.state.measure = {"status": "idle"}
    app.state.unfinished_jobs = 0                    # сколько заданий остановка не дождалась (lifespan)
    app.state.max_file_bytes = max_file_mb * 1024 * 1024
    app.state.service = service
    app.state.agent = agent
    app.state.agent_pool = agent_pool
    app.state.agent_slots = AgentSlots(AGENT_WORKERS)
    app.state.throttle = auth.Throttle(clock)
    app.state.key_throttle = auth.Throttle(clock)            # неверные ключи доступа — по адресу клиента
    app.state.secure_cookies = secure_cookies
    app.state.tz = tz
    app.state.cert_file = cert_file                  # сертификат TLS службы; пусто — без TLS
    _interrupt(repo)            # служба одна, очередь в памяти: всё «в работе» прервано (остановка без lifespan, сбой)
    routes_settings.apply_suffixes(repo)        # внутренние суффиксы, добавленные на странице встроенных списков
    app.mount("/static", StaticFiles(directory=Path(__file__).with_name("static")), name="static")
    app.include_router(routes_auth.router)
    app.include_router(routes_chats.router)
    app.include_router(routes_review.router)
    app.include_router(routes_send.router)
    app.include_router(routes_settings.router)
    app.include_router(routes_keys.router)
    app.include_router(routes_api.router)
    app.include_router(routes_agent.router)
    app.include_router(routes_agent.openai_router)

    @app.get("/cert.pem")
    def service_cert() -> Response:
        """Сертификат службы для агентов (план 5Г) — без входа: то же, что любой клиент получает при TLS-соединении
        (второе исключение AC-1.11). Только блоки сертификата: ключ TLS не отдаётся, даже если он с сертификатом в одном
        файле."""
        if not app.state.cert_file:
            raise StarletteHTTPException(404)
        blocks = _CERT_BLOCK.findall(Path(app.state.cert_file).read_bytes())
        if not blocks:
            raise StarletteHTTPException(404)
        return Response(
            b"".join(block + b"\n" for block in blocks), media_type="application/x-pem-file",
            headers={"content-disposition": 'attachment; filename="cleaner-cert.pem"'},
        )

    @app.exception_handler(LoginRequired)
    async def to_login(request: Request, exc: LoginRequired) -> Response:
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(QueueFull)
    async def queue_full(request: Request, exc: QueueFull) -> Response:
        return _queue_error(request, exc)

    @app.exception_handler(AgentRefused)
    async def agent_refused(request: Request, exc: AgentRefused) -> Response:
        if _for_openai_agent(request):
            return _openai_error(exc.status, exc.message, exc.headers)
        return _agent_error(exc.status, exc.message, exc.headers, exc.kind)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if _for_agent(request) or _for_openai_agent(request):
            detail = str(exc.detail)
            standard = detail == HTTPStatus(exc.status_code).phrase
            message = _STATUS_TEXT.get(exc.status_code, detail) if standard else detail
            if _for_openai_agent(request):
                return _openai_error(exc.status_code, message, exc.headers)
            return _agent_error(exc.status_code, message, exc.headers)
        if _for_program(request):
            # Своё сообщение маршрута («Чат не найден») — как есть; стандартное английское Starlette — по-русски.
            standard = exc.detail == HTTPStatus(exc.status_code).phrase
            message = _STATUS_TEXT.get(exc.status_code, exc.detail) if standard else exc.detail
            return _json_error(exc.status_code, message, exc.headers)
        # Странице — так же: причина маршрута («Текст не найден») видна, стандартная фраза Starlette — по-русски.
        standard = exc.detail == HTTPStatus(exc.status_code).phrase
        return _error_page(request, exc.status_code, _STATUS_TEXT.get(exc.status_code, exc.detail) if standard else exc.detail)

    @app.exception_handler(RequestValidationError)
    async def bad_request(request: Request, exc: RequestValidationError) -> Response:
        # Стандартный ответ FastAPI повторяет присланные значения — здесь их нет.
        if _for_openai_agent(request):
            return _openai_error(400, "Неверный запрос")
        if _for_agent(request):
            return _agent_error(400, "Неверный запрос")
        if _for_program(request):
            return _json_error(422, "Неверный запрос")
        return _error_page(request, 400, "Неверный запрос")

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
            if _for_openai_agent(request):
                response = _openai_error(500, "внутренняя ошибка, запрос не отправлен")
            elif _for_agent(request):
                response = _agent_error(500, "внутренняя ошибка, запрос не отправлен")
            elif _for_program(request):
                response = _json_error(500, _INTERNAL)
            else:
                response = _error_page(request, 500, _INTERNAL)
        response.headers.update(SECURITY_HEADERS)
        if secure_cookies:
            response.headers["Strict-Transport-Security"] = HSTS
        return response

    app.add_middleware(UpdateAdmission, drain=update, secure=secure_cookies)
    return app
