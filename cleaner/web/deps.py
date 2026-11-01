"""Общее для маршрутов: вошедший пользователь, токен формы, страница по шаблону."""
from __future__ import annotations

import hmac
import io
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from cleaner.queueing import Reservation
from cleaner.service import ChatService
from cleaner.storage.repo import ApiKey, Chat, Repository, Session, User
from cleaner.web import auth

SESSION_COOKIE = "cleaner_session"
IDLE = timedelta(hours=8)
# Предел тела запроса (app.BodyLimit) и одного поля формы: 500 000 знаков даже четырёхбайтных —
# около 6 МБ в закодированной форме. У Starlette поле формы по умолчанию не больше 1 МБ.
MAX_BODY_BYTES = 8 * 1024 * 1024
# Тело запроса агента (спецификация 2026-10-28, 8.2): вся история разговора с прочитанными файлами — и до, и после
# распаковки. Постоянная, а не настройка agent_max_body_mb: менять её пока некому.
AGENT_BODY_BYTES = 32 * 1024 * 1024

templates = Jinja2Templates(directory=Path(__file__).with_name("templates"))


def _local(iso: str, tz: tzinfo) -> str:
    return datetime.fromisoformat(iso).astimezone(tz).strftime("%d.%m.%Y %H:%M")


templates.env.filters["local"] = _local


class LoginRequired(Exception):
    """Нет действующей сессии — на страницу входа."""


@dataclass(frozen=True)
class Viewer:
    user: User
    session: Session

    @property
    def is_admin(self) -> bool:
        return self.user.role == "admin"


def repo_of(request: Request) -> Repository:
    return request.app.state.repo


def service_of(request: Request) -> ChatService:
    return request.app.state.service


def own_chat(request: Request, chat_id: str, viewer: Viewer) -> Chat:
    """Чат вошедшего пользователя. Чужой и несуществующий неотличимы — 404 (FR-1.5)."""
    chat = repo_of(request).chat(chat_id)
    if chat is None or chat.user_id != viewer.user.id:
        raise HTTPException(404, "Чат не найден")
    return chat


AGENT_READ_ONLY = "Чат агента только для просмотра: в него пишет шлюз, правки распознавания — в таблице соответствий"


def writable_chat(request: Request, chat_id: str, viewer: Viewer) -> Chat:
    """Чат вошедшего пользователя, в который пишет он сам. Чат шлюза пишет только шлюз (спецификация 2026-10-28, 16):
    ввод, ответ, отправка, слои и подключение в нём — отказ 400."""
    chat = own_chat(request, chat_id, viewer)
    if chat.kind == "agent":
        raise HTTPException(400, AGENT_READ_ONLY)
    return chat


def get_viewer(request: Request) -> Viewer:
    repo = repo_of(request)
    token = request.cookies.get(SESSION_COOKIE, "")
    session = repo.session(auth.token_hash(token)) if token else None
    if session is None:
        raise LoginRequired()
    user = repo.user(session.user_id)
    idle = request.app.state.clock.now() - datetime.fromisoformat(session.last_seen_at)
    if user is None or user.disabled or idle > IDLE:
        repo.delete_session(session.token_hash)
        raise LoginRequired()
    repo.touch_session(session.token_hash)
    return Viewer(user, session)


@dataclass(frozen=True)
class ApiCaller:
    """Программа с действующим ключом доступа (FR-13.1) и его владелец."""

    user: User
    key: ApiKey


def _presented_key(request: Request) -> str:
    """X-Cleaner-Key, иначе Authorization: Bearer, иначе x-api-key (так ключ передаёт Claude Code и SDK Anthropic, 6.1).
    Из нескольких — первый вида ck_…: у агента с подпиской в Authorization — его собственный токен."""
    scheme, _, bearer = request.headers.get("authorization", "").strip().partition(" ")
    presented = [
        value.strip() for value in (
            request.headers.get("x-cleaner-key"), bearer if scheme.lower() == "bearer" else None,
            request.headers.get("x-api-key"),
        ) if value is not None
    ]
    return next((value for value in presented if value.startswith(auth.API_KEY_PREFIX)), presented[0] if presented else "")


def get_api_caller(request: Request) -> ApiCaller:
    """Ключ из X-Cleaner-Key или Authorization: Bearer; cookie сессии /api/v1 не открывает. После пяти неверных
    ключей с одного адреса — нарастающая пауза, как у входа; в паузе ключ не проверяется. Ключ отозван или его
    владелец отключён — тот же отказ, что у неизвестного (спецификация 2026-10-28, раздел 6.1)."""
    throttle: auth.Throttle = request.app.state.key_throttle
    host = request.client.host if request.client else ""
    wait = throttle.wait(host)
    if wait > 0:
        raise HTTPException(429, "Слишком много неверных ключей", headers={"Retry-After": str(math.ceil(wait))})
    repo = repo_of(request)
    presented = _presented_key(request)
    key = repo.api_key_by_hash(auth.token_hash(presented)) if presented.startswith(auth.API_KEY_PREFIX) else None
    user = repo.user(key.user_id) if key is not None and not key.disabled else None
    if key is None or user is None or user.disabled:
        throttle.failed(host)
        repo.audit("api_auth_failed")          # без адреса и ключа: присланное — не для журнала (FR-11.2)
        raise HTTPException(401, "Нужен действующий ключ доступа")
    throttle.succeeded(host)
    repo.touch_api_key(key.id)
    return ApiCaller(user, key)


def api_chat(request: Request, chat_id: str, caller: ApiCaller) -> Chat:
    """Чат владельца ключа. Чужой и несуществующий неотличимы — 404 (FR-1.5)."""
    chat = repo_of(request).chat(chat_id)
    if chat is None or chat.user_id != caller.user.id:
        raise HTTPException(404, "Чат не найден")
    return chat


def api_writable_chat(request: Request, chat_id: str, caller: ApiCaller) -> Chat:
    """Чат владельца ключа для текстов, ответов и правил; в чат шлюза их не добавить — 409."""
    chat = api_chat(request, chat_id, caller)
    if chat.kind == "agent":
        raise HTTPException(409, AGENT_READ_ONLY)
    return chat


def get_admin(viewer: Viewer = Depends(get_viewer)) -> Viewer:
    if not viewer.is_admin:
        raise HTTPException(403, "Раздел доступен только администратору")
    return viewer


async def get_form(request: Request, viewer: Viewer = Depends(get_viewer)) -> dict[str, str]:
    """Поля формы POST. Без верного токена формы — отказ: запрос пришёл не с нашей страницы.
    Размер тела ограничивает app.BodyLimit."""
    async with request.form(max_part_size=MAX_BODY_BYTES, max_files=0) as form:
        # Байты, а не строки: compare_digest не сравнивает строки с не-ASCII знаками (TypeError).
        if not hmac.compare_digest(str(form.get("csrf", "")).encode("utf-8"), viewer.session.csrf.encode("utf-8")):
            raise HTTPException(403, "Форма устарела — обновите страницу")
        return {key: value for key, value in form.items() if isinstance(value, str)}


_UPLOAD_OVERHEAD = 64 * 1024        # поля формы и заголовки частей multipart
MAX_BATCH_FILES = 10


class MemoryBuffer(io.BytesIO):
    _rolled = False                    # UploadFile читает/пишет BytesIO без пула дисковых операций


class MemoryMultipart(MultiPartParser):
    """Starlette хранит файлы в SpooledTemporaryFile. Здесь их содержимое существует только в BytesIO."""
    def on_headers_finished(self) -> None:
        super().on_headers_finished()
        upload = self._current_part.file
        if upload is not None:
            empty_spool = upload.file
            empty_spool.close()              # ещё ни одного байта файла не принято
            memory = MemoryBuffer()
            upload.file = memory
            self._files_to_close_on_error.remove(empty_spool)
            self._files_to_close_on_error.append(memory)


@dataclass(frozen=True)
class Upload:
    filename: str        # только для расширения: нигде не сохраняется
    data: bytes
    ocr_all: bool = False       # отметка «Распознать текст на всех страницах PDF»
    reservation: Reservation | None = None


async def _read_upload(request: Request, csrf: str | None, user_id: str = "", multiple: bool = False) -> list[Upload]:
    """Файл из формы multipart. Предел — max_file_mb (FR-2.2); Cleaner файл на диск не пишет (FR-2.7).
    csrf — токен формы страницы; у программы его нет (None), её открывает ключ доступа."""
    limit = request.app.state.max_file_bytes
    too_large = f"Файл больше {limit // (1024 * 1024)} МБ"
    length = request.headers.get("content-length", "0")
    if not length.isascii() or not length.isdigit():
        raise HTTPException(400, "Неверный размер запроса")
    if len(length) > 12 or int(length) > limit + _UPLOAD_OVERHEAD:
        raise HTTPException(413, too_large)
    count = MAX_BATCH_FILES if multiple else 1
    # Предел на весь пакет. На разборе одновременно живут буфер multipart и извлечённые bytes, плюс текст очистки.
    reserve = request.app.state.jobs.budget.reserve(user_id, limit * 2 + count * request.app.state.service.max_text_chars * 8, count)
    parser = None
    form = None
    uploads = []
    try:
        received = 0

        async def bounded_stream():
            nonlocal received
            async for chunk in request.stream():
                received += len(chunk)
                if received > limit + _UPLOAD_OVERHEAD:
                    raise HTTPException(413, too_large)
                yield chunk

        if not request.headers.get("content-type", "").lower().startswith("multipart/form-data"):
            raise HTTPException(400, "Выберите файл")
        parser = MemoryMultipart(request.headers, bounded_stream(), max_files=count, max_fields=4,
                                 max_part_size=_UPLOAD_OVERHEAD)
        form = await parser.parse()
        if csrf is not None and not hmac.compare_digest(str(form.get("csrf", "")).encode("utf-8"), csrf.encode("utf-8")):
            raise HTTPException(403, "Форма устарела — обновите страницу")
        files = form.getlist("file")
        if not files or any(not isinstance(f, UploadFile) or not f.filename for f in files):
            raise HTTPException(400, "Выберите файл")
        if any(isinstance(value, UploadFile) and key != "file" for key, value in form.multi_items()):
            raise HTTPException(400, "Неверное поле файла")
        total = 0
        for upload in files:
            data = await upload.read(limit + 1)
            total += len(data)
            if total > limit:
                raise HTTPException(413, too_large)
            uploads.append(Upload(upload.filename, data, form.get("ocr") == "all"))
        reservations = reserve.split([len(upload.data) * 2 + request.app.state.service.max_text_chars * 8 for upload in uploads])
        return [Upload(upload.filename, upload.data, upload.ocr_all, ticket) for upload, ticket in zip(uploads, reservations)]
    except MultiPartException:
        raise HTTPException(400, f"Неверная форма загрузки (не больше {count} файлов)") from None
    finally:
        try:
            if form is not None:
                await form.close()
        finally:
            if parser is not None:
                # parse() закрывает файлы лишь для MultiPartException: disconnect/CancelledError/413 также требуют cleanup.
                for file in parser._files_to_close_on_error:
                    file.close()
            reserve.release()


async def get_upload(request: Request, viewer: Viewer = Depends(get_viewer)):
    """Файл из формы страницы — с токеном формы."""
    writable_chat(request, request.path_params["chat_id"], viewer)
    uploads = await _read_upload(request, viewer.session.csrf, viewer.user.id, multiple=True)
    try:
        yield uploads
    finally:
        for upload in uploads:
            upload.reservation.release_unused()


async def get_api_upload(request: Request, caller: ApiCaller = Depends(get_api_caller)):
    """Файл программы: поле file и необязательное ocr=all. Ключ проверяется раньше, чем читается тело."""
    api_writable_chat(request, request.path_params["chat_id"], caller)
    uploads = await _read_upload(request, None, caller.user.id)
    try:
        yield uploads[0]
    finally:
        for upload in uploads:
            upload.reservation.release_unused()


def page(request: Request, name: str, viewer: Viewer | None, status_code: int = 200, **context: object) -> HTMLResponse:
    return templates.TemplateResponse(
        request, name,
        {"viewer": viewer, "csrf": viewer.session.csrf if viewer else "", "tz": request.app.state.tz, **context},
        status_code=status_code,
    )
