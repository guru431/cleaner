"""Общее для маршрутов: вошедший пользователь, токен формы, страница по шаблону."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.datastructures import UploadFile

from cleaner.service import ChatService
from cleaner.storage.repo import Chat, Repository, Session, User
from cleaner.web import auth

SESSION_COOKIE = "cleaner_session"
IDLE = timedelta(hours=8)
# Предел тела запроса (app.BodyLimit) и одного поля формы: 500 000 знаков даже четырёхбайтных —
# около 6 МБ в закодированной форме. У Starlette поле формы по умолчанию не больше 1 МБ.
MAX_BODY_BYTES = 8 * 1024 * 1024

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


def get_admin(viewer: Viewer = Depends(get_viewer)) -> Viewer:
    if not viewer.is_admin:
        raise HTTPException(403, "Раздел доступен только администратору")
    return viewer


async def get_form(request: Request, viewer: Viewer = Depends(get_viewer)) -> dict[str, str]:
    """Поля формы POST. Без верного токена формы — отказ: запрос пришёл не с нашей страницы.
    Размер тела ограничивает app.BodyLimit."""
    form = await request.form(max_part_size=MAX_BODY_BYTES)
    # Байты, а не строки: compare_digest не сравнивает строки с не-ASCII знаками (TypeError).
    if not hmac.compare_digest(str(form.get("csrf", "")).encode("utf-8"), viewer.session.csrf.encode("utf-8")):
        raise HTTPException(403, "Форма устарела — обновите страницу")
    return {key: value for key, value in form.items() if isinstance(value, str)}


_UPLOAD_OVERHEAD = 64 * 1024        # поля формы и заголовки частей multipart


@dataclass(frozen=True)
class Upload:
    filename: str        # только для расширения: нигде не сохраняется
    data: bytes
    ocr_all: bool = False       # отметка «Распознать текст на всех страницах PDF»


async def get_upload(request: Request, viewer: Viewer = Depends(get_viewer)) -> Upload:
    """Файл из формы multipart с токеном формы. Предел — max_file_mb (FR-2.2); Cleaner файл на диск не пишет (FR-2.7)."""
    limit = request.app.state.max_file_bytes
    too_large = f"Файл больше {limit // (1024 * 1024)} МБ"
    if int(request.headers.get("content-length") or 0) > limit + _UPLOAD_OVERHEAD:
        raise HTTPException(413, too_large)
    form = await request.form(max_files=1, max_fields=4)
    if not hmac.compare_digest(str(form.get("csrf", "")).encode("utf-8"), viewer.session.csrf.encode("utf-8")):
        raise HTTPException(403, "Форма устарела — обновите страницу")
    upload = form.get("file")
    if not isinstance(upload, UploadFile) or not upload.filename:
        raise HTTPException(400, "Выберите файл")
    data = await upload.read(limit + 1)
    await upload.close()
    if len(data) > limit:
        raise HTTPException(413, too_large)
    return Upload(upload.filename, data, form.get("ocr") == "all")


def page(request: Request, name: str, viewer: Viewer | None, status_code: int = 200, **context: object) -> HTMLResponse:
    return templates.TemplateResponse(
        request, name,
        {"viewer": viewer, "csrf": viewer.session.csrf if viewer else "", "tz": request.app.state.tz, **context},
        status_code=status_code,
    )
