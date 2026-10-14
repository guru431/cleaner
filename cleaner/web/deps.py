"""Общее для маршрутов: вошедший пользователь, токен формы, страница по шаблону."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from cleaner.storage.repo import Repository, Session, User
from cleaner.web import auth

SESSION_COOKIE = "cleaner_session"
IDLE = timedelta(hours=8)
MAX_FORM_BYTES = 8 * 1024 * 1024     # 500 000 знаков кириллицы в закодированной форме — около 3 МБ

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
    """Поля формы POST. Без верного токена формы — отказ: запрос пришёл не с нашей страницы."""
    if int(request.headers.get("content-length") or 0) > MAX_FORM_BYTES:
        raise HTTPException(413, "Слишком большой запрос")
    form = await request.form()
    # Байты, а не строки: compare_digest не сравнивает строки с не-ASCII знаками (TypeError).
    if not hmac.compare_digest(str(form.get("csrf", "")).encode("utf-8"), viewer.session.csrf.encode("utf-8")):
        raise HTTPException(403, "Форма устарела — обновите страницу")
    return {key: value for key, value in form.items() if isinstance(value, str)}


def page(request: Request, name: str, viewer: Viewer | None, status_code: int = 200, **context: object) -> HTMLResponse:
    return templates.TemplateResponse(
        request, name,
        {"viewer": viewer, "csrf": viewer.session.csrf if viewer else "", "tz": request.app.state.tz, **context},
        status_code=status_code,
    )
