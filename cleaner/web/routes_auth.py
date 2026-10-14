"""Вход и выход."""
from __future__ import annotations

import hmac
import math

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response

from cleaner.web import auth
from cleaner.web.deps import SESSION_COOKIE, Viewer, get_form, get_viewer, page, repo_of

router = APIRouter()
LOGIN_COOKIE = "cleaner_login"      # токен формы входа: сессии ещё нет, проверяем двойной отправкой


def _login_page(request: Request, token: str, status_code: int = 200, error: str = "") -> Response:
    response = page(request, "login.html", None, status_code=status_code, login_csrf=token, error=error)
    response.set_cookie(
        LOGIN_COOKIE, token, httponly=True, samesite="strict", secure=request.app.state.secure_cookies, path="/login"
    )
    return response


@router.get("/login")
def login_form(request: Request) -> Response:
    return _login_page(request, auth.new_token())


@router.post("/login")
async def login(request: Request) -> Response:
    form = await request.form()
    repo, throttle = repo_of(request), request.app.state.throttle
    expected = request.cookies.get(LOGIN_COOKIE, "")
    if not expected or not hmac.compare_digest(str(form.get("csrf", "")).encode("utf-8"), expected.encode("utf-8")):
        return _login_page(request, auth.new_token(), 403, "Форма устарела — попробуйте ещё раз")
    name = str(form.get("login", "")).strip()
    wait = throttle.wait(name)
    if wait:
        return _login_page(request, expected, 429, f"Слишком много попыток. Повторите через {math.ceil(wait)} с")
    user = repo.user_by_login(name)
    password_ok = auth.verify_password(user.password_hash if user else None, str(form.get("password", "")))
    if not password_ok or user.disabled:
        throttle.failed(name)
        repo.audit("login_failed", user.id if user else None)
        return _login_page(request, expected, 401, "Неверный логин или пароль")
    throttle.succeeded(name)
    token, csrf = auth.new_token(), auth.new_token()
    repo.create_session(auth.token_hash(token), user.id, csrf)
    repo.audit("login", user.id)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict", secure=request.app.state.secure_cookies, path="/"
    )
    response.delete_cookie(LOGIN_COOKIE, path="/login")
    return response


@router.post("/logout")
def logout(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    repo = repo_of(request)
    repo.delete_session(viewer.session.token_hash)
    repo.audit("logout", viewer.user.id)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/")
def home(viewer: Viewer = Depends(get_viewer)) -> Response:
    return RedirectResponse("/chats", status_code=303)
