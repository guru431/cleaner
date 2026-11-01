"""Вход и выход."""
from __future__ import annotations

import hmac
import math

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from cleaner.storage.repo import User
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


async def _login_fields(request: Request) -> dict[str, str]:
    async with request.form(max_files=0) as form:
        return {key: value for key, value in form.items() if isinstance(value, str)}


# async: место для Argon2 (десятки миллисекунд и 64 МБ на попытку) вход ждёт в цикле событий и не держит
# поток общего пула, которым обслуживаются все страницы (auth.check_password). Таблица неудач и база —
# в пуле потоков, как у обычных маршрутов: цикл событий не должен ждать их замков.
@router.post("/login")
async def login(request: Request, form: dict[str, str] = Depends(_login_fields)) -> Response:
    expected = request.cookies.get(LOGIN_COOKIE, "")
    if not expected or not hmac.compare_digest(str(form.get("csrf", "")).encode("utf-8"), expected.encode("utf-8")):
        return _login_page(request, auth.new_token(), 403, "Форма устарела — попробуйте ещё раз")
    name = str(form.get("login", "")).strip()
    wait, user = await run_in_threadpool(_account, request, name)
    if wait:
        return _login_page(request, expected, 429, f"Слишком много попыток. Повторите через {math.ceil(wait)} с")
    try:
        password_ok = await auth.check_password(user.password_hash if user else None, str(form.get("password", "")))
    except auth.Busy:                   # пароль не проверялся: это не неудачная попытка
        return _login_page(request, expected, 503, "Сервер занят проверкой других входов — попробуйте позже")
    return await run_in_threadpool(_logged_in, request, expected, name, user, password_ok)


def _account(request: Request, name: str) -> tuple[float, User | None]:
    """Пауза логина после неудач, а без паузы — его учётная запись."""
    wait = request.app.state.throttle.wait(name)
    return wait, None if wait else repo_of(request).user_by_login(name)


def _logged_in(request: Request, expected: str, name: str, user: User | None, password_ok: bool) -> Response:
    """Итог проверки: неудача идёт в счёт паузы и в журнал, успех открывает сессию.

    user — снимок до проверки пароля: пока она шла, пароль могли сменить, а учётную запись — отключить. Сессия
    открывается, только если проверенный хэш всё ещё действует (create_session); нет — проверенный пароль
    уже не тот, и это та же неудача."""
    repo, throttle = repo_of(request), request.app.state.throttle
    token, csrf = auth.new_token(), auth.new_token()
    if (
        not password_ok or user.disabled
        or not repo.create_session(auth.token_hash(token), user.id, csrf, user.password_hash)
    ):
        throttle.failed(name)
        repo.audit("login_failed", user.id if user else None)
        return _login_page(request, expected, 401, "Неверный логин или пароль")
    throttle.succeeded(name)
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
