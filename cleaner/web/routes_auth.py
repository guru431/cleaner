"""Вход и выход."""
from __future__ import annotations

import hmac
import math
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from cleaner.storage.repo import User
from cleaner.web import auth
from cleaner.web.deps import IDLE, MAX_AGE, SESSION_COOKIE, Viewer, get_form, get_viewer, page, repo_of

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
        await run_in_threadpool(request.app.state.throttle.cancel, name)
        return _login_page(request, expected, 503, "Сервер занят проверкой других входов — попробуйте позже")
    return await run_in_threadpool(_logged_in, request, expected, name, user, password_ok)


def _account(request: Request, name: str) -> tuple[float, User | None]:
    """Пауза логина после неудач, а без паузы — попытка в счёт паузы (Throttle.attempt) и учётная запись."""
    wait = request.app.state.throttle.attempt(name)
    return wait, None if wait else repo_of(request).user_by_login(name)


def _logged_in(request: Request, expected: str, name: str, user: User | None, password_ok: bool) -> Response:
    """Итог проверки: неудача (уже в счёте паузы) идёт в журнал, успех снимает счёт и открывает сессию.

    user — снимок до проверки пароля: пока она шла, пароль могли сменить, а учётную запись — отключить. Сессия
    открывается, только если проверенный хэш всё ещё действует (create_session); нет — проверенный пароль
    уже не тот, и это та же неудача."""
    repo, throttle = repo_of(request), request.app.state.throttle
    token, csrf = auth.new_token(), auth.new_token()
    if (
        not password_ok or user.disabled
        or not repo.create_session(auth.token_hash(token), user.id, csrf, user.password_hash)
    ):
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


def _signed_out(path: str = "/login") -> Response:
    response = RedirectResponse(path, status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# --- своя учётная запись: сессии и пароль ------------------------------------------------

@router.get("/account/sessions")
def sessions(request: Request, viewer: Viewer = Depends(get_viewer)) -> Response:
    """Свои сессии: начало, последнее действие и когда истечёт. Адресов и браузеров сессия не хранит."""
    rows = [
        {
            "current": session.token_hash == viewer.session.token_hash, "created_at": session.created_at,
            "last_seen_at": session.last_seen_at,
            "expires_at": min(
                datetime.fromisoformat(session.created_at) + MAX_AGE, datetime.fromisoformat(session.last_seen_at) + IDLE,
            ).isoformat(timespec="seconds"),
        }
        for session in repo_of(request).sessions(viewer.user.id)
    ]
    return page(request, "account_sessions.html", viewer, rows=rows, idle_hours=IDLE // timedelta(hours=1),
                max_age_hours=MAX_AGE // timedelta(hours=1))


@router.post("/account/sessions/logout-all")
def logout_all(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """Выйти на всех устройствах — и на этом тоже."""
    repo = repo_of(request)
    repo.audit("logout_all", viewer.user.id, sessions=repo.delete_sessions(viewer.user.id))
    return _signed_out()


def _password_page(request: Request, viewer: Viewer, status_code: int = 200, error: str = "") -> Response:
    return page(request, "account_password.html", viewer, status_code=status_code, error=error, min_password=auth.MIN_PASSWORD)


@router.get("/account/password")
def password_form(request: Request, viewer: Viewer = Depends(get_viewer)) -> Response:
    return _password_page(request, viewer)


# async, как вход: текущий пароль проверяется в пуле Argon2, место ждётся в цикле событий (auth.check_password).
# Неверный текущий пароль — неудача входа этого логина: перебор пароля из чужой открытой сессии упирается в ту же паузу.
@router.post("/account/password")
async def change_own_password(
    request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer),
) -> Response:
    login, throttle = viewer.user.login, request.app.state.throttle
    new = str(form.get("password", ""))
    if new != str(form.get("repeat", "")):
        return _password_page(request, viewer, 400, "Новый пароль и повтор не совпадают")
    if len(new) < auth.MIN_PASSWORD:
        return _password_page(request, viewer, 400, f"Новый пароль короче {auth.MIN_PASSWORD} знаков")
    wait = await run_in_threadpool(throttle.attempt, login)          # в счёт паузы до проверки, как у входа
    if wait:
        return _password_page(request, viewer, 429, f"Слишком много попыток. Повторите через {math.ceil(wait)} с")
    try:
        password_ok = await auth.check_password(viewer.user.password_hash, str(form.get("current", "")))
    except auth.Busy:
        await run_in_threadpool(throttle.cancel, login)
        return _password_page(request, viewer, 503, "Сервер занят проверкой паролей — попробуйте позже")
    return await run_in_threadpool(_change_own_password, request, viewer, password_ok, new)


def _change_own_password(request: Request, viewer: Viewer, password_ok: bool, new: str) -> Response:
    repo, throttle = repo_of(request), request.app.state.throttle
    if not password_ok:
        repo.audit("login_failed", viewer.user.id, stage="password_change")
        return _password_page(request, viewer, 400, "Текущий пароль неверен")
    throttle.succeeded(viewer.user.login)
    repo.set_password(viewer.user.id, auth.hash_password(new))           # закрывает все сессии, и эту тоже
    repo.audit("password_changed", viewer.user.id, target=viewer.user.id, by="self")
    return _signed_out()
