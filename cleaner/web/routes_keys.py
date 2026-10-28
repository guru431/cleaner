"""Страница «Ключи» (FR-13.1; спецификация 2026-10-28, разделы 6.1 и 16): ключи доступа программ к /api/v1.
Ключ показывается один раз — на странице сразу после выпуска; в базе — его хэш и последние четыре знака."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from cleaner.web import auth
from cleaner.web.deps import Viewer, get_form, get_viewer, page, repo_of

router = APIRouter()
NAME_LIMIT = 100


def _page(request: Request, viewer: Viewer, issued: str = "") -> Response:
    """Пользователь видит свои ключи, администратор — все, с владельцем (без значений: их нет и в базе)."""
    repo = repo_of(request)
    keys = repo.api_keys(None if viewer.is_admin else viewer.user.id)
    logins = {user.id: user.login for user in repo.users()} if viewer.is_admin else {}
    return page(request, "keys.html", viewer, keys=keys, logins=logins, issued=issued, endpoint=f"{request.base_url}api/v1/chats")


@router.get("/keys")
def keys(request: Request, viewer: Viewer = Depends(get_viewer)) -> Response:
    return _page(request, viewer)


@router.post("/keys")
def create_key(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    name = form.get("name", "").strip()
    if not 1 <= len(name) <= NAME_LIMIT:
        raise HTTPException(400, f"Имя ключа — от 1 до {NAME_LIMIT} знаков")
    key = auth.new_api_key()
    repo = repo_of(request)
    key_id = repo.add_api_key(viewer.user.id, name, auth.token_hash(key), key[-4:])
    repo.audit("key_created", viewer.user.id, id=key_id)
    # Страница, а не переадресация: ключ виден один раз и не попадает ни в адрес, ни в базу.
    return _page(request, viewer, issued=key)


@router.post("/keys/{key_id}/disable")
def disable_key(request: Request, key_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """Отзыв насовсем — владельцем или администратором; чужой и несуществующий ключ неотличимы (404)."""
    repo = repo_of(request)
    key = repo.api_key(key_id)
    if key is None or (key.user_id != viewer.user.id and not viewer.is_admin):
        raise HTTPException(404, "Ключ не найден")
    repo.disable_api_key(key_id)
    repo.audit("key_disabled", viewer.user.id, id=key_id)
    return RedirectResponse("/keys", status_code=303)
