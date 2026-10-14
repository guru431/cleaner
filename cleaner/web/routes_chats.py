"""Чаты: список с поиском, лента, ввод текста и ответа модели, состояние обработки, скачивание."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from cleaner.service import ChatView, EditRefused, InputView, TextTooLong
from cleaner.storage.repo import Chat, Item
from cleaner.web import render
from cleaner.web.deps import Viewer, get_form, get_viewer, own_chat, page, repo_of, service_of

router = APIRouter()
_TITLE = 200


def chat_list(request: Request, viewer: Viewer, query: str = "") -> list[Chat]:
    """Названия зашифрованы, поэтому поиск идёт после расшифровки, в памяти (FR-1.2)."""
    chats = repo_of(request).chats(viewer.user.id)
    needle = query.strip().lower()
    return [chat for chat in chats if needle in chat.title.lower()] if needle else chats


def input_view(view: ChatView, item_id: str) -> InputView:
    entry = next((e for e in view.items if isinstance(e, InputView) and e.item.id == item_id), None)
    if entry is None:
        raise HTTPException(404, "Текст не найден")
    return entry


def can_retry(item: Item) -> bool:
    """Заново очищается сохранённый текст: вставленный или уже извлечённый из файла (сам файл не хранится)."""
    return item.kind == "input" and item.status in ("done", "failed") and bool(item.original)


def _entries(view: ChatView) -> list[dict[str, object]]:
    names = render.surrogates_by_entity(view.state)
    entries: list[dict[str, object]] = []
    for entry in view.items:
        item = entry.item
        if isinstance(entry, InputView):
            common = {"kind": "input", "id": item.id, "seq": item.seq, "source": item.source, "status": item.status}
            if item.status != "done":
                entries.append(common | {
                    "error": item.meta.get("error", ""), "progress": item.meta.get("progress", ""),
                    "retry": can_retry(item),
                })
                continue
            blocked = frozenset(span["entity_id"] for span in entry.blocked)
            entries.append(common | {
                "deliverable": entry.deliverable, "leaks": len(entry.leaks), "blocked": len(entry.blocked),
                "exposed": [", ".join(names.get(entity_id, ["?"])) for entity_id in item.exposed],
                "html": render.highlight(item.sanitized or "", render.sanitized_marks(item, view.state, entry.leaks, blocked)),
            })
        else:
            entries.append({
                "kind": "answer", "id": item.id, "seq": item.seq, "raw": item.original,
                "counters": entry.result.counters,
                "html": render.highlight(entry.result.text, render.restored_marks(entry.result.segments)),
            })
    return entries


@router.get("/chats")
def chats(request: Request, q: str = "", viewer: Viewer = Depends(get_viewer)) -> Response:
    return page(request, "chats.html", viewer, chats=chat_list(request, viewer, q), q=q)


@router.post("/chats")
def create_chat(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    now = request.app.state.clock.now().astimezone(request.app.state.tz)
    title = form.get("title", "").strip()[:_TITLE] or f"Чат от {now:%d.%m.%Y %H:%M}"       # FR-1.1
    chat_id = repo_of(request).create_chat(viewer.user.id, title)
    repo_of(request).audit("chat_created", viewer.user.id, chat_id)
    return RedirectResponse(f"/chats/{chat_id}", status_code=303)


@router.get("/chats/{chat_id}")
def chat_page(request: Request, chat_id: str, q: str = "", viewer: Viewer = Depends(get_viewer)) -> Response:
    chat = own_chat(request, chat_id, viewer)
    view = service_of(request).view(chat_id)
    return page(
        request, "chat.html", viewer, chat=chat, chats=chat_list(request, viewer, q), q=q, entries=_entries(view),
        max_file_mb=request.app.state.max_file_bytes // (1024 * 1024),
    )


@router.post("/chats/{chat_id}/rename")
def rename(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    title = form.get("title", "").strip()[:_TITLE]
    if not title:
        raise HTTPException(400, "Название не может быть пустым")
    repo_of(request).rename_chat(chat_id, title)
    return RedirectResponse(f"/chats/{chat_id}", status_code=303)


@router.post("/chats/{chat_id}/delete")
def delete(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    if form.get("confirm") != "yes":
        raise HTTPException(400, "Подтвердите удаление")          # FR-1.4
    repo_of(request).delete_chat(chat_id)
    repo_of(request).audit("chat_deleted", viewer.user.id, chat_id)
    return RedirectResponse("/chats", status_code=303)


@router.post("/chats/{chat_id}/input")
def add_input(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    text = form.get("text", "")
    if not text.strip():
        raise HTTPException(400, "Вставьте текст")
    try:
        item = service_of(request).add_input(chat_id, viewer.user.id, text)
    except TextTooLong as exc:
        raise HTTPException(413, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}/items/{item.id}", status_code=303)


@router.post("/chats/{chat_id}/answer")
def add_answer(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    answer = form.get("answer", "")
    if not answer.strip():
        raise HTTPException(400, "Вставьте ответ модели")
    try:
        item = service_of(request).add_answer(chat_id, viewer.user.id, answer)
    except TextTooLong as exc:
        raise HTTPException(413, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}#item-{item.id}", status_code=303)


@router.get("/chats/{chat_id}/items/{item_id}/status")
def item_status(request: Request, chat_id: str, item_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    """Состояние обработки для опроса из app.js (раздел 14): коды и ход, без текста."""
    own_chat(request, chat_id, viewer)
    item = repo_of(request).item(chat_id, item_id)
    if item is None:
        raise HTTPException(404, "Текст не найден")
    return JSONResponse({"status": item.status, "risk": item.risk_status, "progress": item.meta.get("progress", "")})


@router.post("/chats/{chat_id}/items/{item_id}/retry")
def retry(request: Request, chat_id: str, item_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    try:
        service_of(request).retry(chat_id, viewer.user.id, item_id)
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Текст не найден") from None
    return RedirectResponse(f"/chats/{chat_id}/items/{item_id}", status_code=303)


@router.get("/chats/{chat_id}/items/{item_id}/download")
def download(request: Request, chat_id: str, item_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    entry = input_view(service_of(request).view(chat_id), item_id)
    if not entry.deliverable:
        raise HTTPException(409, "Выдача заблокирована: текст не обработан, в нём найден оригинал или фрагмент запрещённого типа")
    return Response(
        entry.item.sanitized,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="cleaned-{entry.item.seq}.txt"'},
    )
