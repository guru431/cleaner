"""Облачная модель и локальная вместо облачной (FR-8, FR-9.4): выбор подключения, экран подтверждения,
поток ответа событиями сервера, остановка."""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse

from cleaner.core.restore import StreamRestorer
from cleaner.service import EditRefused
from cleaner.web import render
from cleaner.web.deps import Viewer, get_form, get_viewer, own_chat, page, repo_of, service_of

router = APIRouter()
_TICK = 1.0           # как часто поток ответа показывает новые фрагменты, секунды: каждый показ — восстановление префикса


@router.post("/chats/{chat_id}/provider")
def choose(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """FR-8.3: подключение и модель чата; пустой выбор — ручной режим."""
    own_chat(request, chat_id, viewer)
    provider_id, _, model = form.get("choice", "").partition("|")
    try:
        service_of(request).set_provider(chat_id, provider_id or None, model)
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}", status_code=303)


@router.get("/chats/{chat_id}/send")
def confirm(request: Request, chat_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    """FR-8.4: экран подтверждения показывает ровно то, что уйдёт, и что в запрос не вошло."""
    chat = own_chat(request, chat_id, viewer)
    try:
        preview = service_of(request).outgoing(chat_id)
    except EditRefused as exc:
        raise HTTPException(409, str(exc)) from None
    outgoing = preview.outgoing
    context = outgoing.context

    def marked(number: int, text: str):
        return render.highlight(text, render.leak_marks([leak for index, leak in outgoing.leaks if index == number]))

    messages = [(message.role, marked(number, message.text)) for number, message in enumerate(context.messages)]
    return page(
        request, "send.html", viewer, chat=chat, provider=preview.provider, model=context.model,
        system=marked(-1, context.system), messages=messages, skipped=preview.skipped,
        sendable=outgoing.sendable, leaks=len(outgoing.leaks), blocked=outgoing.blocked, digest=context.digest(),
    )


@router.post("/chats/{chat_id}/send")
def send(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    try:
        item = service_of(request).send(chat_id, viewer.user.id, form.get("digest", ""))
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}#item-{item.id}", status_code=303)


@router.get("/chats/{chat_id}/items/{item_id}/stream")
def stream(request: Request, chat_id: str, item_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    """События сервера (раздел 14): весь восстановленный к этому моменту текст, затем «done» — страница
    перезагружается и показывает полное восстановление. Только чтение: генерация от соединения не зависит."""
    own_chat(request, chat_id, viewer)
    item = repo_of(request).item(chat_id, item_id)
    if item is None or item.kind != "answer" or item.source != "api":
        raise HTTPException(404, "Ответ не найден")
    service = service_of(request)
    live = service.live.get(item_id)
    state, _ = repo_of(request).load_state(chat_id)
    restorer = StreamRestorer(state, repo_of(request).settings())

    async def events() -> AsyncIterator[str]:
        seen = 0
        while True:
            if live is not None:
                text = live.text()
                if len(text) > seen:
                    # Восстановление всего показанного префикса — в потоке, не в цикле событий: на длинном ответе
                    # с большой таблицей оно идёт десятки миллисекунд и остановило бы страницы всех пользователей.
                    shown = await anyio.to_thread.run_sync(restorer.feed, text[seen:])
                    seen = len(text)
                    yield f"data: {json.dumps({'text': shown}, ensure_ascii=False)}\n\n"
            if live is None or live.finished:
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(_TICK)

    return StreamingResponse(events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


@router.post("/chats/{chat_id}/items/{item_id}/stop")
def stop(request: Request, chat_id: str, item_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """FR-8.6: генерацию можно остановить; полученная часть сохраняется неполной."""
    own_chat(request, chat_id, viewer)
    try:
        service_of(request).stop(chat_id, item_id)
    except KeyError:
        raise HTTPException(404, "Ответ уже получен или не найден") from None
    return RedirectResponse(f"/chats/{chat_id}#item-{item_id}", status_code=303)


@router.post("/chats/{chat_id}/ask-local")
def ask_local(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """FR-9.4: вопрос локальной модели вместо облачной — без очистки, текст не покидает сервер."""
    own_chat(request, chat_id, viewer)
    try:
        item = service_of(request).ask_local(chat_id, viewer.user.id)
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}#item-{item.id}", status_code=303)
