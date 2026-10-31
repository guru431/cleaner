"""Облачная модель и локальная вместо облачной (FR-8, FR-9.4): выбор подключения, экран подтверждения,
поток ответа событиями сервера, остановка."""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterable

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse

from cleaner.core.restore import StreamRestorer
from cleaner.service import EditRefused, Preview
from cleaner.web import render
from cleaner.web.deps import Viewer, get_form, get_viewer, own_chat, page, repo_of, service_of, writable_chat

router = APIRouter()
_TICK = 1.0           # как часто поток ответа показывает новые фрагменты, секунды: каждый показ — восстановление префикса


@router.post("/chats/{chat_id}/provider")
def choose(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """FR-8.3: подключение и модель чата; пустой выбор — ручной режим."""
    writable_chat(request, chat_id, viewer)
    provider_id, _, model = form.get("choice", "").partition("|")
    try:
        service_of(request).set_provider(chat_id, provider_id or None, model)
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}", status_code=303)


def _numbers(values: Iterable[str]) -> set[int]:
    return {int(value) for value in values if value.isdigit() and len(value) < 10}


def _exclude(request: Request) -> frozenset[int]:
    """Исключённые пользователем элементы — номерами из адреса (номера не данные; GET «Пересобрать»): показанные на
    странице выбора (shown) без отмеченных (include). Без shown — все включены, как при первом открытии."""
    params = request.query_params
    return frozenset(_numbers(params.get("shown", "").split(",")) - _numbers(params.getlist("include")))


def _glued(preview: Preview) -> list[int]:
    """Исключённые ответы модели, вокруг которых остались два вопроса: они склеятся в одно сообщение (раздел 10.1)."""
    dialogue = [(seq, role) for seq, role, _ in preview.candidates if role != "system"]
    glued = []
    for index, (seq, role) in enumerate(dialogue):
        if role != "assistant" or seq not in preview.excluded:
            continue
        before = [r for s, r in dialogue[:index] if s not in preview.excluded]
        after = [r for s, r in dialogue[index + 1:] if s not in preview.excluded]
        if before[-1:] == ["user"] and after[:1] == ["user"]:
            glued.append(seq)
    return glued


def _request(preview: Preview) -> dict[str, object]:
    """Общее экранам отправки и переноса вручную: выбор состава, исключённое, итоговый объём и сам запрос."""
    picks = [
        {"seq": seq, "role": render.ROLE_NAMES[role], "chars": chars, "on": seq not in preview.excluded}
        for seq, role, chars in preview.candidates
    ]
    common = {
        "picks": picks, "excluded": [p for p in picks if not p["on"]], "glued": _glued(preview),
        "shown": ",".join(str(p["seq"]) for p in picks), "exclude": ",".join(map(str, preview.excluded)),
        "skipped": preview.skipped, "refused": preview.refused,
    }
    outgoing = preview.outgoing
    if outgoing is None:
        return common | {"outgoing": None, "sendable": False, "leaks": 0, "blocked": 0}
    context = outgoing.context

    def marked(number: int, text: str):
        return render.highlight(text, render.leak_marks([leak for index, leak in outgoing.leaks if index == number]))

    return common | {
        "outgoing": outgoing, "system": marked(-1, context.system),
        "messages": [(message.role, marked(number, message.text)) for number, message in enumerate(context.messages)],
        "sendable": outgoing.sendable, "leaks": len(outgoing.leaks), "blocked": outgoing.blocked,
        "total": sum(len(text) for text in context.texts()), "count": len(context.messages),
    }


@router.get("/chats/{chat_id}/send")
def confirm(request: Request, chat_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    """FR-8.4: экран подтверждения показывает ровно то, что уйдёт, и что в запрос не вошло. Состав можно сократить
    (раздел 10.1): отправка — только кнопкой после пересборки, с отпечатком этого состава."""
    chat = writable_chat(request, chat_id, viewer)
    try:
        preview = service_of(request).outgoing(chat_id, _exclude(request))
    except EditRefused as exc:
        raise HTTPException(409, str(exc)) from None
    shown = _request(preview)
    outgoing = preview.outgoing
    return page(
        request, "send.html", viewer, chat=chat, provider=preview.provider,
        model=outgoing.context.model if outgoing else "", digest=outgoing.context.digest() if outgoing else "",
        action=f"/chats/{chat_id}/send", **shown,
    )


@router.get("/chats/{chat_id}/manual")
def manual(request: Request, chat_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    """Перенос вручную (сценарий 5.1): весь очищенный диалог одним текстом с ролями и служебной инструкцией — тот же
    запрос и та же проверка утечек, что у отправки по API (SEC-2). При находке или блокировке копирования нет; нет его
    и когда сборка выдала бы новые замены (stale): страница предлагает очистить тексты чата заново."""
    chat = writable_chat(request, chat_id, viewer)
    try:
        preview = service_of(request).manual(chat_id, _exclude(request))
    except EditRefused as exc:
        raise HTTPException(409, str(exc)) from None
    shown = _request(preview)
    outgoing = preview.outgoing
    text = None
    if outgoing is not None and not preview.stale:
        context = outgoing.context
        text = render.dialogue(context.system, [(m.role, m.text) for m in context.messages], outgoing.leaks)
    return page(
        request, "manual.html", viewer, chat=chat, text=text, stale=preview.stale, action=f"/chats/{chat_id}/manual", **shown,
    )


@router.post("/chats/{chat_id}/send")
def send(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    writable_chat(request, chat_id, viewer)
    exclude = frozenset(_numbers(form.get("exclude", "").split(",")))
    try:
        item = service_of(request).send(chat_id, viewer.user.id, form.get("digest", ""), exclude)
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
    try:
        state, _ = repo_of(request).load_state(chat_id)
    except KeyError:
        raise HTTPException(404, "Ответ не найден") from None
    restorer = StreamRestorer(state, repo_of(request).settings())

    async def events() -> AsyncIterator[str]:
        seen = 0
        while True:
            if await request.is_disconnected():
                return
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
    """FR-9.4: вопрос локальной модели вместо облачной — без очистки: оригиналы уходят только по адресу локальной модели
    (петлевой, частный или доверенный, SEC-12), не облаку."""
    writable_chat(request, chat_id, viewer)
    try:
        item = service_of(request).ask_local(chat_id, viewer.user.id)
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}#item-{item.id}", status_code=303)
