"""JSON-API для программ (FR-13; спецификация 2026-10-28, раздел 15): тонкий вход в ту же ChatService, что у
веб-интерфейса. Открывается только ключом доступа; чаты API — обычные чаты владельца ключа, видимые в интерфейсе."""
from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from cleaner.core.types import ChatState, EntityType
from cleaner.service import EditRefused, InputView, TextTooLong
from cleaner.web import render
from cleaner.web.deps import ApiCaller, Upload, api_chat, get_api_caller, get_api_upload, repo_of, service_of
from cleaner.web.routes_chats import input_view

router = APIRouter(prefix="/api/v1")
_TITLE = 200
_WORKING = ("queued", "running")
_POLL = 0.2                 # как часто маршрут texts смотрит, готов ли текст, пока ждёт wait секунд


class ChatIn(BaseModel):
    title: str = ""
    label_style: Literal["angle", "square"] = "angle"
    layers: dict[Literal["ner", "llm"], bool] = {}


class TextIn(BaseModel):
    text: str
    wait: int = Field(30, ge=0, le=60)


class AnswerIn(BaseModel):
    text: str


class RuleIn(BaseModel):
    action: Literal["mask", "unmask"]
    value: str
    item_id: str = ""           # mask: текст, в котором есть фрагмент, — как выделение на экране проверки
    type: str = ""              # mask: код типа (EntityType)


def _text_result(view: InputView, state: ChatState) -> dict:
    """Состояние и результат входного текста. Позиции замен — в исходном тексте; очищенный текст — только
    выдаваемый (SEC-2, FR-4.2), как у скачивания на странице."""
    item = view.item
    if item.status in _WORKING:
        return {"item_id": item.id, "status": item.status}
    if item.status != "done":
        return {"item_id": item.id, "status": "failed", "error": item.meta.get("error", "")}
    result: dict[str, object] = {"item_id": item.id, "status": "done", "deliverable": view.deliverable}
    if view.deliverable:
        result["sanitized"] = item.sanitized
    return result | {
        "replacements": [
            {"start": s["start"], "end": s["end"], "type": state.entities[s["entity_id"]].type.value, "replacement": s["surrogate"]}
            for s in item.spans if s["entity_id"] in state.entities
        ],
        "notices": [{"code": n["code"], "start": n["start"], "end": n["end"]} for n in item.notices],
        "leaks": len(view.leaks), "blocked": len(view.blocked),
    }


def _item_result(request: Request, chat_id: str, item_id: str) -> dict:
    try:
        view = service_of(request).view(chat_id, item_id)
    except KeyError:
        raise HTTPException(404, "Чат не найден") from None          # удалён, пока текст ждал очереди
    return _text_result(input_view(view, item_id), view.state)


def _status(request: Request, chat_id: str, item_id: str) -> str | None:
    """Статус элемента; None — его нет (чат удалили, пока текст ждал)."""
    try:
        item = repo_of(request).item(chat_id, item_id)
    except KeyError:
        return None
    return None if item is None else item.status


@router.post("/chats")
def create_chat(request: Request, body: ChatIn, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    now = request.app.state.clock.now().astimezone(request.app.state.tz)
    title = body.title.strip()[:_TITLE] or f"API {now:%d.%m.%Y %H:%M}"
    repo = repo_of(request)
    chat_id = repo.create_chat(caller.user.id, title, body.label_style)
    for layer, enabled in body.layers.items():
        service_of(request).set_layer(chat_id, caller.user.id, layer, enabled)
    repo.audit("chat_created", caller.user.id, chat_id, via="api")
    return JSONResponse({"id": chat_id}, status_code=201)


@router.get("/chats")
def chats(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    return JSONResponse([
        {"id": chat.id, "title": chat.title, "updated_at": chat.updated_at} for chat in repo_of(request).chats(caller.user.id)
    ])


@router.delete("/chats/{chat_id}")
def delete_chat(request: Request, chat_id: str, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """FR-1.4 без подтверждения: вызов и есть подтверждение."""
    api_chat(request, chat_id, caller)
    service_of(request).delete_chat(chat_id, caller.user.id, via="api")
    return Response(status_code=204)


@router.post("/chats/{chat_id}/texts")
async def add_text(request: Request, chat_id: str, body: TextIn, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Очистка — то же задание в общем пуле, что у страницы. Маршрут ждёт его до wait секунд в цикле событий, не
    занимая поток пула; не дождался — 202 и опрос GET …/items/{item_id}."""
    await run_in_threadpool(api_chat, request, chat_id, caller)
    if not body.text.strip():
        raise HTTPException(422, "Пустой текст")
    try:
        item = await run_in_threadpool(service_of(request).add_input, chat_id, caller.user.id, body.text, "program")
    except TextTooLong as exc:
        raise HTTPException(413, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Чат не найден") from None
    deadline = time.monotonic() + body.wait
    while (status := await run_in_threadpool(_status, request, chat_id, item.id)) in _WORKING:
        if time.monotonic() >= deadline:
            return JSONResponse({"item_id": item.id, "status": status}, status_code=202)
        await asyncio.sleep(_POLL)
    if status is None:
        raise HTTPException(404, "Чат не найден")
    return JSONResponse(await run_in_threadpool(_item_result, request, chat_id, item.id))


@router.post("/chats/{chat_id}/files")
def add_file(
    request: Request, chat_id: str, upload: Upload = Depends(get_api_upload), caller: ApiCaller = Depends(get_api_caller),
) -> Response:
    """Файл — в очередь разбора (FR-2.2…2.9); результат — опросом GET …/items/{item_id}."""
    api_chat(request, chat_id, caller)
    try:
        item = service_of(request).add_file(chat_id, caller.user.id, upload.filename, upload.data, upload.ocr_all)
    except KeyError:
        raise HTTPException(404, "Чат не найден") from None
    return JSONResponse({"item_id": item.id, "status": item.status}, status_code=202)


@router.get("/chats/{chat_id}/items/{item_id}")
def item(request: Request, chat_id: str, item_id: str, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Входной текст чата; ответ модели и элемент другого чата — 404, как несуществующий."""
    api_chat(request, chat_id, caller)
    return JSONResponse(_item_result(request, chat_id, item_id))


@router.post("/chats/{chat_id}/restore")
def restore(request: Request, chat_id: str, body: AnswerIn, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Ответ модели — элементом чата, как вставленный на странице (FR-7); в ответе — восстановленный текст."""
    api_chat(request, chat_id, caller)
    if not body.text.strip():
        raise HTTPException(422, "Пустой текст")
    service = service_of(request)
    try:
        item = service.add_answer(chat_id, caller.user.id, body.text)
        [answer] = service.view(chat_id, item.id).items
    except TextTooLong as exc:
        raise HTTPException(413, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Чат не найден") from None
    result = answer.result                          # элемент — ответ модели: вид — AnswerView
    return JSONResponse({
        "item_id": item.id, "restored": result.text, "counters": result.counters,
        "unknown": [result.text[s.start:s.end] for s in result.segments if s.kind == "unknown"],
    })


@router.get("/chats/{chat_id}/entities")
def entities(request: Request, chat_id: str, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Таблица соответствий (FR-1.6): замены, значение при восстановлении, написания, число фрагментов во входных
    текстах — как таблица замен на странице, по типу и номеру."""
    api_chat(request, chat_id, caller)
    repo = repo_of(request)
    try:
        state, _ = repo.load_state(chat_id)
        items = repo.items(chat_id)
    except KeyError:
        raise HTTPException(404, "Чат не найден") from None
    names = render.surrogates_by_entity(state)
    counts = Counter(span["entity_id"] for item in items if item.kind == "input" for span in item.spans)
    return JSONResponse([
        {
            "id": e.id, "type": e.type.value, "replacements": names.get(e.id, []), "original": e.restore_value,
            "forms": e.forms, "count": counts[e.id],
        }
        for e in sorted(state.entities.values(), key=lambda e: (e.type.value, e.number))
    ])


@router.post("/chats/{chat_id}/rules")
def rules(request: Request, chat_id: str, body: RuleIn, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Правка распознавания во всём чате (FR-6.2, 6.3) — как на странице: предпросмотр, затем правка для его версии
    чата; changed — сколько входных текстов изменилось. Замену назначают только фрагменту текста item_id."""
    api_chat(request, chat_id, caller)
    service = service_of(request)
    user_id = caller.user.id
    if body.action == "mask":
        try:
            type_ = EntityType(body.type)
        except ValueError:
            raise HTTPException(422, "Неизвестный тип") from None

        def edit(**options):
            return service.mask_value(chat_id, user_id, body.item_id, body.value, type_, **options)
    else:
        def edit(**options):
            return service.unmask(chat_id, user_id, [body.value], **options)
    try:
        preview = edit(dry=True)
        edit(version=preview.version)
    except EditRefused as exc:
        raise HTTPException(422, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Чат не найден") from None
    return JSONResponse({"changed": len(preview.texts)})
