"""JSON-API для программ (FR-13; спецификация 2026-10-28, раздел 15): тонкий вход в ту же ChatService, что у
веб-интерфейса. Открывается только ключом доступа; чаты API — обычные чаты владельца ключа, видимые в интерфейсе."""
from __future__ import annotations

import asyncio
import json
import time
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from cleaner.core.types import ChatState, EntityType
from cleaner.core.detect.base import DetectorError
from cleaner.core.detect.llm import CompletionError
from cleaner.service import EditRefused, InputView, SendRefused, TextTooLong
from cleaner.integration import IntegrationService, provider_for
from cleaner.core.restore import StreamRestorer, restore as restore_text
from cleaner.web import render
from cleaner.web.deps import (
    ApiCaller, Upload, api_chat, api_writable_chat, get_api_caller, get_api_upload, repo_of, service_of,
)
from cleaner.web.routes_chats import input_view

router = APIRouter(prefix="/api/v1")
_TITLE = 200
_WORKING = ("queued", "running")
_POLL = 0.2                 # как часто маршрут texts смотрит, готов ли текст, пока ждёт wait секунд


class Body(BaseModel):
    """Тело запроса программы. Строка с «\\ud800» без пары — допустимый JSON, но не текст: её не закодировать в UTF-8
    для шифрования и базы. Отказ — 422, как у неверного тела, а не внутренняя ошибка."""

    @field_validator("*")
    @classmethod
    def _utf_8(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError("строка не в UTF-8") from None
        return value


class ChatIn(Body):
    title: str = ""
    label_style: Literal["angle", "square"] = "angle"
    layers: dict[Literal["ner", "llm"], bool] = {}


class TextIn(Body):
    text: str
    wait: int = Field(30, ge=0, le=60)


class AnswerIn(Body):
    text: str


class RuleIn(Body):
    action: Literal["mask", "unmask"]
    value: str
    item_id: str = ""           # mask: текст, в котором есть фрагмент, — как выделение на экране проверки
    type: str = ""              # mask: код типа (EntityType)


class RequestMessage(Body):
    role: Literal["system", "user", "assistant"]
    content: str


class RequestRule(Body):
    action: Literal["mask", "unmask"]
    value: str = Field(min_length=1, max_length=2000)
    type: EntityType | None = None


class RequestIn(Body):
    model: str = Field(min_length=1, max_length=200)
    messages: list[RequestMessage] = Field(min_length=1, max_length=1000)
    rules: list[RequestRule] = Field(default_factory=list, max_length=100)


class SendRequestIn(Body):
    receipt: str = Field(min_length=1, max_length=24_000_000)


class LocalRequestIn(Body):
    messages: list[RequestMessage] = Field(min_length=1, max_length=1000)


def _request_caller(request: Request, chat_id: str, caller: ApiCaller = Depends(get_api_caller)) -> ApiCaller:
    # Ownership must be checked before body validation, including malformed bodies from another owner.
    api_writable_chat(request, chat_id, caller)
    return caller


@router.get("/models")
def integration_models(request: Request, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    try:
        _, models = provider_for(repo_of(request), caller.key)
    except SendRefused as exc:
        raise HTTPException(403, str(exc)) from None
    return JSONResponse({"data": [{"id": model} for model in models]})


@router.post("/chats/{chat_id}/requests")
def prepare_request(request: Request, chat_id: str, body: RequestIn,
                    caller: ApiCaller = Depends(_request_caller)) -> Response:
    api_writable_chat(request, chat_id, caller)
    if body.messages[-1].role != "user":
        raise HTTPException(422, "Последним в запросе должен быть вопрос")
    try:
        result = IntegrationService.from_service(service_of(request)).prepare_request(
            chat_id, caller.user.id, caller.key, body.model, [m.model_dump() for m in body.messages],
            [rule.model_dump() for rule in body.rules],
        )
    except TextTooLong as exc:
        raise HTTPException(413, str(exc)) from None
    except (SendRefused, EditRefused) as exc:
        raise HTTPException(409, str(exc)) from None
    except (DetectorError, CompletionError):
        raise HTTPException(503, "Очистка не выполнена: запрос не отправлен облачной модели") from None
    return JSONResponse(result)


@router.post("/chats/{chat_id}/requests/send", status_code=202)
def send_request(request: Request, chat_id: str, body: SendRequestIn,
                 caller: ApiCaller = Depends(_request_caller)) -> Response:
    api_writable_chat(request, chat_id, caller)
    try:
        item = IntegrationService.from_service(service_of(request)).send_request(
            chat_id, caller.user.id, caller.key, body.receipt,
        )
    except (SendRefused, EditRefused) as exc:
        raise HTTPException(409, str(exc)) from None
    return JSONResponse({"item_id": item.id}, status_code=202)


@router.get("/chats/{chat_id}/answers/{item_id}/events")
def answer_events(request: Request, chat_id: str, item_id: str,
                  caller: ApiCaller = Depends(get_api_caller)) -> Response:
    api_chat(request, chat_id, caller)
    repo, service = repo_of(request), service_of(request)
    item = repo.item(chat_id, item_id)
    if item is None or item.kind != "answer" or item.source not in ("api", "local"):
        raise HTTPException(404, "Ответ не найден")
    state, _ = repo.load_state(chat_id)
    settings = repo.settings()
    restorer, live = StreamRestorer(state, settings), service.live.get(item_id)

    def event(kind, data):
        return f"event: {kind}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

    async def events():
        seen = 0
        while True:
            if await request.is_disconnected():
                return
            if live is not None:
                text = live.text()
                if len(text) > seen:
                    # Весь префикс, а не прирост (контракт docs/studio-api.md): клиент заменяет показанный текст.
                    shown = text if item.source == "local" else await run_in_threadpool(restorer.feed, text[seen:])
                    seen = len(text)
                    yield event("text", {"text": shown})
            if live is None or live.finished:
                final = await run_in_threadpool(repo.item, chat_id, item_id)
                if final is None:
                    yield event("done", {"status": "failed", "error": "Ответ удалён"})
                    return
                result = None if item.source == "local" else await run_in_threadpool(restore_text, state, final.original, settings)
                yield event("done", {"status": final.status, "text": result.text if result else final.original, "raw": final.original,
                                     "counters": result.counters if result else {}, "error": final.meta.get("error", "")})
                return
            yield ": keepalive\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})


@router.post("/chats/{chat_id}/answers/{item_id}/stop", status_code=204)
def stop_answer(request: Request, chat_id: str, item_id: str,
                caller: ApiCaller = Depends(get_api_caller)) -> Response:
    api_chat(request, chat_id, caller)
    item = repo_of(request).item(chat_id, item_id)
    if item is None or item.kind != "answer" or item.source not in ("api", "local"):
        raise HTTPException(404, "Ответ не найден")
    try:
        service_of(request).stop(chat_id, item_id)
    except KeyError:
        pass  # Generation may finish between the ownership check and stop.
    return Response(status_code=204)


@router.post("/chats/{chat_id}/local-requests")
def prepare_local_request(request: Request, chat_id: str, body: LocalRequestIn,
                          caller: ApiCaller = Depends(_request_caller)) -> Response:
    if body.messages[-1].role != "user":
        raise HTTPException(422, "Последним в запросе должен быть вопрос")
    try:
        result = IntegrationService.from_service(service_of(request)).prepare_local_request(
            chat_id, caller.user.id, caller.key, [m.model_dump() for m in body.messages])
    except TextTooLong as exc:
        raise HTTPException(413, str(exc)) from None
    except (SendRefused, EditRefused, DetectorError) as exc:
        raise HTTPException(409, str(exc)) from None
    return JSONResponse(result)


@router.post("/chats/{chat_id}/local-requests/send", status_code=202)
def send_local_request(request: Request, chat_id: str, body: SendRequestIn,
                       caller: ApiCaller = Depends(_request_caller)) -> Response:
    try:
        item = IntegrationService.from_service(service_of(request)).send_local_request(chat_id, caller.user.id, caller.key, body.receipt)
    except (SendRefused, EditRefused, DetectorError) as exc:
        raise HTTPException(409, str(exc)) from None
    return JSONResponse({"item_id": item.id}, status_code=202)


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
    return repo_of(request).item_status(chat_id, item_id)


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
    await run_in_threadpool(api_writable_chat, request, chat_id, caller)
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
    """Файл — в очередь разбора (FR-2.2…2.9); результат — опросом GET …/items/{item_id}. У PDF — estimate: страниц,
    на распознавание и минут распознавания; PDF с текстом заведомо длиннее предела — сразу status failed."""
    api_writable_chat(request, chat_id, caller)
    try:
        item = service_of(request).add_file(chat_id, caller.user.id, upload.filename, upload.data, upload.ocr_all,
                                            reservation=upload.reservation)
    except KeyError:
        raise HTTPException(404, "Чат не найден") from None
    estimate = {"estimate": item.meta["estimate"]} if "estimate" in item.meta else {}
    return JSONResponse({"item_id": item.id, "status": item.status} | estimate, status_code=202)


@router.get("/chats/{chat_id}/items/{item_id}")
def item(request: Request, chat_id: str, item_id: str, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Входной текст чата; ответ модели и элемент другого чата — 404, как несуществующий."""
    api_chat(request, chat_id, caller)
    return JSONResponse(_item_result(request, chat_id, item_id))


@router.post("/chats/{chat_id}/restore")
def restore(request: Request, chat_id: str, body: AnswerIn, caller: ApiCaller = Depends(get_api_caller)) -> Response:
    """Ответ модели — элементом чата, как вставленный на странице (FR-7); в ответе — восстановленный текст."""
    api_writable_chat(request, chat_id, caller)
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
    """Правка без предпросмотра: служба повторяет её при смене версии и возвращает сводку записанной правки.
    changed — сколько входных текстов изменилось. Замену назначают только фрагменту текста item_id."""
    api_writable_chat(request, chat_id, caller)
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
        preview = edit(summary=True)
    except EditRefused as exc:
        raise HTTPException(422, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Чат не найден") from None
    return JSONResponse({"changed": len(preview.texts)})
