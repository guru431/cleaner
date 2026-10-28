"""JSON-API для программ (FR-13; спецификация 2026-10-28, раздел 15): тонкий вход в ту же ChatService, что у
веб-интерфейса. Открывается только ключом доступа; чаты API — обычные чаты владельца ключа, видимые в интерфейсе."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from cleaner.web.deps import ApiCaller, api_chat, get_api_caller, repo_of, service_of

router = APIRouter(prefix="/api/v1")
_TITLE = 200


class ChatIn(BaseModel):
    title: str = ""
    label_style: Literal["angle", "square"] = "angle"
    layers: dict[Literal["ner", "llm"], bool] = {}


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
