"""Экран проверки, правки пользователя и таблица замен чата (FR-6, FR-1.6)."""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from cleaner.core.types import EntityType
from cleaner.service import ChatService, EditRefused
from cleaner.storage.repo import Item
from cleaner.web import render
from cleaner.web.deps import Viewer, get_admin, get_form, get_viewer, own_chat, page, repo_of, service_of
from cleaner.web.routes_chats import can_retry, input_view

router = APIRouter()
_ITEM_ID = re.compile(r"[0-9a-f]{32}")
_NOTICES = {
    "surrogate_in_input": "В тексте есть замены этого чата — они оставлены как есть.",
    "foreign_label": "В тексте есть строки вида метки, которых нет в таблице чата: в ответе модели они не восстановятся.",
}


def _type(form: dict[str, str]) -> EntityType:
    try:
        return EntityType(form.get("type", ""))
    except ValueError:
        raise HTTPException(400, "Неизвестный тип") from None


def _back(chat_id: str, form: dict[str, str]) -> str:
    """Возврат после правки: к экрану проверки текста, иначе в таблицу замен. Адрес собирается здесь, не из формы."""
    item_id = form.get("item_id", "")
    return f"/chats/{chat_id}/items/{item_id}" if _ITEM_ID.fullmatch(item_id) else f"/chats/{chat_id}/entities"


def _pages(numbers: list[int]) -> str:
    return ", ".join(str(number) for number in numbers)


def _warnings(item: Item) -> list[str]:
    """Предупреждения экрана проверки о происхождении текста и о слоях (FR-2.5, FR-6.7)."""
    warnings = []
    if item.meta.get("ocr_pages"):
        warnings.append(
            f"Текст получен распознаванием изображения (страницы: {_pages(item.meta['ocr_pages'])}). "
            "Распознавание ошибается в именах и числах — проверьте замены особенно внимательно."
        )
    if item.meta.get("unread_pages"):
        warnings.append(
            f"На страницах {_pages(item.meta['unread_pages'])} распознавание не нашло текста: "
            "их содержимое в очищенный текст не попало."
        )
    return warnings


def _edit(
    request: Request, chat_id: str, viewer: Viewer, form: dict[str, str], action: Callable[[ChatService], None]
) -> Response:
    own_chat(request, chat_id, viewer)
    try:
        action(service_of(request))
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Сущность не найдена") from None
    return RedirectResponse(_back(chat_id, form), status_code=303)


@router.get("/chats/{chat_id}/items/{item_id}")
def review(request: Request, chat_id: str, item_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    chat = own_chat(request, chat_id, viewer)
    view = service_of(request).view(chat_id)
    entry = input_view(view, item_id)
    item, state = entry.item, view.state
    if item.status != "done":
        return page(request, "review.html", viewer, chat=chat, item=item, pending=True, retry=can_retry(item))
    names = render.surrogates_by_entity(state)
    fragments, seen = [], set()
    for span in sorted(item.spans, key=lambda s: s["start"]):
        value = item.original[span["start"]:span["end"]]
        entity = state.entities.get(span["entity_id"])
        if entity is None or value.lower() in seen:
            continue
        seen.add(value.lower())
        fragments.append({"value": value, "surrogate": span["surrogate"], "type": render.TYPE_NAMES[entity.type]})
    blocked = frozenset(span["entity_id"] for span in entry.blocked)
    notices = Counter(notice["code"] for notice in item.notices)
    return page(
        request, "review.html", viewer, chat=chat, item=item, deliverable=entry.deliverable,
        leaks=len(entry.leaks), blocked=len(entry.blocked),
        original=render.highlight(item.original, render.original_marks(item, state)),
        sanitized=render.highlight(item.sanitized or "", render.sanitized_marks(item, state, entry.leaks, blocked)),
        summary=render.summary(item, state), fragments=fragments,
        notices=[(_NOTICES.get(code, code), count) for code, count in notices.items()],
        exposed=[", ".join(names.get(entity_id, ["?"])) for entity_id in item.exposed],
        types=render.TYPE_NAMES, pending=False, retry=can_retry(item), warnings=_warnings(item),
    )


@router.post("/chats/{chat_id}/items/{item_id}/gold")
def save_gold(request: Request, chat_id: str, item_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    try:
        service_of(request).save_gold(chat_id, viewer.user.id, item_id)
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Текст не найден") from None
    return RedirectResponse(f"/chats/{chat_id}/items/{item_id}", status_code=303)


@router.post("/chats/{chat_id}/mask")
def mask(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service: service.mask_value(
        chat_id, viewer.user.id, form.get("item_id", ""), form.get("value", ""), _type(form)
    ))


@router.post("/chats/{chat_id}/unmask")
def unmask(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service: service.unmask(
        chat_id, viewer.user.id, [form.get("value", "")]
    ))


@router.post("/chats/{chat_id}/refresh")
def refresh(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service: service.refresh(chat_id, viewer.user.id))


@router.get("/chats/{chat_id}/entities")
def entities(request: Request, chat_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    chat = own_chat(request, chat_id, viewer)
    view = service_of(request).view(chat_id)
    names = render.surrogates_by_entity(view.state)
    counts = Counter(
        span["entity_id"] for entry in view.items if entry.item.kind == "input" for span in entry.item.spans
    )
    ordered = sorted(view.state.entities.values(), key=lambda e: (e.type.value, e.number))
    rows = [
        {
            "id": e.id, "type": e.type, "type_name": render.TYPE_NAMES[e.type], "surrogates": names.get(e.id, []),
            "restore_value": e.restore_value, "forms": e.forms, "count": counts[e.id],
            "peers": [(p.id, ", ".join(names.get(p.id, ["?"]))) for p in ordered if p.type is e.type and p.id != e.id],
        }
        for e in ordered
    ]
    return page(request, "entities.html", viewer, chat=chat, rows=rows, types=render.TYPE_NAMES)


@router.post("/chats/{chat_id}/entities/merge")
def merge(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service: service.merge(
        chat_id, viewer.user.id, form.get("keep", ""), form.get("drop", "")
    ))


@router.post("/chats/{chat_id}/entities/{entity_id}/retype")
def retype(request: Request, chat_id: str, entity_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service: service.retype(
        chat_id, viewer.user.id, entity_id, _type(form)
    ))


@router.post("/chats/{chat_id}/entities/{entity_id}/restore-value")
def restore_value(request: Request, chat_id: str, entity_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service: service.set_restore_value(
        chat_id, viewer.user.id, entity_id, form.get("value", "")
    ))


@router.post("/chats/{chat_id}/entities/{entity_id}/unmask")
def unmask_entity(request: Request, chat_id: str, entity_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    def action(service: ChatService) -> None:
        entity = repo_of(request).load_state(chat_id)[0].entities[entity_id]        # KeyError — 404
        service.unmask(chat_id, viewer.user.id, entity.forms or [entity.restore_value])

    return _edit(request, chat_id, viewer, form, action)


@router.post("/chats/{chat_id}/dictionary")
def to_dictionary(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    own_chat(request, chat_id, viewer)
    list_, value = form.get("list", ""), form.get("value", "").strip()
    if list_ not in ("always", "never") or not value:
        raise HTTPException(400, "Укажите значение и список")
    repo = repo_of(request)
    repo.add_dictionary(list_, value, _type(form) if list_ == "always" else None)
    repo.audit("dictionary_changed", viewer.user.id, chat_id, action="add", list=list_)
    service_of(request).refresh(chat_id, viewer.user.id)
    return RedirectResponse(_back(chat_id, form), status_code=303)
