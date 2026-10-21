"""Экран проверки, правки пользователя и таблица замен чата (FR-6, FR-1.6)."""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from collections.abc import Mapping
from urllib.parse import parse_qs, urlencode

from cleaner.core.risk import KINDS
from cleaner.core.types import ChatState, EntityType, Policy
from cleaner.service import ChatService, EditRefused
from cleaner.storage.repo import Item
from cleaner.web import render
from cleaner.web.deps import Viewer, get_admin, get_form, get_viewer, own_chat, page, repo_of, service_of
from cleaner.web.routes_chats import LAYER_NAMES, can_retry, input_view
from cleaner.web.routes_settings import DUPLICATE, POLICY_NAMES

router = APIRouter()
_ITEM_ID = re.compile(r"[0-9a-f]{32}")
_NOTICES = {
    "surrogate_in_input": "В тексте есть замены этого чата — они оставлены как есть.",
    "foreign_label": "В тексте есть строки вида метки, которых нет в таблице чата: в ответе модели они не восстановятся.",
}
# Строк таблицы замен на странице. Без страниц таблица чата с тысячами сущностей — мегабайты HTML и DOM на каждое
# открытие, а прежние списки кандидатов на объединение в каждой строке росли квадратично (аудит 21.10.2026).
ENTITIES_PAGE = 100
_SENIORITY = (
    "Фрагмент нашли несколько слоёв. Где находки пересекаются, тип берётся по старшинству (FR-3.3): решение "
    "пользователя, секрет, подтверждённый формат, остальные правила и словари, модели распознавания имён, локальная модель."
)


def _type(form: dict[str, str]) -> EntityType:
    try:
        return EntityType(form.get("type", ""))
    except ValueError:
        raise HTTPException(400, "Неизвестный тип") from None


def _entities_query(type_: str, number: int) -> str:
    """Фильтр и страница таблицы замен в адресе — только код типа и номер, значений в адресе нет."""
    query = urlencode({key: value for key, value in (("type", type_), ("page", number if number > 1 else "")) if value})
    return f"?{query}" if query else ""


def _back(chat_id: str, form: dict[str, str]) -> str:
    """Возврат после правки: к экрану проверки текста, иначе в таблицу замен — на ту же страницу с тем же фильтром.
    Адрес собирается здесь, не из формы: из поля back берутся только известный код типа и число."""
    item_id = form.get("item_id", "")
    if _ITEM_ID.fullmatch(item_id):
        return f"/chats/{chat_id}/items/{item_id}"
    back = parse_qs(form.get("back", ""))
    type_ = back.get("type", [""])[0]
    number = back.get("page", [""])[0]
    query = _entities_query(
        type_ if type_ in EntityType.__members__ else "", int(number) if number.isdigit() and len(number) < 7 else 1
    )
    return f"/chats/{chat_id}/entities{query}"


def _advice(type_name: str, policy: Policy, sources: list[str]) -> str:
    """Что делать с заменой: снять, сменить тип — или это решение администратора."""
    if policy is Policy.BLOCK:
        return (
            f"Тип «{type_name}» администратор велел блокировать: текст не выдаётся, пока фрагмент в нём. Ошибка "
            "распознавания — снимите замену; неверный тип — смените его в таблице замен; политику меняет администратор."
        )
    if "manual" in sources:
        return "Скрыто решением пользователя в этом чате. Отменить — «Снять замену во всём чате»."
    if sources == ["dict"]:
        return (
            "Значение есть в словаре организации или шаблонах либо уже скрыто в этом чате. Не нужно скрывать — снимите "
            "замену; во всех чатах — администратор добавит его в «никогда не скрывать»."
        )
    return (
        "Ложное срабатывание — «Снять замену во всём чате»; неверный тип — «Сменить тип» в таблице замен; два написания "
        "одного значения — «Присоединить» там же."
    )


def _why(item: Item, state: ChatState, policies: Mapping[EntityType, Policy]) -> dict[str, dict]:
    """Карточка «Почему скрыто» по каждой сущности текста (FR-6.1): тип, кто нашёл, подтверждён ли формат, политика.
    Только коды и слова интерфейса — значений и оригиналов в ней нет (сущность — по замене)."""
    found: dict[str, dict] = {}
    for span in sorted(item.spans, key=lambda s: s["start"]):
        entity = state.entities.get(span["entity_id"])
        if entity is None:
            continue
        entry = found.setdefault(entity.id, {"surrogate": span["surrogate"], "type": entity.type, "codes": set(), "validated": False})
        entry["codes"].update(span.get("sources", ()))
        entry["validated"] |= bool(span.get("validated"))
    why = {}
    for entity_id, entry in found.items():
        codes = [code for code in render.SOURCE_NAMES if code in entry["codes"]]
        policy, name = policies.get(entry["type"], Policy.MASK), render.TYPE_NAMES[entry["type"]]
        why[entity_id] = {
            "surrogate": entry["surrogate"], "type": name, "code": entry["type"].value, "sources": codes,
            "names": [render.SOURCE_NAMES[code] for code in codes], "validated": entry["validated"],
            "policy": POLICY_NAMES[policy], "advice": _advice(name, policy, codes), "seniority": _SENIORITY if len(codes) > 1 else "",
        }
    return why


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
    if item.meta.get("hidden_sheets"):          # только число: имена листов — данные пользователя, а meta не шифруется
        warnings.append(
            f"Скрытые листы книги ({item.meta['hidden_sheets']}) не извлечены: их содержимое в очищенный текст "
            "не попало. Если оно нужно — покажите листы в Excel и загрузите файл снова."
        )
    ran = item.meta.get("layers")
    if ran is None:             # текст очищен до появления слоёв 4 и 5 (этап 1): выключенными они не были (m-12)
        return warnings
    for layer, label in LAYER_NAMES.items():
        if layer not in ran:
            warnings.append(
                f"{label} для этого текста не выполнялся: слой выключен. Если он нужен — включите его для чата "
                "и нажмите «Очистить заново всеми включёнными слоями»."
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
    view = service_of(request).view(chat_id, item_id)
    entry = input_view(view, item_id)
    item, state = entry.item, view.state
    if item.status != "done":
        return page(request, "review.html", viewer, chat=chat, item=item, pending=True, retry=can_retry(item))
    names = render.surrogates_by_entity(state)
    why = _why(item, state, view.settings.policies)
    fragments, seen = [], set()
    for span in sorted(item.spans, key=lambda s: s["start"]):
        value = item.original[span["start"]:span["end"]]
        entity = state.entities.get(span["entity_id"])
        if entity is None or value.lower() in seen:
            continue
        seen.add(value.lower())
        fragments.append({
            "value": value, "surrogate": span["surrogate"], "type": render.TYPE_NAMES[entity.type], "why": why[entity.id],
        })
    blocked = frozenset(span["entity_id"] for span in entry.blocked)
    notices = Counter(notice["code"] for notice in item.notices)
    # Легенда над панелями — типы этого текста словами (кнопки-фильтры), затем состояния, которые тоже выделены цветом.
    legend = list(dict.fromkeys((f"t-{w['code']}", w["type"]) for w in sorted(why.values(), key=lambda w: w["code"])))
    if blocked:
        legend.append(("blocked", "блокировка по политике"))
    if entry.leaks:
        legend.append(("leak", "оригинал в очищенном"))
    sources = [(code, label) for code, label in render.SOURCE_NAMES.items() if any(code in w["sources"] for w in why.values())]
    return page(
        request, "review.html", viewer, chat=chat, item=item, deliverable=entry.deliverable,
        leaks=len(entry.leaks), blocked=len(entry.blocked),
        original=render.highlight(item.original, render.original_marks(item, state)),
        sanitized=render.highlight(item.sanitized or "", render.sanitized_marks(item, state, entry.leaks, blocked)),
        summary=render.summary(item, state), fragments=fragments, why=why, legend=legend, sources=sources,
        notices=[(_NOTICES.get(code, code), count) for code, count in notices.items()],
        exposed=[", ".join(names.get(entity_id, ["?"])) for entity_id in item.exposed],
        types=render.TYPE_NAMES, pending=False, retry=can_retry(item), warnings=_warnings(item),
        risk=repo_of(request).item_risk(chat_id, item_id) if item.risk_status == "done" else None, risk_kinds=KINDS,
    )


@router.post("/chats/{chat_id}/items/{item_id}/risk")
def check_risk(request: Request, chat_id: str, item_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    try:
        service_of(request).check_risk(chat_id, viewer.user.id, item_id)
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Текст не найден") from None
    return RedirectResponse(f"/chats/{chat_id}/items/{item_id}", status_code=303)


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
    # Таблице нужны состояние и замены текстов, а не вид чата: проверка утечек и восстановление ответов ей ни к чему.
    repo = repo_of(request)
    state, _ = repo.load_state(chat_id)
    names = render.surrogates_by_entity(state)
    counts = Counter(span["entity_id"] for item in repo.items(chat_id) if item.kind == "input" for span in item.spans)
    ordered = sorted(state.entities.values(), key=lambda e: (e.type.value, e.number))
    by_type = Counter(e.type for e in ordered)
    # Фильтр по типу и страница — в адресе (коды и номер, не значения); неизвестный тип — отказ, номер — в пределах.
    code = request.query_params.get("type", "")
    shown_type = _type({"type": code}) if code else None
    chosen = [e for e in ordered if shown_type is None or e.type is shown_type]
    pages = max(1, -(-len(chosen) // ENTITIES_PAGE))
    raw = request.query_params.get("page", "1")
    number = min(pages, max(1, int(raw))) if raw.isdigit() and len(raw) < 7 else 1
    shown = chosen[(number - 1) * ENTITIES_PAGE:number * ENTITIES_PAGE]
    rows = [
        {
            "id": e.id, "type": e.type, "type_name": render.TYPE_NAMES[e.type], "surrogates": names.get(e.id, []),
            "restore_value": e.restore_value, "forms": e.forms, "count": counts[e.id], "peers": by_type[e.type] > 1,
        }
        for e in shown
    ]
    # Кандидаты на объединение — один список на тип для всей страницы (O(n), а не список в каждой строке): замены
    # каждой сущности типа, подписанные её значением при восстановлении, — оно и так видно в этой таблице.
    peers = {
        type_: [(text, e.restore_value) for e in ordered if e.type is type_ for text in names.get(e.id, [])]
        for type_ in dict.fromkeys(row["type"] for row in rows if row["peers"])
    }
    return page(
        request, "entities.html", viewer, chat=chat, rows=rows, types=render.TYPE_NAMES, peers=peers,
        present=[(type_, render.TYPE_NAMES[type_], by_type[type_]) for type_ in by_type], shown_type=shown_type,
        total=len(ordered), chosen=len(chosen), first=(number - 1) * ENTITIES_PAGE + 1, number=number, pages=pages,
        query=lambda target: _entities_query(code, target), back=_entities_query(code, number).lstrip("?"),
    )


@router.post("/chats/{chat_id}/entities/merge")
def merge(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    # Присоединяемая сущность — по её замене (поле со списком кандидатов): тот же ли тип, проверяет ChatService.merge.
    def action(service: ChatService) -> None:
        surrogate = repo_of(request).load_state(chat_id)[0].surrogates.get(form.get("surrogate", "").strip())
        if surrogate is None:
            raise EditRefused("такой замены в таблице чата нет")
        service.merge(chat_id, viewer.user.id, form.get("keep", ""), surrogate.entity_id)

    return _edit(request, chat_id, viewer, form, action)


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
    if repo.in_dictionary(list_, value):
        raise HTTPException(400, DUPLICATE)
    repo.add_dictionary(list_, value, _type(form) if list_ == "always" else None)
    repo.audit("dictionary_changed", viewer.user.id, chat_id, action="add", list=list_)
    service_of(request).refresh(chat_id, viewer.user.id)
    return RedirectResponse(_back(chat_id, form), status_code=303)
