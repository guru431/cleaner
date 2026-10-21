"""Экран проверки, правки пользователя и таблица замен чата (FR-6, FR-1.6)."""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Mapping
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from cleaner.core.entities import ops
from cleaner.core.match import find_forms
from cleaner.core.risk import KINDS
from cleaner.core.types import ChatState, EntityType, Policy
from cleaner.service import UNDOABLE, ChatService, EditPreview, EditRefused
from cleaner.storage.repo import Item
from cleaner.web import render
from cleaner.web.deps import Viewer, get_admin, get_form, get_viewer, own_chat, page, repo_of, service_of
from cleaner.web.routes_chats import LAYER_LABELS, LAYER_NAMES, OCR_ALL, can_retry, input_view, layers_ran, shown_digest
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
    """Возврат после правки: к экрану проверки текста, на страницу переноса вручную (back=manual — её «Очистить тексты
    чата заново»), иначе в таблицу замен — на ту же страницу с тем же фильтром. Адрес собирается здесь, не из формы:
    из поля back берутся только известные слово, код типа и число."""
    item_id = form.get("item_id", "")
    if _ITEM_ID.fullmatch(item_id):
        return f"/chats/{chat_id}/items/{item_id}"
    if form.get("back") == "manual":
        return f"/chats/{chat_id}/manual"
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
        entry = found.setdefault(
            entity.id, {"surrogate": span["surrogate"], "type": entity.type, "codes": set(), "validated": False, "held": set()},
        )
        entry["codes"].update(span.get("sources", ()))
        entry["validated"] |= bool(span.get("validated"))
        entry["held"].update(EntityType(type_) for type_ in span.get("held", ()))
    why = {}
    for entity_id, entry in found.items():
        codes = [code for code in render.SOURCE_NAMES if code in entry["codes"]]
        policy, name = policies.get(entry["type"], Policy.MASK), render.TYPE_NAMES[entry["type"]]
        advice = _advice(name, policy, codes)
        # Находка «блокировать», скрытая во фрагменте под этой меткой (pipeline._held), держит выдачу и при другой
        # политике метки — карточка говорит, чья политика.
        held = sorted(render.TYPE_NAMES[t] for t in entry["held"] if policies.get(t) is Policy.BLOCK)
        if held and policy is not Policy.BLOCK:
            advice = (
                f"Внутри фрагмента найдено значение типа «{'», «'.join(held)}», который администратор велел блокировать: "
                "текст не выдаётся, пока фрагмент в нём; политику меняет администратор."
            )
        why[entity_id] = {
            "surrogate": entry["surrogate"], "type": name, "code": entry["type"].value, "sources": codes,
            "names": [render.SOURCE_NAMES[code] for code in codes], "validated": entry["validated"],
            "policy": POLICY_NAMES[policy], "advice": advice, "seniority": _SENIORITY if len(codes) > 1 else "",
        }
    return why


def _pages(numbers: list[int]) -> str:
    """«1–4, 7, 9»: у PDF на сотни страниц список номеров подряд иначе занял бы экран."""
    runs: list[list[int]] = []
    for number in numbers:
        if runs and number == runs[-1][-1] + 1:
            runs[-1].append(number)
        else:
            runs.append([number])
    return ", ".join(f"{run[0]}–{run[-1]}" if len(run) > 2 else ", ".join(map(str, run)) for run in runs)


def _extraction(item: Item) -> str:
    """Как получен текст PDF по страницам. Файл не хранится (FR-2.7): перераспознать страницу можно, только
    загрузив файл ещё раз — с отметкой распознавания всех страниц."""
    meta = item.meta
    if meta.get("kind") != "pdf" or not meta.get("pages"):
        return ""
    ocr = set(meta.get("ocr_pages", []))
    layer = [number for number in range(1, meta["pages"] + 1) if number not in ocr]
    parts = [f"распознаванием — {_pages(sorted(ocr))}"] if ocr else []
    if layer:
        parts.append(f"из слоя текста файла — {_pages(layer)}")
    text = f"PDF, страниц — {meta['pages']}: {'; '.join(parts)}."
    if layer and not meta.get("ocr_all"):
        text += (" Если в оригинале не хватает текста с картинок или слой текста нечитаем — загрузите файл ещё раз "
                 f"с отметкой «{OCR_ALL}».")
    return text


def _warnings(item: Item) -> list[str]:
    """Предупреждения экрана проверки о происхождении текста и о слоях (FR-2.5, FR-6.7). «Извлечено частично» —
    содержимое файла, которое не попало в текст или могло не попасть."""
    warnings = []
    if item.meta.get("ocr_pages"):
        warnings.append(
            f"Текст получен распознаванием изображения (страницы: {_pages(item.meta['ocr_pages'])}). "
            "Распознавание ошибается в именах и числах — проверьте замены особенно внимательно."
        )
    if item.meta.get("unread_pages"):
        warnings.append(
            f"Извлечено частично. На страницах {_pages(item.meta['unread_pages'])} распознавание не нашло текста: "
            "их содержимое в очищенный текст не попало."
        )
    if item.meta.get("doubtful_pages"):
        warnings.append(
            f"Извлечено частично. На страницах {_pages(item.meta['doubtful_pages'])} изображение занимает большую часть "
            "страницы, но распознать его не удалось: взят только слой текста, содержимое изображения могло не попасть "
            "в очищенный текст. Загрузите файл ещё раз, когда распознавание будет доступно, или сверьте эти страницы с файлом."
        )
    if item.meta.get("hidden_sheets"):          # только число: имена листов — данные пользователя, а meta не шифруется
        warnings.append(
            f"Извлечено частично. Скрытые листы книги ({item.meta['hidden_sheets']}) не извлечены: их содержимое в "
            "очищенный текст не попало. Если оно нужно — покажите листы в Excel и загрузите файл снова."
        )
    if item.meta.get("images"):
        warnings.append(
            f"Встроенных изображений в документе — {item.meta['images']}: текст на них не распознаётся и в очищенный "
            f"текст не попал. Если на них есть нужный текст — сохраните документ как PDF и загрузите его с отметкой «{OCR_ALL}»."
        )
    ran = item.meta.get("layers")
    if ran is None:             # текст очищен до появления слоёв 4 и 5 (этап 1): выключенными они не были (m-12)
        return warnings
    for layer, label in LAYER_NAMES.items():
        if layer not in ran:
            warnings.append(
                f"Переключатель «{LAYER_LABELS[layer]}» ({label[0].lower()}{label[1:]}) был выключен: для этого текста "
                "слой не выполнялся. Если он нужен — включите переключатель в шапке чата и нажмите «Очистить заново "
                "всеми включёнными слоями»."
            )
    return warnings


def _opened(text: str, state: ChatState) -> int:
    """Сколько значений, с которых в этом чате снята замена, стоит открытыми в очищенном тексте. Проверка утечек их
    намеренно пропускает (раздел 8), поэтому её зелёный итог не говорит, что открытых значений нет. Ищутся так же, как
    их вырезает она, — целыми словами."""
    return len({value for _, _, value in find_forms(text, [(value, "letters", value) for value in ops.unmasked(state)])})


def _version(form: dict[str, str]) -> int | None:
    """Версия чата, для которой показан предпросмотр; без поля — правка напрямую, без сверки (прежние формы, тесты)."""
    raw = form.get("version", "")
    if not raw:
        return None
    if not raw.isdigit() or len(raw) > 18:
        raise HTTPException(400, "Неверная версия чата")
    return int(raw)


def _edit(
    request: Request, chat_id: str, viewer: Viewer, form: dict[str, str],
    action: Callable[..., EditPreview | None], what: Callable[[], str] = lambda: "",
) -> Response:
    """Правка — или её предпросмотр, если адрес кончается на /preview: та же работа без записи (ChatService._edit,
    dry). Предпросмотр — ответ на POST, а не страница по GET: значение правки (выделенный фрагмент) — оригинал, и в
    адресе ему не место. Подтверждение повторяет поля формы и добавляет версию чата: изменился чат — отказ."""
    chat = own_chat(request, chat_id, viewer)
    dry = request.url.path.endswith("/preview")
    try:
        preview = action(service_of(request), version=_version(form), dry=dry)
        title = what() if dry else ""
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Сущность не найдена") from None
    if preview is None:
        return RedirectResponse(_back(chat_id, form), status_code=303)
    fields = [(key, value) for key, value in form.items() if key not in ("csrf", "version")]
    target = request.url.path.removesuffix("/preview")
    return page(
        request, "edit_preview.html", viewer, chat=chat, preview=preview, what=title, fields=fields,
        target=target, back=_back(chat_id, form),
        totals={key: sum(getattr(t, key) for t in preview.texts) for key in ("hidden", "opened", "relabeled", "exposed")},
        sent=[t.seq for t in preview.texts if t.sent], undoable=not target.endswith("/undo"),
    )


def _labels(state: ChatState, entity_id: str) -> str:
    """Замены сущности для заголовка предпросмотра — метки, не значения."""
    return ", ".join(render.surrogates_by_entity(state).get(entity_id, [])) or "сущность"


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
    blocked = render.blocked_at(entry.blocked)
    notices = Counter(notice["code"] for notice in item.notices)
    sanitized = item.sanitized or ""
    original_marks = render.original_marks(item, state)
    sanitized_marks = render.sanitized_marks(item, state, entry.leaks, blocked)
    opened_marks = render.opened_marks(item.original, state, original_marks), render.opened_marks(sanitized, state, sanitized_marks)
    # Легенда над панелями — типы этого текста словами (кнопки-фильтры), затем состояния, которые тоже выделены цветом.
    legend = list(dict.fromkeys((f"t-{w['code']}", w["type"]) for w in sorted(why.values(), key=lambda w: w["code"])))
    if blocked:
        legend.append(("blocked", "блокировка по политике"))
    if entry.leaks:
        legend.append(("leak", "оригинал в очищенном"))
    if any(opened_marks):
        legend.append(("opened", render.OPENED.lower()))
    sources = [(code, label) for code, label in render.SOURCE_NAMES.items() if any(code in w["sources"] for w in why.values())]
    return page(
        request, "review.html", viewer, chat=chat, item=item, deliverable=entry.deliverable,
        leaks=len(entry.leaks), blocked=len(entry.blocked), opened=_opened(sanitized, state),
        layers_ran=layers_ran(item), readiness=entry.readiness, shown=shown_digest(item),
        original=render.highlight(item.original, original_marks + opened_marks[0]),
        sanitized=render.highlight(sanitized, sanitized_marks + opened_marks[1]),
        summary=render.summary(item, state), fragments=fragments, why=why, legend=legend, sources=sources,
        notices=[(_NOTICES.get(code, code), count) for code, count in notices.items()],
        exposed=[", ".join(names.get(entity_id, ["?"])) for entity_id in item.exposed],
        types=render.TYPE_NAMES, pending=False, retry=can_retry(item), warnings=_warnings(item), extraction=_extraction(item),
        risk=repo_of(request).item_risk(chat_id, item_id) if item.risk_status == "done" else None, risk_kinds=KINDS,
        undo=repo_of(request).undo_action(chat_id), undo_names=UNDOABLE,
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
@router.post("/chats/{chat_id}/mask/preview")
def mask(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service, **edit: service.mask_value(
        chat_id, viewer.user.id, form.get("item_id", ""), form.get("value", ""), _type(form), **edit
    ), lambda: f"Скрывать во всём чате «{form.get('value', '').strip()}» как «{render.TYPE_NAMES[_type(form)]}»")


@router.post("/chats/{chat_id}/unmask")
@router.post("/chats/{chat_id}/unmask/preview")
def unmask(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service, **edit: service.unmask(
        chat_id, viewer.user.id, [form.get("value", "")], **edit
    ), lambda: f"Снять замену во всём чате с «{form.get('value', '').strip()}»")


@router.post("/chats/{chat_id}/undo")
@router.post("/chats/{chat_id}/undo/preview")
def undo(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """Отмена последней правки — тоже через предпросмотр: она так же пересчитывает все тексты чата."""
    def what() -> str:
        last = repo_of(request).undo_action(chat_id)
        return f"Отменить последнюю правку: {UNDOABLE.get(last[0], '') if last else ''}"

    return _edit(request, chat_id, viewer, form, lambda service, **edit: service.undo(chat_id, viewer.user.id, **edit), what)


@router.post("/chats/{chat_id}/refresh")
def refresh(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service, **_: service.refresh(chat_id, viewer.user.id))


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
        undo=repo.undo_action(chat_id), undo_names=UNDOABLE,
    )


@router.post("/chats/{chat_id}/entities/merge")
@router.post("/chats/{chat_id}/entities/merge/preview")
def merge(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    # Присоединяемая сущность — по её замене (поле со списком кандидатов): тот же ли тип, проверяет ChatService.merge.
    def action(service: ChatService, **edit: object) -> EditPreview | None:
        surrogate = repo_of(request).load_state(chat_id)[0].surrogates.get(form.get("surrogate", "").strip())
        if surrogate is None:
            raise EditRefused("такой замены в таблице чата нет")
        return service.merge(chat_id, viewer.user.id, form.get("keep", ""), surrogate.entity_id, **edit)

    def what() -> str:
        state = repo_of(request).load_state(chat_id)[0]
        return f"Присоединить {form.get('surrogate', '').strip()} к {_labels(state, form.get('keep', ''))}"

    return _edit(request, chat_id, viewer, form, action, what)


@router.post("/chats/{chat_id}/entities/{entity_id}/retype")
@router.post("/chats/{chat_id}/entities/{entity_id}/retype/preview")
def retype(request: Request, chat_id: str, entity_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    return _edit(request, chat_id, viewer, form, lambda service, **edit: service.retype(
        chat_id, viewer.user.id, entity_id, _type(form), **edit
    ), lambda: f"Сменить тип {_labels(repo_of(request).load_state(chat_id)[0], entity_id)} на «{render.TYPE_NAMES[_type(form)]}»")


@router.post("/chats/{chat_id}/entities/{entity_id}/restore-value")
def restore_value(request: Request, chat_id: str, entity_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    # Без предпросмотра: значение для восстановления не меняет ни одного очищенного текста.
    return _edit(request, chat_id, viewer, form, lambda service, **_: service.set_restore_value(
        chat_id, viewer.user.id, entity_id, form.get("value", "")
    ))


@router.post("/chats/{chat_id}/entities/{entity_id}/unmask")
@router.post("/chats/{chat_id}/entities/{entity_id}/unmask/preview")
def unmask_entity(request: Request, chat_id: str, entity_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    def action(service: ChatService, **edit: object) -> EditPreview | None:
        entity = repo_of(request).load_state(chat_id)[0].entities[entity_id]        # KeyError — 404
        return service.unmask(chat_id, viewer.user.id, entity.forms or [entity.restore_value], **edit)

    return _edit(request, chat_id, viewer, form, action, lambda: (
        f"Снять замену {_labels(repo_of(request).load_state(chat_id)[0], entity_id)} во всём чате"
    ))


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
