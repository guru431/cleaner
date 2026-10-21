"""Чаты: список с поиском, лента, ввод текста и ответа модели, состояние обработки, скачивание."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from cleaner.engines import local_settings
from cleaner.service import LOCAL_PENDING, AnswerView, ChatView, EditRefused, InputView, TextTooLong, local_pending
from cleaner.storage.repo import Chat, CheckpointBusy, Item
from cleaner.web import render
from cleaner.web.deps import Upload, Viewer, get_form, get_upload, get_viewer, own_chat, page, repo_of, service_of

log = logging.getLogger("cleaner.web")
router = APIRouter()
_TITLE = 200
LAYER_NAMES = {"ner": "Слой 4 — модели распознавания имён", "llm": "Слой 5 — локальная модель"}
# Подписи слоёв 4 и 5 для обычной работы — по тому, что они дают: номер слоя требует знать устройство Cleaner и стоит
# в пояснении (LAYER_NAMES) — в подсказке переключателя, в предупреждении проверки, в настройках умолчаний.
LAYER_LABELS = {"ner": "Имена и организации", "llm": "Допроверка локальной моделью"}
OCR_ALL = "Распознать текст на всех страницах PDF"      # подпись отметки в форме «Файл» и совет в предупреждениях
_LISTED_PAGES = 5           # больше — в заголовке ленты число, а не номера: список целиком — на экране проверки


def partial_extraction(meta: dict[str, object]) -> str:
    """Что из файла не попало в текст или могло не попасть — для «извлечено частично» в ленте. Только номера
    страниц и число листов из meta (FR-11.2)."""
    pages = sorted(set(meta.get("unread_pages", [])) | set(meta.get("doubtful_pages", [])))
    parts = []
    if pages:
        parts.append(f"страниц — {len(pages)}" if len(pages) > _LISTED_PAGES else
                     f"страниц{'а' if len(pages) == 1 else 'ы'} {', '.join(str(number) for number in pages)}")
    if meta.get("hidden_sheets"):
        parts.append(f"скрытых листов — {meta['hidden_sheets']}")
    return "; ".join(parts)


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


def layers_ran(item: Item) -> str:
    """Слои, выполненные для текста. Без отметки — текст очищен до слоёв 4 и 5 (этап 1), их не было (m-12)."""
    ran = item.meta.get("layers") or []
    return ", ".join(["1–3"] + [number for layer, number in (("ner", "4"), ("llm", "5")) if layer in ran])


def shown_digest(item: Item) -> str:
    """Отпечаток очищенного текста, показанного пользователю: форма «Отметить проверенным» несёт его, и отметка
    ложится только на этот текст (repo.mark_reviewed). Текст и так на странице — отпечаток ничего не добавляет."""
    return hashlib.sha256((item.sanitized or "").encode("utf-8")).hexdigest()


STAGES = ("Исходник", "Проверка", "Передача", "Восстановленный ответ")


def route(view: ChatView, chat_id: str, chosen: bool) -> dict[str, object]:
    """Маршрут чата (аудит интерфейса 21.10.2026): этап по последним элементам, готовность текстов и основное действие
    следующего шага. Готовность — по всем входным текстам чата: запрос собирается из всей истории (раздел 10.1), и
    текст, изменённый правкой после прошлого ответа, уйдёт в новом виде. Подсказка, а не запрет: копирование и
    отправку решают проверка утечек и политики, как прежде."""
    entries = view.items
    if not entries:
        return {"stage": 0, "state": "", "action": None, "hint": "Вставьте текст или загрузите файл ниже"}
    last = entries[-1]
    if isinstance(last, AnswerView):
        if last.item.status in ("queued", "running"):
            return {"stage": 3, "state": "", "action": None, "hint": "Модель отвечает…"}
        if last.item.status != "failed" and not last.item.meta.get("aborted"):
            return {"stage": 3, "state": "", "action": None, "hint": "Продолжить — следующий текст или вопрос ниже"}
        # Ответ не получен — вопрос уходит снова (FR-8.9): этап передачи.
    inputs = [entry for entry in entries if isinstance(entry, InputView)]
    ready = [entry.readiness for entry in inputs]
    if "processing" in ready:
        return {"stage": 0, "state": "processing", "action": None, "hint": "Дождитесь очистки"}
    for state in ("blocked", "review"):
        first = next((entry for entry in inputs if entry.readiness == state), None)
        if first is not None:
            return {"stage": 1, "state": state, "action": ("Проверить", f"/chats/{chat_id}/items/{first.item.id}"), "hint": ""}
    if "reviewed" not in ready:
        first = inputs[-1] if inputs else None
        return {"stage": 0, "state": "failed" if first else "", "hint": "",
                "action": ("Открыть", f"#item-{first.item.id}") if first else None}
    if chosen:
        return {"stage": 2, "state": "reviewed", "action": ("Подтвердить отправку…", f"/chats/{chat_id}/send"), "hint": ""}
    return {"stage": 2, "state": "reviewed", "action": ("Копировать очищенное…", f"/chats/{chat_id}/manual"),
            "hint": "ответ модели — затем во вкладку «Ответ вручную»"}


def _entries(view: ChatView) -> list[dict[str, object]]:
    names = render.surrogates_by_entity(view.state)
    entries: list[dict[str, object]] = []
    for entry in view.items:
        item = entry.item
        if isinstance(entry, InputView):
            common = {
                "kind": "input", "id": item.id, "seq": item.seq, "source": item.source, "status": item.status,
                "readiness": entry.readiness,
            }
            if item.status != "done":
                entries.append(common | {
                    "error": item.meta.get("error", ""), "progress": item.meta.get("progress", ""),
                    "retry": can_retry(item),
                })
                continue
            blocked = render.blocked_at(entry.blocked)
            entries.append(common | {
                "deliverable": entry.deliverable, "leaks": len(entry.leaks), "blocked": len(entry.blocked),
                "partial": partial_extraction(item.meta), "layers": layers_ran(item),
                "ocr": len(item.meta.get("ocr_pages", [])),
                "exposed": [", ".join(names.get(entity_id, ["?"])) for entity_id in item.exposed],
                "html": render.highlight(item.sanitized or "", render.sanitized_marks(item, view.state, entry.leaks, blocked)),
            })
        else:
            entries.append({
                "kind": "answer", "id": item.id, "seq": item.seq, "raw": item.original, "source": item.source,
                "status": item.status, "error": item.meta.get("error", ""), "model": item.meta.get("model", ""),
                "provider": item.meta.get("provider", ""), "counters": entry.result.counters,
                "html": render.highlight(entry.result.text, render.restored_marks(entry.result.segments)),
            })
    return entries


def _local_hint(request: Request) -> str:
    """Куда уходят оригиналы с вопросом локальной модели (FR-9.4). Адрес бывает и частным, и доверенным (FR-9.1, SEC-12),
    и тогда это уже другой сервер. Показываются только узел и порт: учётные данные в адресе — не для подсказки."""
    parts = urlsplit(local_settings(repo_of(request)).url)
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    node = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if loopback:
        return f"Без очистки: оригиналы остаются на этом сервере (локальная модель по адресу {node})"
    return f"Без очистки: оригиналы уходят локальной модели на узел {node}"


def _choices(request: Request) -> list[tuple[str, str]]:
    """Подключения и модели для выбора в чате (FR-8.3): значение «id|модель» и подпись."""
    return [
        (f"{provider.id}|{model}", f"{provider.name} — {model}")
        for provider in repo_of(request).providers() if provider.enabled for model in provider.models
    ]


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
    provider_id, model = repo_of(request).chat_provider(chat_id)
    return page(
        request, "chat.html", viewer, chat=chat, chats=chat_list(request, viewer, q), q=q, entries=_entries(view),
        max_file_mb=request.app.state.max_file_bytes // (1024 * 1024), ocr_all=OCR_ALL,
        layers=service_of(request).layers(chat_id), layer_names=LAYER_NAMES, layer_labels=LAYER_LABELS,
        choices=_choices(request), chosen=f"{provider_id}|{model}" if provider_id else "",
        route=route(view, chat_id, bool(provider_id)), stages=STAGES,
        local=request.app.state.engines is not None,
        local_hint=_local_hint(request) if request.app.state.engines is not None else "",
        local_pending=LOCAL_PENDING if local_pending(entry.item for entry in view.items) else "",
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
    repo = repo_of(request)
    service_of(request).stop_chat(chat_id)          # идущие ответы облака — прервать, а не дочитывать впустую
    try:
        repo.delete_chat(chat_id)
    except CheckpointBusy as exc:
        # Удаление состоялось; копии страниц в журнале WAL сотрёт следующая контрольная точка — администратору в журнал.
        log.error("удаление чата: %s", type(exc).__name__)
        repo.audit("error", viewer.user.id, chat_id, kind=type(exc).__name__, stage="delete")
    repo.audit("chat_deleted", viewer.user.id, chat_id)
    return RedirectResponse("/chats", status_code=303)


@router.post("/chats/{chat_id}/input")
def add_input(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    text = form.get("text", "")
    if not text.strip():
        raise HTTPException(400, "Вставьте текст")
    try:
        item = service_of(request).add_input(chat_id, viewer.user.id, text, form.get("source", "paste"))
    except TextTooLong as exc:
        raise HTTPException(413, str(exc)) from None
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}/items/{item.id}", status_code=303)


@router.post("/chats/{chat_id}/upload")
def upload(request: Request, chat_id: str, upload: Upload = Depends(get_upload), viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    item = service_of(request).add_file(chat_id, viewer.user.id, upload.filename, upload.data, upload.ocr_all)
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


@router.post("/chats/{chat_id}/items/{item_id}/reviewed")
def mark_reviewed(request: Request, chat_id: str, item_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """«Отметить проверенным» на экране проверки: отметка показанного очищенного текста (поле digest)."""
    own_chat(request, chat_id, viewer)
    try:
        service_of(request).mark_reviewed(chat_id, viewer.user.id, item_id, form.get("digest", ""))
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Текст не найден") from None
    return RedirectResponse(f"/chats/{chat_id}/items/{item_id}", status_code=303)


@router.post("/chats/{chat_id}/layers")
def set_layer(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """FR-3.8: слои 4 и 5 отключаются для чата явным действием; действует на следующие очистки."""
    own_chat(request, chat_id, viewer)
    try:
        service_of(request).set_layer(chat_id, viewer.user.id, form.get("layer", ""), form.get("enabled") == "yes")
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    return RedirectResponse(f"/chats/{chat_id}", status_code=303)


@router.get("/chats/{chat_id}/items/{item_id}/download")
def download(request: Request, chat_id: str, item_id: str, viewer: Viewer = Depends(get_viewer)) -> Response:
    own_chat(request, chat_id, viewer)
    entry = input_view(service_of(request).view(chat_id, item_id), item_id)
    if not entry.deliverable:
        raise HTTPException(409, "Выдача заблокирована: текст не обработан, в нём найден оригинал или фрагмент запрещённого типа")
    return Response(
        entry.item.sanitized,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="cleaned-{entry.item.seq}.txt"'},
    )
