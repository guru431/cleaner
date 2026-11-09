"""Чаты: список с поиском, лента, ввод текста и ответа модели, состояние обработки, скачивание."""
from __future__ import annotations

import bisect
import hashlib
import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from cleaner.core import leakcheck
from cleaner.core.agent import walk
from cleaner.core.types import ChatState, EntityType, Settings
from cleaner.engines import local_settings
from cleaner.service import LOCAL_PENDING, AnswerView, ChatView, EditRefused, InputView, TextTooLong, local_pending
from cleaner.storage.repo import Chat, Item
from cleaner.web import render
from cleaner.web.deps import (
    Upload, Viewer, get_form, get_upload, get_viewer, own_chat, page, repo_of, service_of, writable_chat,
)

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
    pages = sorted(set(meta.get("unread_pages", [])) | set(meta.get("doubtful_pages", [])) | set(meta.get("failed_pages", [])))
    parts = []
    if pages:
        parts.append(f"страниц — {len(pages)}" if len(pages) > _LISTED_PAGES else
                     f"страниц{'а' if len(pages) == 1 else 'ы'} {', '.join(str(number) for number in pages)}")
    if meta.get("hidden_sheets"):
        parts.append(f"скрытых листов — {meta['hidden_sheets']}")
    return "; ".join(parts)


@dataclass(frozen=True)
class ListedChat(Chat):
    agent_key: str = ""
    last_request: str = ""


def chat_filter(request: Request) -> str:
    selected = request.query_params.get("kind", request.cookies.get("cleaner-chat-kind", "all"))
    return selected if selected in ("all", "chat", "agent") else "all"


def chat_list(request: Request, viewer: Viewer, query: str = "") -> list[ListedChat]:
    """Поиск по расшифрованным названиям и именам ключей — только среди чатов владельца."""
    repo = repo_of(request)
    selected = chat_filter(request)
    keys = {key.id: key.name for key in repo.api_keys(viewer.user.id)}
    chats = []
    for chat in repo.chats(viewer.user.id):
        if selected != "all" and chat.kind != selected:
            continue
        conversations = repo.chat_conversations(chat.id) if chat.kind == "agent" else []
        names = ", ".join(dict.fromkeys(keys[c.key_id] for c in conversations if c.key_id in keys))
        last = max((c.last_seen for c in conversations), default="")
        chats.append(ListedChat(**vars(chat), agent_key=names, last_request=last))
    needle = query.strip().lower()
    return [chat for chat in chats if needle in f"{chat.title} {chat.agent_key}".lower()] if needle else chats


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


def no_question(view: ChatView) -> str:
    """Почему передавать нечего — подсказка недоступных кнопок передачи: последним в запросе должен быть вопрос
    (раздел 10.1). Ответ, не полученный или оборванный ошибкой, не ход диалога — вопрос уходит снова (FR-8.9).
    Пусто — передать можно."""
    if not view.items:
        return "В чате ещё нет текста: сначала добавьте текст или вопрос"
    last = view.items[-1]
    if isinstance(last, AnswerView) and last.item.status != "failed" and not last.item.meta.get("aborted"):
        return "Последним в чате стоит ответ: сначала добавьте текст или вопрос"
    return ""


def route(view: ChatView, chat_id: str, chosen: bool) -> dict[str, object]:
    """Маршрут чата (аудит интерфейса 21.10.2026): этап по последним элементам, готовность текстов и основное действие
    следующего шага. Готовность — по всем входным текстам чата: запрос собирается из всей истории (раздел 10.1), и
    текст, изменённый правкой после прошлого ответа, уйдёт в новом виде. Подсказка, а не запрет: копирование и
    отправку решают проверка утечек и политики, как прежде."""
    entries = view.items
    if not entries:
        return {"stage": 0, "state": "", "action": None, "hint": "Вставьте текст или загрузите файл ниже"}
    last = entries[-1]
    inputs = [entry for entry in entries if isinstance(entry, InputView)]
    if isinstance(last, AnswerView):
        # Проверка пройдена, только если все тексты отмечены проверенными; иначе этап «пропущен», а не зелёная галочка.
        skipped = (1,) if any(entry.readiness not in ("reviewed", "failed") for entry in inputs) else ()
        if last.item.status in ("queued", "running"):
            return {"stage": 3, "state": "", "action": None, "hint": "Модель отвечает…", "skipped": skipped}
        if last.item.status != "failed" and not last.item.meta.get("aborted"):
            return {"stage": 3, "state": "", "action": None, "hint": "Продолжить — следующий текст или вопрос ниже",
                    "skipped": skipped}
        # Ответ не получен — вопрос уходит снова (FR-8.9): этап передачи.
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
    response = page(request, "chats.html", viewer, chats=chat_list(request, viewer, q), q=q)
    if "kind" in request.query_params:
        response.set_cookie("cleaner-chat-kind", chat_filter(request), max_age=365 * 86400,
                            httponly=True, secure=request.url.scheme == "https", samesite="lax")
    return response


@router.post("/chats")
def create_chat(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    now = request.app.state.clock.now().astimezone(request.app.state.tz)
    title = form.get("title", "").strip()[:_TITLE] or f"Чат от {now:%d.%m.%Y %H:%M}"       # FR-1.1
    chat_id = repo_of(request).create_chat(viewer.user.id, title)
    repo_of(request).audit("chat_created", viewer.user.id, chat_id)
    return RedirectResponse(f"/chats/{chat_id}", status_code=303)


LEDGER_PAGE = 50
BLOCK_NAMES = {
    "text": "текст", "tool_result": "результат инструмента", "tool_use": "вызов инструмента", "image": "изображение",
    "document": "документ",
}


def _block_name(node: object) -> str:
    if isinstance(node, dict) and "input_schema" in node:
        return "описание инструмента"
    kind = node.get("type") if isinstance(node, dict) else None
    return BLOCK_NAMES.get(kind, str(kind) if kind else "блок")


def _type_name(value: str) -> str:
    try:
        return render.TYPE_NAMES[EntityType(value)]
    except (ValueError, KeyError):
        return value


def _opened(nodes: list[object], state: ChatState, settings: Settings) -> list[bool]:
    """В каких блоках известное значение открыто (FR-6.8, спецификация 2026-10-28, 7.3): одна проверка утечек на все
    строки страницы — таблица чата собирается один раз, — находки разносятся по блокам по позиции."""
    texts, starts, position = [], [], 0
    for node in nodes:
        text = "\n\n".join(walk.strings_of(node))
        starts.append(position)
        texts.append(text)
        position += len(text) + 2
    found = [False] * len(nodes)
    for leak in leakcheck.check("\n\n".join(texts), state, settings) if texts else ():
        found[bisect.bisect_right(starts, leak.start) - 1] = True
    return found


def _agent_chat(request: Request, chat: Chat, viewer: Viewer, q: str) -> Response:
    """Чат шлюза: журнал отправленного по LEDGER_PAGE записей, новые первыми; запись — блок у агента и у провайдера
    рядом, только для чтения (спецификация 2026-10-28, раздел 16)."""
    repo = repo_of(request)
    raw = request.query_params.get("offset", "0")
    offset = int(raw) if raw.isdigit() and len(raw) < 9 else 0
    shown = repo.ledger_page(chat.id, offset, LEDGER_PAGE)
    receipts = repo.agent_receipts(chat.id, offset, LEDGER_PAGE)
    selected = repo.agent_receipt(chat.id, request.query_params.get("request", ""))
    if selected:
        shown = []
        for direction in ("in", "out"):
            digests = [block["digest"] for block in selected["blocks"] if block["direction"] == direction]
            entries = repo.ledger_get(chat.id, selected["conversation"], direction, digests)
            shown += [(entries[digest], selected["time"]) for digest in digests if digest in entries]
    conversations = {c.id: c for c in repo.chat_conversations(chat.id)}
    keys = [repo.api_key(key_id) for key_id in dict.fromkeys(c.key_id for c in conversations.values())]
    state, _ = repo.load_state(chat.id)
    nodes = [(json.loads(entry.local), json.loads(entry.wire)) for entry, _ in shown]
    opened = _opened([wire if not entry.withheld else {} for (entry, _), (_, wire) in zip(shown, nodes)], state, repo.settings())
    rows = []
    for (entry, first_seen), (local, wire), open_here in zip(shown, nodes, opened):
        conversation = conversations.get(entry.conversation)
        rows.append({
            "time": first_seen, "conversation": entry.conversation[:8], "session": conversation.session if conversation else "",
            "direction": "агент → модель" if entry.direction == "in" else "модель → агент", "kind": _block_name(local),
            "size": len(entry.local), "withheld": REASON_NAMES.get(entry.withheld, entry.withheld), "open": open_here,
            "counts": ", ".join(f"{_type_name(type_)}: {count}" for type_, count in sorted(entry.counts.items())),
            "local": render.highlight(json.dumps(local, ensure_ascii=False, indent=1), []),
            "wire": render.highlight(json.dumps(wire, ensure_ascii=False, indent=1), []),
        })
    return page(
        request, "agent_chat.html", viewer, chat=chat, chats=chat_list(request, viewer, q), q=q, rows=rows,
        opened=sum(opened), keys=", ".join(key.name for key in keys if key), conversations=len(conversations),
        receipts=receipts, selected_request=selected,
        offset=offset, more=len(shown) == LEDGER_PAGE, step=LEDGER_PAGE,
    )


# Причины удержания блока (7.4) — для журнала отправленного; значения не показываются.
REASON_NAMES = {"media": "изображение или файл", "blocked": "значение типа с «блокировать»", "failed": "очистка не выполнена"}


@router.get("/chats/{chat_id}")
def chat_page(request: Request, chat_id: str, q: str = "", viewer: Viewer = Depends(get_viewer)) -> Response:
    chat = own_chat(request, chat_id, viewer)
    if chat.kind == "agent":
        return _agent_chat(request, chat, viewer, q)
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
        gold_count=len(repo_of(request).chat_gold(chat_id)), no_question=no_question(view),
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
    # Отметка «и примеры эталона» включена по умолчанию; снятой её видно только по полю gold_shown: форма без отметки
    # (примеров не было при показе, прежние формы) удаляет и примеры, появившиеся с тех пор.
    keep = form.get("gold_shown") == "yes" and form.get("gold") != "yes"
    service_of(request).delete_chat(chat_id, viewer.user.id, gold=not keep)
    return RedirectResponse("/chats", status_code=303)


@router.post("/chats/{chat_id}/input")
def add_input(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    writable_chat(request, chat_id, viewer)
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
def upload(request: Request, chat_id: str, upload: list[Upload] = Depends(get_upload), viewer: Viewer = Depends(get_viewer)) -> Response:
    writable_chat(request, chat_id, viewer)
    items = []
    while upload:
        file = upload[0]
        items.append(service_of(request).add_file(chat_id, viewer.user.id, file.filename, file.data, file.ocr_all,
                                                reservation=file.reservation))
        upload.pop(0)                    # зависимости больше не держат копию исходных bytes уже принятого задания
    target = f"/chats/{chat_id}/items/{items[0].id}" if len(items) == 1 else f"/chats/{chat_id}"
    return RedirectResponse(target, status_code=303)


JOB_NAMES = {"file": "Извлечение файла", "text": "Очистка текста", "risk": "Проверка риска",
             "local": "Ответ локальной модели", "send": "Ответ облачной модели"}


def _my_jobs(request: Request, viewer: Viewer) -> list[dict]:
    repo = repo_of(request)
    rows = []
    for pool in request.app.state.job_pools:
        for job in pool.owned(viewer.user.id):
            chat = repo.chat(job["chat_id"])
            if chat is None or chat.user_id != viewer.user.id:
                continue
            item = repo.item(chat.id, job["item_id"])
            rows.append(job | {"chat_title": chat.title, "name": JOB_NAMES.get(job["kind"], "Обработка"),
                               "progress": item.meta.get("progress", "") if item else ""})
    rows.sort(key=lambda row: row["created_at"])
    for position, row in enumerate([row for row in rows if row["status"] == "queued"], 1):
        row["position"] = position
    return rows


@router.get("/jobs")
def my_jobs(request: Request, viewer: Viewer = Depends(get_viewer)) -> Response:
    return page(request, "jobs.html", viewer, jobs=_my_jobs(request, viewer))


@router.get("/jobs/status")
def my_jobs_status(request: Request, viewer: Viewer = Depends(get_viewer)) -> Response:
    return JSONResponse({"jobs": _my_jobs(request, viewer)})


@router.post("/jobs/{job_id}/cancel")
def cancel_job(request: Request, job_id: str, form: dict[str, str] = Depends(get_form),
               viewer: Viewer = Depends(get_viewer)) -> Response:
    for pool in request.app.state.job_pools:
        cancelled = pool.cancel(job_id, viewer.user.id)
        if cancelled is None:
            continue
        if not cancelled:
            raise HTTPException(409, "Обработка уже началась: отмена ожидающего задания недоступна")
        return RedirectResponse("/jobs", status_code=303)
    raise HTTPException(404, "Задание не найдено")


@router.post("/chats/{chat_id}/answer")
def add_answer(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    writable_chat(request, chat_id, viewer)
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
    """«Отметить проверенным» на экране проверки: отметка показанного очищенного текста (поле digest). Возврат — с
    необязательным предложением сохранить текст как эталон (offer=gold — слово, не данные)."""
    own_chat(request, chat_id, viewer)
    try:
        service_of(request).mark_reviewed(chat_id, viewer.user.id, item_id, form.get("digest", ""))
    except EditRefused as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "Текст не найден") from None
    return RedirectResponse(f"/chats/{chat_id}/items/{item_id}?offer=gold", status_code=303)


@router.post("/chats/{chat_id}/layers")
def set_layer(request: Request, chat_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """FR-3.8: слои 4 и 5 отключаются для чата явным действием; действует на следующие очистки."""
    writable_chat(request, chat_id, viewer)
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
