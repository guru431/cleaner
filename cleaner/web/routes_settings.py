"""Настройки администратора: политики, словарь и импорт, шаблоны, встроенные списки, пользователи, журнал."""
from __future__ import annotations

import csv
import io
import json
import threading
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import regex
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from cleaner.core.detect.base import DetectorError, load_builtin
from cleaner import settings_impact
from cleaner.core import cache
from cleaner.core.detect.dictionary import INFLECTED_TYPES, PATTERN_TIMEOUT, entry
from cleaner.core.detect.llm import CompletionError
from cleaner.core.entities import hostmap
from cleaner.core.types import EntityType, Policy, default_policies
from cleaner.egress import ProviderError, cloud
from cleaner.engines import GATEWAY_KEY_ENV, LocalSettings, local_settings, save_local_settings
from cleaner.eval import coverage, runner
from cleaner.eval.metrics import CLASSES
from cleaner.storage.repo import SUFFIXES_KEY, CheckpointBusy, Provider, User
from cleaner.web import auth, render
from cleaner.web.deps import Viewer, get_admin, get_form, page, repo_of, service_of
from cleaner.web.deps import _local as local_time
from cleaner.web.routes_chats import LAYER_LABELS, LAYER_NAMES
from cleaner.web.routes_keys import SUBSCRIPTION_NAMES

router = APIRouter(prefix="/settings")

POLICY_NAMES = {
    Policy.MASK: "скрывать и восстанавливать",
    Policy.HIDE: "скрывать без восстановления",
    Policy.BLOCK: "блокировать",
    Policy.OFF: "не искать",
}
DELIMITERS = {"comma": ",", "semicolon": ";", "tab": "\t"}
DUPLICATE = "Такое значение уже есть в этом списке словаря"
EVENTS = (
    "login", "login_failed", "logout", "chat_created", "chat_deleted", "sanitize", "restore", "edit", "edit_undo", "leak",
    "dictionary_changed", "dictionary_import", "pattern_changed", "policy_changed",
    "user_created", "user_disabled", "user_enabled", "password_changed", "error", "jobs_interrupted", "job_cancelled",
    "settings_changed", "gold_added", "gold_deleted", "risk_check", "layer_changed",
    "provider_changed", "cloud_send", "local_answer", "eval_run", "reviewed", "api_auth_failed",
    "key_created", "key_disabled", "agent_send", "agent_refused", "agent_withheld", "agent_chat_created", "agent_pruned",
    "key_restarted", "request_prepared",
    "user_deleted", "master_key_rotated", "logout_all", "audit_export", "egress_refused", "service_started",
    "settings_previewed", "api_keys_revoked_all", "user_role_changed", "audit_purged",
)
PROTOCOL_NAMES = {"openai": "OpenAI-совместимый", "anthropic": "Anthropic-совместимый", "responses": "OpenAI Responses"}
AUTH_NAMES = {"bearer": "Authorization: Bearer", "x-api-key": "x-api-key"}
_SHOWN = 50


def _redirect(path: str) -> Response:
    return RedirectResponse(path, status_code=303)


def _type(value: str) -> EntityType:
    try:
        return EntityType(value)
    except ValueError:
        raise HTTPException(400, "Неизвестный тип") from None


def _list(value: str) -> str:
    if value not in ("always", "never"):
        raise HTTPException(400, "Неизвестный список")
    return value


def _impact(request, viewer, operation, **shown):
    try:
        result = settings_impact.preview(repo_of(request), viewer.user.id, operation)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return page(request, "settings_impact.html", viewer, **result, **shown, lists=LIST_NAMES, shown_rows=_SHOWN,
                type_names={t.value: name for t, name in render.TYPE_NAMES.items()},
                policy_names={p.value: name for p, name in POLICY_NAMES.items()})


@router.post("/impact/apply")
def apply_impact(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    try:
        settings_impact.apply(repo_of(request), viewer.user.id, form.get("receipt", ""))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return _redirect("/settings/policies")


@router.post("/impact/undo")
def preview_undo(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    return _impact(request, viewer, {"kind": "undo"})


def _cards(request: Request) -> dict[str, tuple[str, str, str]]:
    """Главная настроек (идея аудита 09.11.2026): по разделу — состояние good / warn / bad, одно число словами и строка
    подробностей. Только из базы и памяти службы, без сетевых запросов."""
    repo, engines = repo_of(request), request.app.state.engines
    providers = repo.providers()
    enabled = sum(provider.enabled for provider in providers)
    policies = repo.policies()
    defaults = default_policies()
    off = sum(policy is Policy.OFF for policy in policies.values())
    changed = sum(policy is not defaults[type_] for type_, policy in policies.items())
    rows = repo.dictionary()
    always = sum(row.list == "always" for row in rows)
    patterns = repo.patterns()
    users = repo.users()
    disabled = sum(user.disabled for user in users)
    since = (request.app.state.clock.now() - timedelta(days=1)).isoformat(timespec="seconds")
    events = repo.audit_count(since=since)
    errors = repo.audit_count("error", since=since)
    gold = _gold_state(request)
    if engines is None:
        local = ("bad", "не подключена", "слои 4 и 5 и сканы недоступны")
    elif not engines.status()["key"]:
        local = ("bad", "ключ шлюза не задан", f"переменная {GATEWAY_KEY_ENV} в окружении службы")
    else:
        layer5 = "включена" if repo.layer_defaults()["llm"] else "выключена"
        local = ("good", "ключ шлюза задан", f"допроверка в новых чатах {layer5}; доступность — кнопкой на странице")
    return {
        "/settings/providers": (
            ("good", f"включено — {enabled}", f"всего — {len(providers)}") if enabled else
            ("warn", "включённых нет", "отправки из чата нет — только перенос вручную")
        ),
        "/settings/local-llm": local,
        "/settings/policies": (
            ("warn", f"не ищется типов — {off}", f"изменено от умолчаний — {changed}") if off else
            ("good", f"изменено от умолчаний — {changed}", f"типов — {len(policies)}")
        ),
        "/settings/dictionary": (
            ("good" if rows else "warn", f"записей — {len(rows)}",
             f"скрывать — {always}, не скрывать — {len(rows) - always}" if rows else "словарь организации пуст")
        ),
        "/settings/patterns": (
            "good", f"включено — {sum(p.enabled for p in patterns)}", f"всего — {len(patterns)}",
        ),
        "/settings/builtin": (
            "good", f"своих суффиксов — {len(stored_suffixes(repo))}",
            f"своих «никогда не скрывать» — {len(rows) - always}",
        ),
        "/settings/gold": (gold["state"], f"эталон — {gold['count']} из {GOLD_TARGET}", gold["detail"]),
        "/settings/labels": _labels_card(request),
        "/settings/users": (
            "good", f"пользователей — {len(users) - disabled}",
            f"администраторов — {sum(u.role == 'admin' and not u.disabled for u in users)}, отключено — {disabled}",
        ),
        "/settings/audit": (
            ("warn" if errors else "good"), f"событий за сутки — {events}", f"ошибок за сутки — {errors}",
        ),
    }


def _gold_state(request: Request) -> dict:
    """Собственный эталон для главной настроек (идея «Сбор собственного эталона»): сколько примеров из GOLD_TARGET и
    какие классы QA-3 пусты — напоминание администратору (warn), пока набор не полон. Без текстов примеров."""
    repo = repo_of(request)
    examples = repo.gold()
    empty = [row["title"] for row in coverage.matrix(examples)["rows"] if not sum(row["cells"])]
    stored = runner.passport(repo).get(runner.GOLD)
    measured = (f"последний замер — {local_time(stored['measured_at'], request.app.state.tz)}" if stored
                else "замера не было")
    detail = f"пустых классов — {len(empty)}: {', '.join(empty)}" if empty else measured
    state = "good" if len(examples) >= GOLD_TARGET and not empty else "warn"
    return {"count": len(examples), "target": GOLD_TARGET, "state": state, "detail": detail, "measured": measured}


# Пулы app.state.job_pools по порядку (app.create_app) — подписи для панели «Служба».
POOL_NAMES = ("Очистка, слои 4–5, локальная модель", "Разбор файлов и сканов", "Отправки облаку", "Замер эталона")
CHECKPOINT_DAYS = 30
_MIB = 1024 * 1024
NOT_CHECKED = "не проверялось"


def _db_size(repo) -> tuple[int, int]:
    """Размер файла базы по страницам SQLite и журнала WAL рядом с ним — в байтах."""
    with repo.lock:
        pages = repo.conn.execute("PRAGMA page_count").fetchone()[0]
        size = repo.conn.execute("PRAGMA page_size").fetchone()[0]
        file = repo.conn.execute("PRAGMA database_list").fetchone()[2]
    wal = Path(f"{file}-wal") if file else None
    return pages * size, wal.stat().st_size if wal is not None and wal.exists() else 0


def _busy(share: float) -> str:
    """Занятость предела: полный — bad (новое получает отказ), от 80 % — warn."""
    return "bad" if share >= 1 else "warn" if share >= 0.8 else "good"


def _service(request: Request) -> dict:
    """Блок «Служба» на главной настроек (идея аудита 09.11.2026): занятость входного бюджета, пулов и шлюза агентов,
    очередь со сроками, отказы контрольной точки, размер базы, модели и внешние службы. Внешние службы здесь не
    опрашиваются (страница обновляется опросом): итога их проверки служба не хранит — «не проверялось».
    Только счётчики и время: ни владельцев, ни чатов, ни текстов."""
    app, repo, engines = request.app, repo_of(request), request.app.state.engines
    budget = app.state.jobs.budget
    jobs, used = budget.usage()
    now = app.state.clock.now()
    pools = []
    for number, pool in enumerate(app.state.job_pools):
        state = pool.overview()
        left = (datetime.fromisoformat(state["expires"]) - now).total_seconds() if state["expires"] else None
        pools.append(state | {
            "name": POOL_NAMES[number] if number < len(POOL_NAMES) else "Другие задания",
            "left": None if left is None else max(0, int(left)),
            "state": "warn" if state["queued"] else "good",
        })
    slots = app.state.agent_slots
    since = (now - timedelta(days=CHECKPOINT_DAYS)).isoformat(timespec="seconds")
    checkpoint = repo.audit_count("error", since=since, kind="CheckpointBusy")
    last = repo.audit_events("error", since=since, limit=1, kind="CheckpointBusy") if checkpoint else []
    database, wal = _db_size(repo)
    models = engines.status()["models"] if engines is not None else {}
    local = local_settings(repo)
    providers = repo.providers()
    return {
        "budget": {"jobs": jobs, "max_jobs": budget.max_jobs, "mib": round(used / _MIB), "max_mib": budget.max_bytes // _MIB,
                   "state": _busy(max(jobs / budget.max_jobs, used / budget.max_bytes))},
        "pools": pools,
        "agents": {"busy": slots.busy, "limit": slots.limit, "refused": slots.refused, "state": _busy(slots.busy / slots.limit)},
        "checkpoint": {"count": checkpoint, "last": last[0].ts if last else "", "days": CHECKPOINT_DAYS},
        "database": {"mib": round(database / _MIB, 1), "wal_mib": round(wal / _MIB, 1)},
        "models": {"present": sum(models.values()), "total": len(models)},
        "local": {"connected": engines is not None, "key": bool(engines is not None and engines.status()["key"]),
                  "model": local.model},
        "ocr": local.ocr_model or "служба ocr-ru",
        "providers": {"enabled": sum(p.enabled for p in providers), "total": len(providers)},
        "gold": _gold_state(request),
        "measure": app.state.measure["status"],
        "not_checked": NOT_CHECKED,
    }


@router.get("")
def index(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    return page(request, "settings.html", viewer, cards=_cards(request), service=_service(request))


@router.get("/service")
def service_state(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    """Блок «Служба» для опроса главной настроек (app.js, data-refresh): тот же кусок разметки, без страницы."""
    return page(request, "_settings_service.html", viewer, service=_service(request))


# --- политики (FR-4.2, FR-10.6) -----------------------------------------------

# Группы типов на странице политик. Каждый тип — ровно в одной группе (тест): новый тип не пропадёт со страницы молча.
POLICY_GROUPS = (
    ("Люди и организации", (EntityType.PERSON, EntityType.ORG, EntityType.ADDRESS, EntityType.EMAIL, EntityType.PHONE,
                            EntityType.BIRTHDATE, EntityType.TERM)),
    ("Документы и реквизиты", (EntityType.PASSPORT, EntityType.INN, EntityType.SNILS, EntityType.OGRN, EntityType.KPP,
                               EntityType.OMS)),
    ("Финансы", (EntityType.CARD, EntityType.BANK_ACCOUNT)),
    ("Инфраструктура", (EntityType.IP, EntityType.MAC, EntityType.HOST, EntityType.DOMAIN, EntityType.SID, EntityType.DN,
                        EntityType.ACCOUNT)),
    ("Секреты", (EntityType.SECRET,)),
)
# Уточнение подписи только здесь: паспортом находятся и ВУ, СТС, ПТС, загранпаспорт; общая подпись типа не меняется.
_POLICY_LABELS = {EntityType.PASSPORT: "Паспорт и документы (ВУ, СТС, ПТС, загранпаспорт)"}


@router.get("/policies")
def policies(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    groups = [(title, [(type_, _POLICY_LABELS.get(type_, render.TYPE_NAMES[type_])) for type_ in types])
              for title, types in POLICY_GROUPS]
    return page(
        request, "policies.html", viewer, current=repo_of(request).policies(), groups=groups, names=POLICY_NAMES,
        defaults=default_policies(),
    )


@router.post("/policies")
def save_policies(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    repo = repo_of(request)
    wanted: dict[EntityType, Policy] = {}
    for type_ in EntityType:                      # сначала проверить всё, потом записывать
        raw = form.get(f"policy-{type_.value}")
        if raw is None:
            continue
        try:
            wanted[type_] = Policy(raw)
        except ValueError:
            raise HTTPException(400, "Неизвестная политика") from None
    current = repo.policies()
    if form.get("reset"):                         # «Вернуть умолчание» у строки — тоже через оценку влияния
        type_ = _type(form["reset"])
        wanted[type_] = default_policies()[type_]
    if form.get("action") == "impact" or form.get("reset"):
        return _impact(request, viewer, {"kind": "policies", "policies": {t.value: p.value for t, p in wanted.items()}})
    for type_, policy in wanted.items():
        if policy is not current[type_]:
            repo.set_policy(type_, policy)
            repo.audit("policy_changed", viewer.user.id, type=type_.value, policy=policy.value)
    return _redirect("/settings/policies")


# --- словарь и импорт (FR-10.1–10.3) ------------------------------------------

DICTIONARY_PAGE = 100
LIST_NAMES = {"always": "всегда скрывать", "never": "никогда не скрывать"}


def _dictionary_query(list_: str, type_: str, number: int) -> str:
    """Отбор и страница словаря в адресе — только коды списка и типа и номер; искомое значение в адрес не попадает."""
    pairs = (("list", list_), ("type", type_), ("page", number if number > 1 else ""))
    query = urlencode({key: value for key, value in pairs if value})
    return f"?{query}" if query else ""


def _folded(value: str) -> str:
    return value.casefold().replace("ё", "е")


def _dictionary_page(request: Request, viewer: Viewer, list_: str, type_: str, raw_page: str, wanted: str = "") -> Response:
    """Словарь страницами по DICTIONARY_PAGE строк (выгрузка AD — тысячи строк): отбор по списку, типу и поиск по значению
    и вариантам без учёта регистра и «ё». Неизвестные список и тип — отказ, номер страницы — в пределах."""
    if list_:
        _list(list_)
    shown_type = _type(type_) if type_ else None
    rows = repo_of(request).dictionary()
    rows.sort(key=lambda r: r.list != "always")             # «всегда скрывать» первым, внутри — в порядке добавления
    by_list = Counter(r.list for r in rows)
    by_type = Counter(r.type for r in rows if r.type is not None)
    needle = _folded(wanted.strip())
    chosen = [
        r for r in rows
        if (not list_ or r.list == list_) and (shown_type is None or r.type is shown_type)
        and (not needle or any(needle in _folded(value) for value in (r.value, *r.aliases)))
    ]
    pages = max(1, -(-len(chosen) // DICTIONARY_PAGE))
    number = min(pages, max(1, int(raw_page))) if raw_page.isdigit() and len(raw_page) < 7 else 1
    return page(
        request, "dictionary.html", viewer, types=render.TYPE_NAMES, lists=LIST_NAMES,
        rows=chosen[(number - 1) * DICTIONARY_PAGE:number * DICTIONARY_PAGE], total=len(rows), chosen=len(chosen),
        by_list=by_list, present=[(t, render.TYPE_NAMES[t], by_type[t]) for t in EntityType if by_type[t]],
        shown_list=list_, shown_type=shown_type, q=wanted.strip(), first=(number - 1) * DICTIONARY_PAGE + 1,
        number=number, pages=pages, query=lambda target: _dictionary_query(list_, type_, target),
        inflected=INFLECTED_TYPES,
    )


@router.get("/dictionary")
def dictionary(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    params = request.query_params
    return _dictionary_page(request, viewer, params.get("list", ""), params.get("type", ""), params.get("page", "1"))


@router.post("/dictionary/search")
def search_dictionary(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """Поиск — формой POST: значение не попадает ни в адрес, ни в журнал запросов. Без искомого — переход к адресу с
    отбором, как у ссылок страниц."""
    list_, type_, number = form.get("list", ""), form.get("type", ""), form.get("page", "1")
    if not form.get("q", "").strip():
        if list_:
            _list(list_)
        if type_:
            _type(type_)
        page_number = int(number) if number.isdigit() and len(number) < 7 else 1
        return _redirect("/settings/dictionary" + _dictionary_query(list_, type_, page_number))
    return _dictionary_page(request, viewer, list_, type_, number, form["q"])


@router.post("/dictionary")
def add_entry(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    list_, value = _list(form.get("list", "")), form.get("value", "").strip()
    if not value:
        raise HTTPException(400, "Укажите значение")
    type_ = _type(form.get("type", "")) if list_ == "always" else None
    aliases = tuple(alias.strip() for alias in form.get("aliases", "").splitlines() if alias.strip())
    # Падежные формы — у людей, организаций, адресов и терминов списка «всегда скрывать»; у прочих отметка не хранится.
    inflect = form.get("inflect") == "1" and type_ in INFLECTED_TYPES
    repo = repo_of(request)
    if repo.in_dictionary(list_, value):
        raise HTTPException(400, DUPLICATE)
    if form.get("action") == "impact":
        row = {"id": "", "list": list_, "value": value, "type": type_.value if type_ else None,
               "aliases": list(aliases), "comment": form.get("comment", "").strip(), "inflect": inflect}
        forms = [form for form in entry(type_, value, aliases, True).aliases if form not in aliases] if inflect else []
        return _impact(request, viewer, {"kind": "add", "rows": [row]}, inflected_forms=forms)
    repo.add_dictionary(list_, value, type_, aliases, form.get("comment", "").strip(), inflect)
    repo.audit("dictionary_changed", viewer.user.id, action="add", list=list_)
    return _redirect("/settings/builtin" if form.get("back") == "builtin" else "/settings/dictionary")


@router.post("/dictionary/{entry_id}/delete")
def delete_entry(request: Request, entry_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    repo = repo_of(request)
    row = next((r for r in repo.dictionary() if r.id == entry_id), None)
    if row is None:
        raise HTTPException(404, "Запись не найдена")
    if form.get("action") == "impact":
        return _impact(request, viewer, {"kind": "delete", "id": entry_id})
    repo.delete_dictionary(entry_id)
    repo.audit("dictionary_changed", viewer.user.id, action="delete", list=row.list)
    return _redirect("/settings/dictionary")


@router.post("/dictionary/{entry_id}/edit")
def edit_entry(request: Request, entry_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """Правка записи — варианты, комментарий и отметка падежей — только через оценку влияния; значение, список и тип
    не меняются (другое значение — новая запись). Отметка падежей — по тем же правилам, что при добавлении."""
    row = next((r for r in repo_of(request).dictionary() if r.id == entry_id), None)
    if row is None:
        raise HTTPException(404, "Запись не найдена")
    aliases = tuple(alias.strip() for alias in form.get("aliases", "").splitlines() if alias.strip())
    inflect = form.get("inflect") == "1" and row.list == "always" and row.type in INFLECTED_TYPES
    edited = {"id": row.id, "list": row.list, "value": row.value, "type": row.type.value if row.type else None,
              "aliases": list(aliases), "comment": form.get("comment", "").strip(), "inflect": inflect}
    forms = [form for form in entry(row.type, row.value, aliases, True).aliases if form not in aliases] if inflect else []
    return _impact(request, viewer, {"kind": "edit", "row": edited}, inflected_forms=forms)


def _csv_column(text: str, delimiter: str, column: str) -> tuple[list[str], list[str]]:
    """Заголовки и значения колонки: без пустых и повторов, в порядке файла."""
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿")), delimiter=delimiter))
    headers = [header.strip() for header in rows[0]] if rows else []
    if column not in headers:
        return headers, []
    index = headers.index(column)
    seen: set[str] = set()
    values: list[str] = []
    for row in rows[1:]:
        value = row[index].strip() if index < len(row) else ""
        if value and value.lower() not in seen:
            seen.add(value.lower())
            values.append(value)
    return headers, values


@router.post("/dictionary/import")
def import_csv(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    list_ = _list(form.get("list", ""))
    delimiter = DELIMITERS.get(form.get("delimiter", ""))
    if delimiter is None:
        raise HTTPException(400, "Выберите разделитель")
    type_ = _type(form.get("type", "")) if list_ == "always" else None
    inflect = form.get("inflect") == "1" and type_ in INFLECTED_TYPES      # как в ручной форме
    text, column = form.get("csv", ""), form.get("column", "").strip()
    try:
        headers, values = _csv_column(text, delimiter, column)
    except csv.Error:
        raise HTTPException(400, "Файл CSV не разбирается") from None
    repo = repo_of(request)
    known = {row.value.lower() for row in repo.dictionary() if row.list == list_}
    new = [value for value in values if value.lower() not in known]
    if form.get("action") in ("save", "impact"):
        if column not in headers:
            raise HTTPException(400, "Выберите колонку из первой строки файла")
        if form.get("action") == "impact":
            return _impact(request, viewer, {"kind": "add", "import": True, "rows": [
                {"id": "", "list": list_, "value": value, "type": type_.value if type_ else None, "aliases": [], "comment": "",
                 "inflect": inflect}
                for value in new]})
        repo.add_dictionary_many(list_, new, type_, inflect)
        repo.audit("dictionary_import", viewer.user.id, list=list_, count=len(new))
        return _redirect("/settings/dictionary")
    return page(
        request, "import_preview.html", viewer, csv_text=text, headers=headers, column=column,
        delimiter=form.get("delimiter", ""), list_=list_, type_=type_, new=new, total=len(values), shown=new[:_SHOWN],
        inflect=inflect,
    )


# --- шаблоны (FR-10.4) -----------------------------------------------------------

def _try_pattern(expression: str, sample: str) -> list[str]:
    """Совпадения на тестовой строке. Не разбирается, находит пустую строку, ищет слишком долго — отказ."""
    try:
        compiled = regex.compile(expression)
    except regex.error as exc:
        raise HTTPException(400, f"Выражение не разбирается: {exc}") from None
    if compiled.match("") is not None:
        raise HTTPException(400, "Шаблон находит пустую строку")
    try:
        return [m.group() for m in compiled.finditer(sample, timeout=PATTERN_TIMEOUT)]
    except TimeoutError:
        raise HTTPException(400, "Шаблон ищет слишком долго") from None


@router.get("/patterns")
def patterns(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    return page(request, "patterns.html", viewer, rows=repo_of(request).patterns(), types=render.TYPE_NAMES, form={}, matches=None)


@router.post("/patterns")
def save_pattern(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    name, expression = form.get("name", "").strip(), form.get("regex", "")
    if not name or not expression:
        raise HTTPException(400, "Укажите название и выражение")
    type_ = _type(form.get("type", ""))
    matches = _try_pattern(expression, form.get("sample", ""))
    repo = repo_of(request)
    if form.get("action") == "save":
        repo.add_pattern(name, expression, type_)
        repo.audit("pattern_changed", viewer.user.id, action="add")
        return _redirect("/settings/patterns")
    return page(request, "patterns.html", viewer, rows=repo.patterns(), types=render.TYPE_NAMES, form=form, matches=matches)


@router.post("/patterns/{pattern_id}/delete")
def delete_pattern(request: Request, pattern_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    repo = repo_of(request)
    if not repo.delete_pattern(pattern_id):
        raise HTTPException(404, "Шаблон не найден")
    repo.audit("pattern_changed", viewer.user.id, action="delete")
    return _redirect("/settings/patterns")


# --- встроенные списки (FR-10.5) -------------------------------------------------

_SUFFIX =regex.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def stored_suffixes(repo) -> tuple[str, ...]:
    """Внутренние суффиксы, которые добавил администратор."""
    raw = repo.setting(SUFFIXES_KEY)
    return tuple(json.loads(raw)) if raw else ()


def apply_suffixes(repo) -> None:
    """Дополнения внутренних суффиксов действуют на всю службу: при старте и после изменения на странице."""
    hostmap.set_extra_suffixes(stored_suffixes(repo))
    cache.clear_strings()           # ответы о доменных именах меток (labels) зависят от суффиксов


@router.get("/builtin")
def builtin(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    lists = load_builtin()
    return page(
        request, "builtin.html", viewer,
        lists=[
            ("Общеизвестные домены", sorted(lists.well_known_domains)),
            ("Суффиксы арендатора под общеизвестными доменами", sorted(lists.tenant_suffixes)),
            ("Служебные имена узлов", sorted(lists.generic_labels)),
            ("Стандартные учётные записи", sorted(lists.builtin_accounts)),
            ("Внутренние суффиксы", sorted(hostmap.INTERNAL_SUFFIXES)),
        ],
        never=[row for row in repo_of(request).dictionary() if row.list == "never"],
        suffixes=stored_suffixes(repo_of(request)),
    )


@router.post("/builtin/suffixes")
def add_suffix(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    value = form.get("value", "").strip().lower().lstrip("*.")
    if not _SUFFIX.fullmatch(value):
        raise HTTPException(400, "Суффикс — части из латинских букв, цифр и дефиса через точку: «loc», «corp.example»")
    repo = repo_of(request)
    current = stored_suffixes(repo)
    if value in current or value in hostmap.INTERNAL_SUFFIXES or hostmap.has_known_suffix(f"name.{value}"):
        raise HTTPException(400, "Этот суффикс уже известен")
    repo.set_setting(SUFFIXES_KEY, json.dumps([*current, value]))
    apply_suffixes(repo)
    repo.audit("settings_changed", viewer.user.id, section="internal_suffixes", action="add")
    return _redirect("/settings/builtin")


@router.post("/builtin/suffixes/{value}/delete")
def delete_suffix(
    request: Request, value: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin),
) -> Response:
    repo = repo_of(request)
    current = stored_suffixes(repo)
    if value not in current:
        raise HTTPException(404, "Суффикс не найден")
    repo.set_setting(SUFFIXES_KEY, json.dumps([suffix for suffix in current if suffix != value]))
    apply_suffixes(repo)
    repo.audit("settings_changed", viewer.user.id, section="internal_suffixes", action="delete")
    return _redirect("/settings/builtin")


# --- локальная модель (FR-9.1, SEC-12) -------------------------------------------------

def _local_page(request: Request, viewer: Viewer, result: str = "", failed: bool = False) -> Response:
    engines = request.app.state.engines
    status = engines.status() if engines is not None else {"key": False, "models": {}}
    return page(
        request, "local_llm.html", viewer, current=local_settings(repo_of(request)), status=status,
        key_env=GATEWAY_KEY_ENV, result=result, failed=failed, defaults=repo_of(request).layer_defaults(),
        layer_names=LAYER_NAMES, layer_labels=LAYER_LABELS,
    )


@router.get("/local-llm")
def local_llm(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    return _local_page(request, viewer)


@router.post("/local-llm")
def save_local_llm(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    url, model = form.get("url", "").strip(), form.get("model", "").strip()
    if not url or not model:
        raise HTTPException(400, "Укажите адрес и модель")
    trusted = frozenset(line.strip().lower() for line in form.get("trusted", "").splitlines() if line.strip())
    settings = LocalSettings(url, model, trusted, form.get("schema") != "prompt", form.get("ocr_model", "").strip())
    try:
        save_local_settings(repo_of(request), settings)
    except ValueError as exc:
        raise HTTPException(400, f"Адрес отклонён: {exc}") from None
    repo_of(request).audit("settings_changed", viewer.user.id, section="local_llm")
    return _redirect("/settings/local-llm")


@router.post("/local-llm/check")
def check_local_llm(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """Тестовый запрос без пользовательских данных (по образцу FR-8.2)."""
    engines = request.app.state.engines
    try:
        if engines is None:
            raise DetectorError("локальная модель не подключена к приложению")
        engines.client().complete([{"role": "user", "content": "Ответь одним словом: готово"}], max_tokens=16)
    except (DetectorError, CompletionError) as exc:
        return _local_page(request, viewer, f"Проверка не прошла: {exc}", failed=True)
    return _local_page(request, viewer, "Локальная модель ответила.")


@router.post("/layers")
def save_layers(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """Умолчания слоёв 4 и 5 для чатов, где пользователь не выбирал сам (FR-3.8)."""
    values = {"ner": form.get("ner") == "yes", "llm": form.get("llm") == "yes"}
    repo = repo_of(request)
    repo.set_layer_defaults(values)
    repo.audit("settings_changed", viewer.user.id, section="layers", **values)
    return _redirect("/settings/local-llm")


# --- подключения к облачным моделям (FR-8.1, FR-8.2, FR-8.10, SEC-13) ----------------------

def _providers_page(request: Request, viewer: Viewer, result: str = "", failed: bool = False, detail: str = "") -> Response:
    return page(
        request, "providers.html", viewer, providers=repo_of(request).providers(), protocols=PROTOCOL_NAMES,
        auth_styles=AUTH_NAMES, result=result, failed=failed, detail=detail,
    )


def _provider_form(form: dict[str, str], provider_id: str = "") -> tuple[Provider, str | None]:
    """Подключение из формы и новый ключ (None — прежний). HTTPException 400 с причиной."""
    name, url = form.get("name", "").strip(), form.get("base_url", "").strip()
    protocol, auth_style = form.get("protocol", ""), form.get("auth_style", "")
    models = tuple(dict.fromkeys(line.strip() for line in form.get("models", "").splitlines() if line.strip()))
    key = form.get("api_key", "").strip() or None
    if not name or not url or not models:
        raise HTTPException(400, "Укажите название, адрес и хотя бы одну модель")
    if protocol not in PROTOCOL_NAMES or auth_style not in AUTH_NAMES:
        raise HTTPException(400, "Неизвестный протокол или способ передачи ключа")
    if key is None and not provider_id:
        raise HTTPException(400, "Укажите ключ")
    try:
        cloud.check_url(url)
        max_tokens = int(form.get("max_tokens", "") or 4096)
        extra = json.loads(form.get("extra_body", "").strip() or "{}")
        cloud.check_extra_body(extra)
    except ValueError as exc:
        raise HTTPException(400, f"Подключение не сохранено: {exc}") from None
    if not 1 <= max_tokens <= 1_000_000:
        raise HTTPException(400, "Предел длины ответа — от 1 до 1 000 000 токенов")
    enabled = form.get("enabled") == "yes"
    return Provider(provider_id, name, protocol, url, auth_style, key or "", models, max_tokens, extra, enabled), key


@router.get("/providers")
def providers(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    return _providers_page(request, viewer)


@router.post("/providers")
def add_provider(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    provider, _ = _provider_form(form)
    provider_id = repo_of(request).add_provider(provider)
    repo_of(request).audit("provider_changed", viewer.user.id, action="add", id=provider_id)
    return _redirect("/settings/providers")


@router.post("/providers/{provider_id}")
def update_provider(request: Request, provider_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    old = repo_of(request).provider(provider_id)
    if old is None:
        raise HTTPException(404, "Подключение не найдено")
    provider, key = _provider_form(form, provider_id)
    # Ключ уходит туда, куда указывает адрес: без нового ключа сменой адреса его можно было бы увести на свой узел
    # кнопкой «Проверить соединение» (FR-8.10). Схема — тоже: у адреса без порта она задаёт порт (443 или 80).
    new, before = urlsplit(provider.base_url), urlsplit(old.base_url)
    moved = (
        (new.scheme, new.hostname, new.port) != (before.scheme, before.hostname, before.port)
        or provider.auth_style != old.auth_style
    )
    if moved and key is None:
        raise HTTPException(400, "Адрес или способ передачи ключа изменился: укажите ключ заново")
    repo_of(request).update_provider(provider, key)
    repo_of(request).audit("provider_changed", viewer.user.id, action="update", id=provider_id, key_changed=key is not None)
    return _redirect("/settings/providers")


@router.post("/providers/{provider_id}/delete")
def delete_provider(request: Request, provider_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    if not repo_of(request).delete_provider(provider_id):
        raise HTTPException(404, "Подключение не найдено")
    repo_of(request).audit("provider_changed", viewer.user.id, action="delete", id=provider_id)
    return _redirect("/settings/providers")


@router.post("/providers/{provider_id}/check")
def check_provider(request: Request, provider_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """FR-8.2: проверочный запрос без пользовательских данных; показывается и сообщение провайдера."""
    provider = repo_of(request).provider(provider_id)
    if provider is None:
        raise HTTPException(404, "Подключение не найдено")
    model = form.get("model", "")
    if model not in provider.models:
        raise HTTPException(400, "Выберите модель из списка подключения")
    try:
        answer = service_of(request).check_provider(provider, model)
    except ProviderError as exc:
        return _providers_page(request, viewer, f"«{provider.name}», {model}: {exc}", failed=True, detail=exc.detail)
    except ValueError as exc:
        return _providers_page(request, viewer, f"«{provider.name}»: {exc}", failed=True)
    return _providers_page(request, viewer, f"«{provider.name}», {model} ответил: {answer or '(пустой ответ)'}")


# --- пользователи (FR-12.1) -------------------------------------------------------

def _target(request: Request, user_id: str) -> User:
    user = repo_of(request).user(user_id)
    if user is None:
        raise HTTPException(404, "Пользователь не найден")
    return user


def _hash(form: dict[str, str]) -> str:
    try:
        return auth.hash_password(form.get("password", ""))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("/users")
def users(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    return page(request, "users.html", viewer, rows=repo_of(request).users(), min_password=auth.MIN_PASSWORD)


@router.post("/users")
def create_user(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    login, role = form.get("login", "").strip(), form.get("role", "")
    if not login or role not in ("admin", "user"):
        raise HTTPException(400, "Укажите логин и роль")
    password_hash = _hash(form)
    repo = repo_of(request)
    if repo.user_by_login(login) is not None:
        raise HTTPException(400, "Такой логин уже есть")
    user_id = repo.create_user(login, password_hash, role)
    repo.audit("user_created", viewer.user.id, target=user_id, role=role)
    return _redirect("/settings/users")


@router.post("/users/{user_id}/password")
def change_password(request: Request, user_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    _target(request, user_id)
    repo = repo_of(request)
    repo.set_password(user_id, _hash(form))          # закрывает сессии этого пользователя
    repo.audit("password_changed", viewer.user.id, target=user_id)
    return _redirect("/settings/users")


@router.post("/users/{user_id}/role")
def change_role(request: Request, user_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """Роль на месте — без отключения и потери чатов. С себя роль не снимается; последнего активного администратора
    защищает и repo.set_role (два администратора, снимающие роль друг с друга разом)."""
    _target(request, user_id)
    role = form.get("role", "")
    if role not in ("admin", "user"):
        raise HTTPException(400, "Неизвестная роль")
    if role != "admin" and user_id == viewer.user.id:
        raise HTTPException(400, "Нельзя снять роль администратора с себя")
    repo = repo_of(request)
    if not repo.set_role(user_id, role):
        raise HTTPException(400, "Нельзя снять роль с последнего активного администратора")
    repo.audit("user_role_changed", viewer.user.id, target=user_id, role=role)
    return _redirect("/settings/users")


@router.post("/users/{user_id}/disable")
def disable_user(request: Request, user_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    _target(request, user_id)
    disabled = form.get("disabled") == "yes"
    if disabled and user_id == viewer.user.id:
        raise HTTPException(400, "Нельзя отключить собственную учётную запись")
    repo = repo_of(request)
    if not repo.set_disabled(user_id, disabled):
        raise HTTPException(400, "Нельзя отключить последнего активного администратора")
    repo.audit("user_disabled" if disabled else "user_enabled", viewer.user.id, target=user_id)
    return _redirect("/settings/users")


@router.post("/users/{user_id}/delete")
def delete_user(request: Request, user_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """Учётная запись и все её чаты — только у отключённой записи (она не входит, ключи её не принимаются) и после
    ввода её логина. Чаты — через ChatService.delete_chat, как кнопкой пользователя (FR-1.4)."""
    user = _target(request, user_id)
    if not user.disabled:
        raise HTTPException(400, "Удалить можно только отключённую учётную запись")
    if form.get("confirm", "").strip() != user.login:
        raise HTTPException(400, "Для подтверждения введите логин удаляемой учётной записи")
    repo, service = repo_of(request), service_of(request)
    chat_ids = repo.chat_ids(user_id)
    for chat_id in chat_ids:
        service.delete_chat(chat_id, viewer.user.id, via="user_deleted")
    try:
        deleted = repo.delete_user(user_id)
    except CheckpointBusy as exc:
        deleted = True              # запись удалена; копии страниц в журнале WAL сотрёт следующая контрольная точка
        repo.audit("error", viewer.user.id, kind=type(exc).__name__, stage="delete_user")
    if not deleted:
        raise HTTPException(409, "Пока удалялись чаты, у учётной записи появились новые — повторите удаление")
    repo.audit("user_deleted", viewer.user.id, target=user_id, chats=len(chat_ids))
    return _redirect("/settings/users")


# --- журнал (FR-11.3) -----------------------------------------------------------

def _day_start(request: Request, value: str, shift: int = 0) -> str | None:
    """Начало дня в поясе интерфейса — строкой ISO в UTC, как хранится время в журнале."""
    if not value:
        return None
    try:
        day = date.fromisoformat(value) + timedelta(days=shift)
    except ValueError:
        raise HTTPException(400, "Дата — в виде ГГГГ-ММ-ДД") from None
    start = datetime.combine(day, time(), tzinfo=request.app.state.tz)
    return start.astimezone(timezone.utc).isoformat(timespec="seconds")


AUDIT_PAGE = 500


@router.get("/audit")
def audit(
    request: Request, event: str = "", user: str = "", since: str = "", until: str = "",
    viewer: Viewer = Depends(get_admin),
) -> Response:
    """Страница — AUDIT_PAGE событий отбора, свежие первыми; число всех событий отбора и кнопки «Новее/Старше»:
    шлюз пишет события на каждый ход, и отбор за день не помещается на одну страницу."""
    repo = repo_of(request)
    raw = request.query_params.get("offset", "0")
    offset = int(raw) if raw.isdigit() and len(raw) < 9 else 0
    selection = (event or None, user or None, _day_start(request, since), _day_start(request, until, 1))
    rows = repo.audit_events(*selection, limit=AUDIT_PAGE, offset=offset)
    total = repo.audit_count(*selection)
    filters = {key: value for key, value in (("event", event), ("user", user), ("since", since), ("until", until)) if value}

    def link(start: int) -> str:
        return "/settings/audit?" + urlencode(filters | ({"offset": start} if start else {}))

    accounts = repo.users()
    return page(
        request, "audit.html", viewer, rows=rows, logins={u.id: u.login for u in accounts}, users=accounts,
        events=EVENTS, event=event, user=user, since=since, until=until, total=total, offset=offset,
        newer=link(max(offset - AUDIT_PAGE, 0)) if offset else "",
        older=link(offset + AUDIT_PAGE) if offset + len(rows) < total else "",
    )


_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: object) -> str:
    """Ячейка CSV, которую Excel и LibreOffice не примут за формулу (CSV-инъекция: логин «=HYPERLINK(…)»)."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA) else text


@router.get("/audit/export")
def export_audit(
    request: Request, event: str = "", user: str = "", since: str = "", until: str = "",
    viewer: Viewer = Depends(get_admin),
) -> Response:
    """Журнал с отбором страницы, без её предела в 500 строк, — файлом CSV (UTF-8 с BOM: его открывает Excel).
    Время — UTC, как хранится. Сама выгрузка — событие журнала с отбором и числом строк."""
    repo = repo_of(request)
    rows = repo.audit_events(event or None, user or None, _day_start(request, since), _day_start(request, until, 1), limit=None)
    logins = {u.id: u.login for u in repo.users()}
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(["time_utc", "login", "user_id", "chat_id", "event", "details"])
    for row in rows:
        writer.writerow([_cell(value) for value in (
            row.ts, logins.get(row.user_id, ""), row.user_id, row.chat_id, row.event,
            json.dumps(row.details, ensure_ascii=False),
        )])
    repo.audit(
        "audit_export", viewer.user.id, rows=len(rows), filter={"event": event, "user": user, "since": since, "until": until},
    )
    return Response(
        "﻿" + out.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="cleaner-audit.csv"'},
    )


# --- сохранность меток (FR-7.3, FR-7.5, FR-5.10; открытый вопрос ТЗ, раздел 14) ---------------------------------

# Модель «искажает метки», когда за период доля искажённых замен в её ответах больше LABEL_DISTORTION_SHARE при не
# меньше LABEL_MIN_LABELS замен (решение владельца, 09.11.2026). Искажённые — восстановленные из искажённой записи
# (altered: FR-7.3 их вернул, но модель записала метку не так, как выдана) и неизвестные (unknown: такой метки чат не
# выдавал — данные не вернутся). 5 % — каждая двадцатая замена: ответы этой модели уже приходится перечитывать.
# 50 замен — меньше одна-две метки решали бы долю случайно (один ответ с тремя метками давал бы 33 %).
LABEL_DISTORTION_SHARE = 0.05
LABEL_MIN_LABELS = 50
LABEL_DAYS = 30            # период отчёта и карточки на главной настроек по умолчанию
LABEL_STYLES = {"angle": "<ТИП_N>", "square": "[[ТИП_N]]"}
LABEL_SOURCES = {"chat": "чаты", "agent": "агенты"}    # источник события restore; у событий чатов поля source нет
_LABEL_COUNTERS = ("restored", "altered", "derived", "unknown", "kept")


def _label_report(repo, since: str | None, before: str | None, source: str = "") -> list[dict]:
    """Сводка событий restore за период по подключению, модели и виду метки (FR-5.10) — только числа журнала.
    Событие без подключения и модели (вставленный ответ или записанное до 09.11.2026) — в строке «модель не указана».
    Замены в ответе — восстановленные, из искажённой записи, выведенные и неизвестные; оставленные по политике (kept)
    в долю не входят: это решение политики, а не модели. Сначала помеченные, затем по числу замен.
    Ответы чатов и шлюза агентов (source="agent") одной модели — в одной строке: порог пометки — о модели; sources —
    откуда ответы строки, source — отбор одного источника ("chat" | "agent", "" — все)."""
    names = {provider.id: provider.name for provider in repo.providers()} | SUBSCRIPTION_NAMES
    groups: dict[tuple, dict] = {}
    for sums in repo.audit_sums("restore", ("source", "provider", "model", "label_style"), _LABEL_COUNTERS, since, before):
        origin = sums["source"] or "chat"
        if source and origin != source:
            continue
        provider, model = sums["provider"] or "", sums["model"] or ""
        style = sums["label_style"] or ""
        group = groups.setdefault((provider, model, style), {
            "connection": names.get(provider, provider) if provider else "",
            "model": model, "style": LABEL_STYLES.get(style, style), "answers": 0, "sources": set(),
        } | dict.fromkeys(_LABEL_COUNTERS, 0))
        group["answers"] += sums["events"]
        group["sources"].add(origin)
        for counter in _LABEL_COUNTERS:
            group[counter] += int(sums[counter] or 0)
    for group in groups.values():
        group["sources"] = ", ".join(LABEL_SOURCES[name] for name in LABEL_SOURCES if name in group["sources"])
        group["labels"] = group["restored"] + group["altered"] + group["derived"] + group["unknown"]
        group["share"] = (group["altered"] + group["unknown"]) / group["labels"] if group["labels"] else 0.0
        group["flagged"] = group["labels"] >= LABEL_MIN_LABELS and group["share"] > LABEL_DISTORTION_SHARE
    return sorted(groups.values(), key=lambda group: (not group["flagged"], -group["labels"]))


def _labels_card(request: Request) -> tuple[str, str, str]:
    """Карточка «Сохранность меток» на главной настроек: за LABEL_DAYS дней — модели, искажающие метки (warn)."""
    since = (request.app.state.clock.now() - timedelta(days=LABEL_DAYS)).isoformat(timespec="seconds")
    rows = _label_report(repo_of(request), since, None)
    flagged = [row for row in rows if row["flagged"]]
    if flagged:
        return ("warn", f"искажают метки — {len(flagged)}",
                ", ".join(row["model"] or "модель не указана" for row in flagged))
    return ("good", f"ответов за {LABEL_DAYS} дней — {sum(row['answers'] for row in rows)}",
            f"замен в них — {sum(row['labels'] for row in rows)}")


@router.get("/labels")
def labels(
    request: Request, since: str | None = None, until: str = "", source: str = "", viewer: Viewer = Depends(get_admin),
) -> Response:
    """Отчёт «Сохранность меток»: как облачные модели возвращают метки, по счётчикам событий restore за период.
    Без отбора — последние LABEL_DAYS дней; пустое поле «с» — весь журнал; source — чаты или агенты."""
    if since is None:
        today = request.app.state.clock.now().astimezone(request.app.state.tz).date()
        since = (today - timedelta(days=LABEL_DAYS - 1)).isoformat()
    if source and source not in LABEL_SOURCES:
        raise HTTPException(400, "Неизвестный источник ответов")
    rows = _label_report(repo_of(request), _day_start(request, since), _day_start(request, until, 1), source)
    return page(
        request, "labels.html", viewer, rows=rows, since=since, until=until, source=source, sources=LABEL_SOURCES,
        share=LABEL_DISTORTION_SHARE, minimum=LABEL_MIN_LABELS, styles=LABEL_STYLES, style=repo_of(request).label_style(),
    )


@router.post("/label-style")
def save_label_style(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """Вид метки в новых чатах (FR-5.10): консультации, чаты шлюза агентов и чаты API без явного label_style.
    Созданные чаты сохраняют свой вид."""
    style = form.get("style", "")
    if style not in LABEL_STYLES:
        raise HTTPException(400, "Неизвестный вид метки")
    repo = repo_of(request)
    repo.set_label_style(style)
    repo.audit("settings_changed", viewer.user.id, section="label_style", style=style)
    return _redirect("/settings/labels")


# --- эталонный набор (FR-6.10, QA-1) ----------------------------------------------------

GOLD_TARGET = 200          # QA-1: не меньше 200 примеров
_MEASURING = threading.Lock()     # проверка «замер уже идёт» и постановка нового — одним шагом


def _passport_view(dataset: str, entry: dict, current: str | None) -> dict:
    """Паспорт замера для страницы: только счётчики, знаменатели и отпечатки (тексты в паспорт не входят)."""
    layers = entry["layers"]
    names = list(layers)
    first = layers[names[0]] if names else {"classes": {}, "types": {}}
    classes = [
        {
            "title": title, "total": first["classes"][title][1],
            "recalls": [runner.confidence(*layers[name]["classes"].get(title, (0, 0))) for name in names],
            "target": "не задана" if target is None else f"{target:.2f}",
        }
        for title, _, target in CLASSES if title in first["classes"]
    ]

    def total(name: str, key: str) -> int:
        return sum(counts[key] for counts in layers[name]["types"].values())

    quality = [
        ("Точность по пересечению (задели эталон / найдено)", [runner.share(total(n, "correct"), total(n, "found")) for n in names]),
        ("Точность типа (тот же тип / задели эталон)", [runner.share(total(n, "typed"), total(n, "correct")) for n in names]),
        ("Скрыто знаков вне эталона — от скрытых", [runner.share(layers[n]["chars"][0], layers[n]["chars"][1]) for n in names]),
        ("Скрыто знаков вне эталона — от текста вне эталона", [runner.share(layers[n]["chars"][0], layers[n]["chars"][2]) for n in names]),
        ("Лишние замены среди версий, кодов ошибок и общеизвестных доменов", [runner.share(*layers[n]["overmasked"]) for n in names]),
        ("Ложные срабатывания вне эталона", [str(total(n, "found") - total(n, "correct")) for n in names]),
    ]
    types = sorted({type_ for name in names for type_ in layers[name]["types"]})
    empty = {"entities": [0, 0], "mentions": [0, 0], "found": 0, "correct": 0, "typed": 0}
    by_type = []
    for type_ in types:
        cells = []
        for name in names:
            counts = layers[name]["types"].get(type_, empty)
            cells.append(
                f"{runner.share(*counts['entities'])}; по упоминаниям {runner.share(*counts['mentions'])}; "
                f"точность {runner.share(counts['correct'], counts['found'])}"
            )
        by_type.append((type_, cells))
    versions = entry["versions"]
    shown = [("Код ядра", versions["code"][:12]), ("Настройки распознавания", versions["settings"][:12])]
    shown += [(f"Модель {directory}", revision[:12]) for directory, revision in versions.get("models", {}).items()]
    if "local_model" in versions:
        shown.append(("Локальная модель слоя 5", versions["local_model"]))
    source = entry.get("source") or {}
    if source:
        pinned = "" if source.get("pinned") else ", ревизия на момент загрузки"
        shown.append((
            "Снимок",
            f"{source.get('source')} @ {str(source.get('revision') or '—')[:12]}{pinned}; sha256 "
            f"{str(source.get('sha256'))[:12]}; конвертер {source.get('converter')}",
        ))
    return {
        "title": ("Собственный набор" if dataset == runner.GOLD else
                  runner.PARTITIONS.get(dataset.removeprefix("gold:"), f"Открытый набор «{dataset.removeprefix(runner.OPEN_PREFIX)}»")),
        "measured_at": entry["measured_at"], "examples": entry["examples"], "unit": entry["unit"],
        "fingerprint": entry["fingerprint"][:12], "changed": current is not None and current != entry["fingerprint"],
        "versions": shown, "layers": names, "classes": classes, "quality": quality, "types": by_type,
        "drops": entry["drops"], "unchecked": entry["unchecked"], "warnings": entry.get("warnings", []),
        "scenarios": [(dict(coverage.SCENARIOS).get(scenario, "Не указан"), title,
                       [runner.confidence(*layers[n].get("scenarios", {}).get(scenario, {}).get(title, (0, 0))) for n in names])
                      for scenario, counts in first.get("scenarios", {}).items() for title in counts],
        "sources": first.get("sources", 0),
    }


def _measure_layers(repo) -> list[str]:
    """Слой 5 — только если он включён по умолчанию: иначе замер шёл бы с тем, чем чаты не пользуются."""
    return ["1-3", "1-4"] + (["1-5"] if repo.layer_defaults()["llm"] else [])


def _measure(app, user_id: str, layers: list[str]) -> None:
    """Фоновый замер собственного набора: итог — в паспорт (runner.measure), в журнал — только счётчики (FR-11.2)."""
    state, repo, engines = app.state.measure, app.state.repo, app.state.engines
    state["status"] = "running"
    try:
        done = runner.measure(repo, runner.GOLD, runner.gold_examples(repo), layers, engines, engines.models_dir)
        for purpose in runner.PARTITIONS:
            examples = runner.gold_examples(repo, purpose)
            if examples:
                runner.measure(repo, f"gold:{purpose}", examples, layers, engines, engines.models_dir)
    except DetectorError as exc:
        state.update(status="failed", error=f"Замер не выполнен: {exc}")
        repo.audit("eval_run", user_id, dataset=runner.GOLD, layers=layers, outcome="failed")
        return
    except Exception:
        state.update(status="failed", error="Замер не выполнен: внутренняя ошибка")
        repo.audit("eval_run", user_id, dataset=runner.GOLD, layers=layers, outcome="failed")
        raise                                   # вид ошибки — в журнал службы (jobs._run), без текста
    repo.audit(
        "eval_run", user_id, dataset=runner.GOLD, layers=layers, outcome="done", examples=done.examples,
        drops=len(done.comparison.drops), unchecked=len(done.comparison.unchecked),
    )
    state["status"] = "done"


@router.get("/gold")
def gold(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    """Число примеров и разметка по типам — без текстов: чужие тексты администратор не видит (раздел 4 ТЗ).
    Паспорт качества — последний замер собственного набора и открытых наборов, раздельно."""
    repo = repo_of(request)
    logins = {user.id: user.login for user in repo.users()}
    examples = repo.gold()
    rows = [
        {
            "id": row.id, "created_at": row.created_at, "login": logins.get(row.user_id, "—"), "length": len(row.text),
            "types": ", ".join(f"{type_} — {count}" for type_, count in sorted(Counter(s["type"] for s in row.spans).items())),
            "scenario": dict(coverage.SCENARIOS).get(row.metadata.get("scenario"), "Не указан"),
            "purpose": runner.PARTITIONS.get(row.metadata.get("purpose"), "Не назначено"),
        }
        for row in examples
    ]
    stored = runner.passport(repo)
    current = runner.fingerprint(runner.gold_examples(repo), repo.global_key)
    own = _passport_view(runner.GOLD, stored[runner.GOLD], current) if runner.GOLD in stored else None
    opened = [_passport_view(name, entry, None) for name, entry in sorted(stored.items()) if name.startswith(runner.OPEN_PREFIX)]
    partitions = [_passport_view(f"gold:{purpose}", stored[f"gold:{purpose}"],
                                runner.fingerprint(runner.gold_examples(repo, purpose), repo.global_key))
                  for purpose in runner.PARTITIONS if f"gold:{purpose}" in stored]
    return page(
        request, "gold.html", viewer, rows=rows, target=GOLD_TARGET, own=own, opened=opened,
        measure=request.app.state.measure, measure_layers=_measure_layers(repo), engines=request.app.state.engines is not None,
        coverage=coverage.matrix(examples),
        partitions=partitions,
    )


@router.post("/gold/measure")
def measure_gold(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    """Замер собственного набора фоновым заданием; повторное нажатие, пока он идёт, второго не запускает."""
    app, repo = request.app, repo_of(request)
    if app.state.engines is None:
        raise HTTPException(400, "Модели слоя 4 не подключены к приложению")
    if not repo.gold():
        raise HTTPException(400, "Эталонный набор пуст: измерять нечего")
    layers = _measure_layers(repo)
    with _MEASURING:
        if app.state.measure["status"] in ("queued", "running"):
            return _redirect("/settings/gold")
        app.state.measure = {"status": "queued", "layers": layers}
        state = app.state.measure
        reservation = None
        try:
            reservation = app.state.measures.budget.reserve(viewer.user.id)
            app.state.measures.submit_reserved(
                _measure, (app, viewer.user.id, layers), reservation, user=viewer.user.id, kind="measure",
                cancelled=lambda reason: state.update(status="failed", error=reason),
            )
        except Exception:
            if reservation is not None:
                reservation.release()
            app.state.measure = {"status": "failed", "layers": layers, "error": "Замер не поставлен в очередь: повторите позже"}
            raise
    return _redirect("/settings/gold")


@router.get("/gold/measure/status")
def measure_status(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    """Для опроса из app.js: только состояние."""
    return JSONResponse({"status": request.app.state.measure["status"]})


@router.post("/gold/{gold_id}/delete")
def delete_gold(request: Request, gold_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    repo = repo_of(request)
    if not repo.delete_gold(gold_id):
        raise HTTPException(404, "Пример не найден")
    repo.audit("gold_deleted", viewer.user.id)
    return _redirect("/settings/gold")
