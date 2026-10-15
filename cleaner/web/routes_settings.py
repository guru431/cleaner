"""Настройки администратора: политики, словарь и импорт, шаблоны, встроенные списки, пользователи, журнал."""
from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone

import regex
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from cleaner.core.detect.base import DetectorError, load_builtin
from cleaner.core.detect.dictionary import PATTERN_TIMEOUT
from cleaner.core.detect.llm import CompletionError
from cleaner.core.types import EntityType, Policy
from cleaner.engines import GATEWAY_KEY_ENV, LocalSettings, local_settings, save_local_settings
from cleaner.storage.repo import User
from cleaner.web import auth, render
from cleaner.web.deps import Viewer, get_admin, get_form, page, repo_of

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
    "login", "login_failed", "logout", "chat_created", "chat_deleted", "sanitize", "restore", "edit", "leak",
    "dictionary_changed", "dictionary_import", "pattern_changed", "policy_changed",
    "user_created", "user_disabled", "user_enabled", "password_changed", "error", "jobs_interrupted",
    "settings_changed", "gold_added", "gold_deleted", "risk_check", "layer_changed",
)
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


@router.get("")
def index(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    return page(request, "settings.html", viewer)


# --- политики (FR-4.2, FR-10.6) -----------------------------------------------

@router.get("/policies")
def policies(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    return page(
        request, "policies.html", viewer, current=repo_of(request).policies(), types=render.TYPE_NAMES, names=POLICY_NAMES
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
    for type_, policy in wanted.items():
        if policy is not current[type_]:
            repo.set_policy(type_, policy)
            repo.audit("policy_changed", viewer.user.id, type=type_.value, policy=policy.value)
    return _redirect("/settings/policies")


# --- словарь и импорт (FR-10.1–10.3) ------------------------------------------

@router.get("/dictionary")
def dictionary(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    rows = repo_of(request).dictionary()
    return page(
        request, "dictionary.html", viewer, types=render.TYPE_NAMES,
        always=[r for r in rows if r.list == "always"], never=[r for r in rows if r.list == "never"],
    )


@router.post("/dictionary")
def add_entry(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    list_, value = _list(form.get("list", "")), form.get("value", "").strip()
    if not value:
        raise HTTPException(400, "Укажите значение")
    type_ = _type(form.get("type", "")) if list_ == "always" else None
    aliases = tuple(alias.strip() for alias in form.get("aliases", "").splitlines() if alias.strip())
    repo = repo_of(request)
    if repo.in_dictionary(list_, value):
        raise HTTPException(400, DUPLICATE)
    repo.add_dictionary(list_, value, type_, aliases, form.get("comment", "").strip())
    repo.audit("dictionary_changed", viewer.user.id, action="add", list=list_)
    return _redirect("/settings/builtin" if form.get("back") == "builtin" else "/settings/dictionary")


@router.post("/dictionary/{entry_id}/delete")
def delete_entry(request: Request, entry_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    repo = repo_of(request)
    row = next((r for r in repo.dictionary() if r.id == entry_id), None)
    if row is None:
        raise HTTPException(404, "Запись не найдена")
    repo.delete_dictionary(entry_id)
    repo.audit("dictionary_changed", viewer.user.id, action="delete", list=row.list)
    return _redirect("/settings/dictionary")


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
    text, column = form.get("csv", ""), form.get("column", "").strip()
    try:
        headers, values = _csv_column(text, delimiter, column)
    except csv.Error:
        raise HTTPException(400, "Файл CSV не разбирается") from None
    repo = repo_of(request)
    known = {row.value.lower() for row in repo.dictionary() if row.list == list_}
    new = [value for value in values if value.lower() not in known]
    if form.get("action") == "save":
        if column not in headers:
            raise HTTPException(400, "Выберите колонку из первой строки файла")
        repo.add_dictionary_many(list_, new, type_)
        repo.audit("dictionary_import", viewer.user.id, list=list_, count=len(new))
        return _redirect("/settings/dictionary")
    return page(
        request, "import_preview.html", viewer, csv_text=text, headers=headers, column=column,
        delimiter=form.get("delimiter", ""), list_=list_, type_=type_, new=new, total=len(values), shown=new[:_SHOWN],
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
        return [m.group() for m in regex.finditer(expression, sample, timeout=PATTERN_TIMEOUT)]
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

@router.get("/builtin")
def builtin(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    lists = load_builtin()
    return page(
        request, "builtin.html", viewer,
        lists=[
            ("Общеизвестные домены", sorted(lists.well_known_domains)),
            ("Служебные имена узлов", sorted(lists.generic_labels)),
            ("Стандартные учётные записи", sorted(lists.builtin_accounts)),
        ],
        never=[row for row in repo_of(request).dictionary() if row.list == "never"],
    )


# --- локальная модель (FR-9.1, SEC-12) -------------------------------------------------

def _local_page(request: Request, viewer: Viewer, result: str = "", failed: bool = False) -> Response:
    engines = request.app.state.engines
    status = engines.status() if engines is not None else {"key": False, "models": {}}
    return page(
        request, "local_llm.html", viewer, current=local_settings(repo_of(request)), status=status,
        key_env=GATEWAY_KEY_ENV, result=result, failed=failed, defaults=repo_of(request).layer_defaults(),
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
    try:
        save_local_settings(repo_of(request), LocalSettings(url, model, trusted, form.get("schema") != "prompt"))
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
    return page(request, "users.html", viewer, rows=repo_of(request).users())


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


@router.post("/users/{user_id}/disable")
def disable_user(request: Request, user_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    _target(request, user_id)
    disabled = form.get("disabled") == "yes"
    if disabled and user_id == viewer.user.id:
        raise HTTPException(400, "Нельзя отключить собственную учётную запись")
    repo = repo_of(request)
    repo.set_disabled(user_id, disabled)
    repo.audit("user_disabled" if disabled else "user_enabled", viewer.user.id, target=user_id)
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


@router.get("/audit")
def audit(
    request: Request, event: str = "", user: str = "", since: str = "", until: str = "",
    viewer: Viewer = Depends(get_admin),
) -> Response:
    repo = repo_of(request)
    rows = repo.audit_events(event or None, user or None, _day_start(request, since), _day_start(request, until, 1), limit=500)
    accounts = repo.users()
    return page(
        request, "audit.html", viewer, rows=rows, logins={u.id: u.login for u in accounts}, users=accounts,
        events=EVENTS, event=event, user=user, since=since, until=until,
    )


# --- эталонный набор (FR-6.10, QA-1) ----------------------------------------------------

GOLD_TARGET = 200          # QA-1: не меньше 200 примеров к концу этапа 2


@router.get("/gold")
def gold(request: Request, viewer: Viewer = Depends(get_admin)) -> Response:
    """Число примеров и разметка по типам — без текстов: чужие тексты администратор не видит (раздел 4 ТЗ)."""
    repo = repo_of(request)
    logins = {user.id: user.login for user in repo.users()}
    rows = [
        {
            "id": row.id, "created_at": row.created_at, "login": logins.get(row.user_id, "—"), "length": len(row.text),
            "types": ", ".join(f"{type_} — {count}" for type_, count in sorted(Counter(s["type"] for s in row.spans).items())),
        }
        for row in repo.gold()
    ]
    return page(request, "gold.html", viewer, rows=rows, target=GOLD_TARGET)


@router.post("/gold/{gold_id}/delete")
def delete_gold(request: Request, gold_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_admin)) -> Response:
    repo = repo_of(request)
    if not repo.delete_gold(gold_id):
        raise HTTPException(404, "Пример не найден")
    repo.audit("gold_deleted", viewer.user.id)
    return _redirect("/settings/gold")
