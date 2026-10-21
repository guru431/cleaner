"""Настройки администратора: политики, словарь и импорт, шаблоны, встроенные списки, пользователи, журнал."""
from __future__ import annotations

import csv
import io
import json
import threading
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from urllib.parse import urlsplit

import regex
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from cleaner.core.detect.base import DetectorError, load_builtin
from cleaner.core.detect.dictionary import PATTERN_TIMEOUT
from cleaner.core.detect.llm import CompletionError
from cleaner.core.types import EntityType, Policy
from cleaner.egress import ProviderError, cloud
from cleaner.engines import GATEWAY_KEY_ENV, LocalSettings, local_settings, save_local_settings
from cleaner.eval import runner
from cleaner.eval.metrics import CLASSES
from cleaner.storage.repo import Provider, User
from cleaner.web import auth, render
from cleaner.web.deps import Viewer, get_admin, get_form, page, repo_of, service_of
from cleaner.web.routes_chats import LAYER_LABELS, LAYER_NAMES

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
    "user_created", "user_disabled", "user_enabled", "password_changed", "error", "jobs_interrupted",
    "settings_changed", "gold_added", "gold_deleted", "risk_check", "layer_changed",
    "provider_changed", "cloud_send", "local_answer", "eval_run",
)
PROTOCOL_NAMES = {"openai": "OpenAI-совместимый", "anthropic": "Anthropic-совместимый"}
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
    # кнопкой «Проверить соединение» (FR-8.10).
    moved = (urlsplit(provider.base_url).hostname, urlsplit(provider.base_url).port) != (
        urlsplit(old.base_url).hostname, urlsplit(old.base_url).port,
    ) or provider.auth_style != old.auth_style
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
_MEASURING = threading.Lock()     # проверка «замер уже идёт» и постановка нового — одним шагом


def _share(part: int, whole: int) -> str:
    return f"{part / whole:.3f} ({part}/{whole})" if whole else "—"


def _passport_view(dataset: str, entry: dict, current: str | None) -> dict:
    """Паспорт замера для страницы: только счётчики, знаменатели и отпечатки (тексты в паспорт не входят)."""
    layers = entry["layers"]
    names = list(layers)
    first = layers[names[0]] if names else {"classes": {}, "types": {}}
    classes = [
        {
            "title": title, "total": first["classes"][title][1],
            "recalls": [_share(*layers[name]["classes"].get(title, (0, 0))) for name in names],
            "target": "не задана" if target is None else f"{target:.2f}",
        }
        for title, _, target in CLASSES if title in first["classes"]
    ]

    def total(name: str, key: str) -> int:
        return sum(counts[key] for counts in layers[name]["types"].values())

    quality = [
        ("Точность по пересечению (задели эталон / найдено)", [_share(total(n, "correct"), total(n, "found")) for n in names]),
        ("Точность типа (тот же тип / задели эталон)", [_share(total(n, "typed"), total(n, "correct")) for n in names]),
        ("Скрыто знаков вне эталона — от скрытых", [_share(layers[n]["chars"][0], layers[n]["chars"][1]) for n in names]),
        ("Скрыто знаков вне эталона — от текста вне эталона", [_share(layers[n]["chars"][0], layers[n]["chars"][2]) for n in names]),
        ("Лишние замены среди версий, кодов ошибок и общеизвестных доменов", [_share(*layers[n]["overmasked"]) for n in names]),
    ]
    types = sorted({type_ for name in names for type_ in layers[name]["types"]})
    empty = {"entities": [0, 0], "mentions": [0, 0], "found": 0, "correct": 0, "typed": 0}
    by_type = []
    for type_ in types:
        cells = []
        for name in names:
            counts = layers[name]["types"].get(type_, empty)
            cells.append(
                f"{_share(*counts['entities'])}; по упоминаниям {_share(*counts['mentions'])}; "
                f"точность {_share(counts['correct'], counts['found'])}"
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
        "title": "Собственный набор" if dataset == runner.GOLD else f"Открытый набор «{dataset.removeprefix(runner.OPEN_PREFIX)}»",
        "measured_at": entry["measured_at"], "examples": entry["examples"], "unit": entry["unit"],
        "fingerprint": entry["fingerprint"][:12], "changed": current is not None and current != entry["fingerprint"],
        "versions": shown, "layers": names, "classes": classes, "quality": quality, "types": by_type,
        "drops": entry["drops"], "unchecked": entry["unchecked"],
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
        }
        for row in examples
    ]
    stored = runner.passport(repo)
    current = runner.fingerprint([runner.example_from(r.text, r.spans) for r in examples], repo.global_key)
    own = _passport_view(runner.GOLD, stored[runner.GOLD], current) if runner.GOLD in stored else None
    opened = [_passport_view(name, entry, None) for name, entry in sorted(stored.items()) if name.startswith(runner.OPEN_PREFIX)]
    return page(
        request, "gold.html", viewer, rows=rows, target=GOLD_TARGET, own=own, opened=opened,
        measure=request.app.state.measure, measure_layers=_measure_layers(repo), engines=request.app.state.engines is not None,
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
    app.state.measures.submit(_measure, app, viewer.user.id, layers)
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
