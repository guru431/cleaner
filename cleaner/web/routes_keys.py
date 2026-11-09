"""Страница «Ключи» (FR-13.1; спецификация 2026-10-28, разделы 6.1 и 16): ключи доступа программ к /api/v1 и ключи
шлюза агентов с доступом к модели подключения. Ключ показывается один раз — на странице сразу после выпуска; в базе —
его хэш и последние четыре знака."""
from __future__ import annotations

import json
import threading
from collections import OrderedDict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from cleaner.agent_service import GATEWAY_PROTOCOLS, gateway_access
from cleaner.storage import crypto
from cleaner.storage.db import transaction
from cleaner.storage.repo import ApiKey
from cleaner.web import auth
from cleaner.web.deps import Viewer, get_form, get_viewer, page, repo_of

router = APIRouter()
SUBSCRIPTION_NAMES = {"claude-subscription": "Подписка Claude", "chatgpt-subscription": "Подписка ChatGPT"}
SUBSCRIPTION_OPTIONS = {"claude-subscription": "Подписка Claude (Claude Code)", "chatgpt-subscription": "Подписка ChatGPT (Codex)"}
PROTOCOL_LABELS = {"anthropic": "Anthropic", "openai": "OpenAI Chat Completions", "responses": "OpenAI Responses"}
CERT = "<путь к файлу сертификата Cleaner на этой машине>"


class IssuedKeys:
    """Однократный показ после POST/Redirect/GET. В памяти — шифротекст, связанный с сессией; в URL — случайный билет."""

    def __init__(self, clock, secret: bytes):
        self.clock, self.secret = clock, secret
        self.pending = OrderedDict()
        self.lock = threading.Lock()

    def put(self, session: str, key_id: str, key: str) -> str:
        ticket = auth.new_token()
        with self.lock:
            self._prune()
            if len(self.pending) >= 256:
                raise HTTPException(429, "Слишком много ключей ожидают показа. Покажите выпущенные ключи или повторите позже.")
            self.pending[ticket] = (session, self.clock.now() + timedelta(minutes=5), key_id,
                                    crypto.seal(self.secret, key.encode("ascii"), session + ticket))
        return ticket

    def take(self, session: str, ticket: str) -> tuple[str, str] | None:
        with self.lock:
            self._prune()
            entry = self.pending.get(ticket)
            if entry is None or entry[0] != session:
                return None
            self.pending.pop(ticket)
        return entry[2], crypto.unseal(self.secret, entry[3], session + ticket).decode("ascii")

    def _prune(self) -> None:
        expired = [ticket for ticket, entry in self.pending.items() if entry[1] <= self.clock.now()]
        for ticket in expired:
            self.pending.pop(ticket)


def _claude_code(request: Request, key: str, model: str) -> str:
    """Фрагмент настройки Claude Code (раздел 14): блок env в .claude/settings.local.json проекта."""
    env = {
        "ANTHROPIC_BASE_URL": f"{request.base_url}agent/anthropic", "ANTHROPIC_AUTH_TOKEN": key,
        "ANTHROPIC_MODEL": model, "ANTHROPIC_DEFAULT_OPUS_MODEL": model, "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model, "NODE_EXTRA_CA_CERTS": CERT, "CLAUDE_CODE_ATTRIBUTION_HEADER": "0",
    }
    return json.dumps({"env": env}, ensure_ascii=False, indent=2)


def _claude_subscription(request: Request, key: str) -> str:
    """Claude Code со входом claude.ai: ключ Cleaner — своим заголовком, Authorization — вход подписки агента; без
    ANTHROPIC_AUTH_TOKEN и ANTHROPIC_API_KEY (они заменили бы вход claude.ai)."""
    env = {
        "ANTHROPIC_BASE_URL": f"{request.base_url}agent/anthropic", "ANTHROPIC_CUSTOM_HEADERS": f"X-Cleaner-Key: {key}",
        "NODE_EXTRA_CA_CERTS": CERT,
    }
    return json.dumps({"env": env}, ensure_ascii=False, indent=2)


def _quoted(value: str) -> str:
    """Строка в кавычках для TOML и Python: строка JSON допустима в обоих (модель подписки — свободное поле)."""
    return json.dumps(value, ensure_ascii=False)


def _codex(request: Request, key: str, model: str, subscription: bool) -> str:
    """Codex — свой провайдер в ~/.codex/config.toml (раздел 9.3): по подписке — вход ChatGPT (requires_openai_auth, без
    env_key: иначе Codex шлёт ключ из окружения вместо токена), по ключу — env_key. Частный сертификат Codex берёт из
    CODEX_CA_CERTIFICATE (проверка 18.4 5В)."""
    lines = ['model_provider = "cleaner"', *([f"model = {_quoted(model)}"] if model else []), "",
             "[model_providers.cleaner]", 'name = "Cleaner"', f'base_url = "{request.base_url}agent/openai/v1"',
             'wire_api = "responses"', 'env_http_headers = { "X-Cleaner-Key" = "CLEANER_KEY" }',
             "requires_openai_auth = true" if subscription else 'env_key = "CLEANER_KEY"']
    env = [f'$env:CLEANER_KEY = "{key}"', f'$env:CODEX_CA_CERTIFICATE = "{CERT}"']
    return "\n".join(lines) + "\n\n# PowerShell, перед запуском codex:\n" + "\n".join(env)


def _opencode(request: Request, key: str, model: str) -> str:
    """apiKey AI SDK шлёт заголовком Authorization: Bearer — шлюз берёт ключ оттуда и провайдеру его не передаёт."""
    config = {
        "$schema": "https://opencode.ai/config.json",
        "provider": {"cleaner": {
            "npm": "@ai-sdk/openai-compatible", "name": "Cleaner",
            "options": {"baseURL": f"{request.base_url}agent/openai/v1", "apiKey": key},
            "models": {model: {"name": model}},
        }},
        "model": f"cleaner/{model}",
    }
    return json.dumps(config, ensure_ascii=False, indent=2)


def _sdk(request: Request, key: str, model: str) -> str:
    return (
        f'from openai import OpenAI\n\nclient = OpenAI(base_url="{request.base_url}agent/openai/v1", api_key={_quoted(key)})\n'
        f'reply = client.chat.completions.create(model={_quoted(model)}, messages=[{{"role": "user", "content": "Привет"}}])'
    )


def _agent_settings(request: Request, key: str, stored: ApiKey, providers: list) -> list[tuple[str, str]]:
    """Готовые настройки агента по виду доступа ключа (раздел 14): (вид фрагмента, текст)."""
    if stored.upstream == "claude-subscription":
        return [("claude_sub", _claude_subscription(request, key))]
    if stored.upstream == "chatgpt-subscription":
        return [("codex", _codex(request, key, stored.models[0] if stored.models else "", subscription=True))]
    provider = next((p for p in providers if f"provider:{p.id}" == stored.upstream), None)
    if provider is None:
        return []
    model = (stored.models or provider.models or ("",))[0]
    if provider.protocol == "anthropic":
        return [("claude_code", _claude_code(request, key, model))]
    if provider.protocol == "responses":
        return [("codex", _codex(request, key, model, subscription=False))]
    return [("opencode", _opencode(request, key, model)), ("sdk", _sdk(request, key, model))]


def _page(request: Request, viewer: Viewer, issued: str = "", issued_key: ApiKey | None = None) -> Response:
    """Пользователь видит свои ключи, администратор — все, с владельцем (без значений: их нет и в базе)."""
    repo = repo_of(request)
    keys = repo.api_keys(None if viewer.is_admin else viewer.user.id)
    logins = {user.id: user.login for user in repo.users()} if viewer.is_admin else {}
    providers = repo.providers()
    names = {f"provider:{p.id}": p.name for p in providers} | SUBSCRIPTION_NAMES
    access = {
        key.id: "только API" if not key.upstream
        else f"{names.get(key.upstream, 'подключение удалено')}: {', '.join(key.models) or 'все модели'}"
        for key in keys
    }
    gateway = [p for p in providers if p.enabled and p.protocol in GATEWAY_PROTOCOLS]
    provider_by_upstream = {f"provider:{p.id}": p for p in providers}
    details = {}
    for key in keys:
        provider = provider_by_upstream.get(key.upstream)
        protocol = PROTOCOL_LABELS.get(provider.protocol, "") if provider else (
            "Anthropic" if key.upstream == "claude-subscription" else
            "OpenAI Responses" if key.upstream == "chatgpt-subscription" else "")
        enabled = key.layers or {}
        layer_text = "1–3" + (", 4" if enabled.get("ner") else "") + (", 5" if enabled.get("llm") else "")
        guard = "" if key.hold_secrets else " · секреты в адресах чужих узлов восстанавливаются"
        details[key.id] = f"{protocol} · слои {layer_text}{guard} · автоматическая отправка" if key.upstream else "Слои по настройкам чата"
    settings = _agent_settings(request, issued, issued_key, providers) if issued and issued_key and issued_key.upstream else []
    return page(
        request, "keys.html", viewer, keys=keys, logins=logins, issued=issued, endpoint=f"{request.base_url}api/v1/chats",
        access=access, gateway=gateway, protocols=PROTOCOL_LABELS, agent_settings=settings, cert=bool(request.app.state.cert_file),
        subscriptions=SUBSCRIPTION_OPTIONS if viewer.is_admin else {}, key_details=details,
    )


@router.get("/keys")
def keys(request: Request, viewer: Viewer = Depends(get_viewer)) -> Response:
    issued = request.app.state.issued_keys.take(viewer.session.token_hash, request.query_params.get("issued", ""))
    response = _page(request, viewer, issued[1], repo_of(request).api_key(issued[0])) if issued else _page(request, viewer)
    response.headers["cache-control"] = "no-store"
    response.headers["referrer-policy"] = "no-referrer"
    return response


@router.post("/keys")
def create_key(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    try:
        name = auth.api_key_name(form.get("name", ""))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    repo = repo_of(request)
    provider_id = form.get("provider", "")
    # Новый UI указывает режим явно; старые клиенты и форма без JS сохраняют прежний контракт provider.
    mode = form.get("key_mode", "")
    if mode and (mode not in ("api", "connection", "subscription") or
                 (mode == "api" and provider_id) or
                 (mode == "connection" and (not provider_id or provider_id in SUBSCRIPTION_NAMES)) or
                 (mode == "subscription" and provider_id not in SUBSCRIPTION_NAMES)):
        raise HTTPException(400, "Режим ключа не соответствует выбранному доступу к модели")
    upstream, models, layers = None, (), None
    # Отметка снимает защиту (17, риск 1): без неё — и у формы без поля — секреты в адресах чужих узлов не восстанавливаются.
    hold_secrets = form.get("restore_foreign") != "1"
    if provider_id:
        # Отметки моделей — поля «m:<подключение>:<модель>»: у формы несколько подключений, у каждого свои модели. У
        # подписки списка нет — модели через запятую (пусто — все).
        prefix = f"m:{provider_id}:"
        wanted = tuple(field[len(prefix):] for field, value in form.items() if field.startswith(prefix) and value)
        if provider_id in SUBSCRIPTION_NAMES:
            wanted = tuple(model.strip() for model in form.get("sub_models", "").split(","))
        try:
            upstream, models = gateway_access(repo, provider_id, wanted, admin=viewer.is_admin)
        except ValueError as exc:
            raise HTTPException(400, f"Доступ к модели: {exc}") from None
        layers = {"ner": form.get("ner") == "1", "llm": form.get("llm") == "1"}
    key = auth.new_api_key()
    with repo.lock, transaction(repo.conn):
        key_id = repo.add_api_key(viewer.user.id, name, auth.token_hash(key), key[-4:], upstream, models, layers, hold_secrets)
        repo.audit("key_created", viewer.user.id, id=key_id)
        ticket = request.app.state.issued_keys.put(viewer.session.token_hash, key_id, key)
    return RedirectResponse(f"/keys?issued={ticket}", status_code=303, headers={"cache-control": "no-store"})


def _own_key(request: Request, key_id: str, viewer: Viewer) -> ApiKey:
    """Ключ владельца или любой — администратору; чужой и несуществующий неотличимы (404)."""
    key = repo_of(request).api_key(key_id)
    if key is None or (key.user_id != viewer.user.id and not viewer.is_admin):
        raise HTTPException(404, "Ключ не найден")
    return key


@router.post("/keys/{key_id}/disable")
def disable_key(request: Request, key_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """Отзыв насовсем — владельцем или администратором."""
    key = _own_key(request, key_id, viewer)
    repo = repo_of(request)
    repo.disable_api_key(key.id)
    repo.audit("key_disabled", viewer.user.id, id=key.id)
    return RedirectResponse("/keys", status_code=303)


@router.post("/keys/{key_id}/restart")
def restart_key(request: Request, key_id: str, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    """«Начать заново» (6.3, FR-5.2): новые разговоры ключа — в новом чате шлюза; идущие доживают в своём."""
    key = _own_key(request, key_id, viewer)
    repo = repo_of(request)
    repo.restart_key_chat(key.id)
    repo.audit("key_restarted", viewer.user.id, id=key.id)
    return RedirectResponse("/keys", status_code=303)
