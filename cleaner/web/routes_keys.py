"""Страница «Ключи» (FR-13.1; спецификация 2026-10-28, разделы 6.1 и 16): ключи доступа программ к /api/v1 и ключи
шлюза агентов с доступом к модели подключения. Ключ показывается один раз — на странице сразу после выпуска; в базе —
его хэш и последние четыре знака."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from cleaner.agent_service import GATEWAY_PROTOCOLS, gateway_access
from cleaner.storage.repo import ApiKey
from cleaner.web import auth
from cleaner.web.deps import Viewer, get_form, get_viewer, page, repo_of

router = APIRouter()
NAME_LIMIT = 100
SUBSCRIPTION_NAMES = {"claude-subscription": "Подписка Claude", "chatgpt-subscription": "Подписка ChatGPT"}
SUBSCRIPTION_OPTIONS = {"claude-subscription": "Подписка Claude (Claude Code)", "chatgpt-subscription": "Подписка ChatGPT (Codex)"}
PROTOCOL_LABELS = {"anthropic": "Anthropic", "openai": "OpenAI Chat Completions", "responses": "OpenAI Responses"}
CERT = "<путь к файлу сертификата Cleaner на этой машине>"


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


def _codex(request: Request, key: str, model: str, subscription: bool) -> str:
    """Codex — свой провайдер в ~/.codex/config.toml (раздел 9.3): по подписке — вход ChatGPT (requires_openai_auth, без
    env_key: иначе Codex шлёт ключ из окружения вместо токена), по ключу — env_key. Частный сертификат Codex берёт из
    CODEX_CA_CERTIFICATE (проверка 18.4 5В)."""
    lines = ['model_provider = "cleaner"', *([f'model = "{model}"'] if model else []), "",
             "[model_providers.cleaner]", 'name = "Cleaner"', f'base_url = "{request.base_url}agent/openai/v1"',
             'wire_api = "responses"', 'env_http_headers = { "X-Cleaner-Key" = "CLEANER_KEY" }',
             "requires_openai_auth = true" if subscription else 'env_key = "CLEANER_KEY"']
    env = [f'$env:CLEANER_KEY = "{key}"', f'$env:CODEX_CA_CERTIFICATE = "{CERT}"']
    return "\n".join(lines) + "\n\n# PowerShell, перед запуском codex:\n" + "\n".join(env)


def _opencode(request: Request, key: str, model: str) -> str:
    config = {
        "$schema": "https://opencode.ai/config.json",
        "provider": {"cleaner": {
            "npm": "@ai-sdk/openai-compatible", "name": "Cleaner",
            "options": {"baseURL": f"{request.base_url}agent/openai/v1", "headers": {"X-Cleaner-Key": key}},
            "models": {model: {"name": model}},
        }},
        "model": f"cleaner/{model}",
    }
    return json.dumps(config, ensure_ascii=False, indent=2)


def _sdk(request: Request, key: str, model: str) -> str:
    return (
        f'from openai import OpenAI\n\nclient = OpenAI(base_url="{request.base_url}agent/openai/v1", api_key="{key}")\n'
        f'reply = client.chat.completions.create(model="{model}", messages=[{{"role": "user", "content": "Привет"}}])'
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
    settings = _agent_settings(request, issued, issued_key, providers) if issued and issued_key and issued_key.upstream else []
    return page(
        request, "keys.html", viewer, keys=keys, logins=logins, issued=issued, endpoint=f"{request.base_url}api/v1/chats",
        access=access, gateway=gateway, protocols=PROTOCOL_LABELS, agent_settings=settings,
        subscriptions=SUBSCRIPTION_OPTIONS if viewer.is_admin else {},
    )


@router.get("/keys")
def keys(request: Request, viewer: Viewer = Depends(get_viewer)) -> Response:
    return _page(request, viewer)


@router.post("/keys")
def create_key(request: Request, form: dict[str, str] = Depends(get_form), viewer: Viewer = Depends(get_viewer)) -> Response:
    name = form.get("name", "").strip()
    if not 1 <= len(name) <= NAME_LIMIT:
        raise HTTPException(400, f"Имя ключа — от 1 до {NAME_LIMIT} знаков")
    repo = repo_of(request)
    provider_id = form.get("provider", "")
    upstream, models, layers = None, (), None
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
    key_id = repo.add_api_key(viewer.user.id, name, auth.token_hash(key), key[-4:], upstream, models, layers)
    repo.audit("key_created", viewer.user.id, id=key_id)
    # Страница, а не переадресация: ключ виден один раз и не попадает ни в адрес, ни в базу.
    return _page(request, viewer, issued=key, issued_key=repo.api_key(key_id))


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
    repo.set_key_chat(key.id, None)
    repo.audit("key_restarted", viewer.user.id, id=key.id)
    return RedirectResponse("/keys", status_code=303)
