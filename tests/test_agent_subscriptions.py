"""Доступ по подписке (спецификация 2026-10-28, раздел 9.4; SEC-18…SEC-20; план 5В, задача 7): токен агента уходит
только на закреплённый адрес подписки и нигде не остаётся; ключ с подпиской действует только у администратора."""
import json
import logging

import pytest

from cleaner.agent_service import AgentCall, AgentRefused, AgentService, gateway_access
from cleaner.storage.repo import Provider
from cleaner.web import auth
from tests.agent_bodies import body as claude_body
from tests.agent_bodies import model_turn
from tests.stub_provider import StubProvider
from tests.test_agent_responses import completed, message, text_events

TOKEN = 'sk-a' 'nt-oat01-canary-0123456789abcdefghij'  # secret-scan:allow -- synthetic test fixture
CHATGPT = "eyJhbGciOi.canary-chatgpt-token.0123456789"
PROVIDER_KEY = 'sk-p' 'rovider-canary-0123456789'  # secret-scan:allow -- synthetic test fixture
TASK = "Проверь узел srv-dc01.corp.contoso.ru и почту i.ivanov@contoso.ru"
CLAUDE = {
    "authorization": f"Bearer {TOKEN}", "anthropic-beta": "claude-code-20250219,oauth-2025-04-20",
    "anthropic-version": "2023-06-01", "x-cleaner-key": "ck_agent", "user-agent": "claude-cli/2.1.270 (external, sdk-cli)",
    "x-app": "cli", "x-stainless-os": "Windows", "content-type": "application/json",
}
CODEX = {
    "authorization": f"Bearer {CHATGPT}", "chatgpt-account-id": "00000000-0000-4000-8000-000000000002",
    "originator": "codex_exec", "session-id": "s-1", "user-agent": "codex_exec/0.163.0", "x-cleaner-key": "ck_agent",
    "accept": "text/event-stream", "content-type": "application/json",
}


class Subscriptions:
    """Администратор с ключами обеих подписок; закреплённые адреса заменены заглушкой."""

    def __init__(self, repo, engines, clock, stub):
        self.repo, self.stub = repo, stub
        self.user_id = repo.create_user("boss", "hash", "admin")
        self.keys = {
            access: repo.add_api_key(self.user_id, access, f"h-{access}", "aaaa", upstream=access, models=())
            for access in ("claude-subscription", "chatgpt-subscription")
        }
        urls = {"claude-subscription": stub.url, "chatgpt-subscription": f"{stub.url}/backend-api/codex"}
        self.service = AgentService(repo, engines, clock, subscription_urls=urls)

    def call(self, access: str, request: dict, headers: dict, protocol: str = ""):
        protocol = protocol or ("anthropic" if access == "claude-subscription" else "responses")
        path = "/v1/messages" if protocol == "anthropic" else "/responses"
        return self.service.handle(AgentCall(
            key=self.repo.api_key(self.keys[access]), user=self.repo.user(self.user_id), protocol=protocol, path=path,
            query="beta=true" if protocol == "anthropic" else "", headers=headers, body=request,
        ))

    def send(self, access: str, request: dict, headers: dict) -> bytes:
        reply = self.call(access, request, headers)
        assert reply.status == 200, reply.body
        return b"".join(reply.events) if reply.events is not None else reply.body


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


@pytest.fixture
def subs(repo, engines, clock, stub) -> Subscriptions:
    return Subscriptions(repo, engines, clock, stub)


def codex_request() -> dict:
    return {"model": "gpt-6.1-sol", "stream": True, "store": False, "input": TASK}


def codex_answer() -> list[dict]:
    return [*text_events(0, message("msg_1", "Готово"), []), completed(message("msg_1", "Готово"))]


def test_claude_subscription_forwards_the_agents_token_and_beta(subs, stub):
    stub.script.append(model_turn("Готово"))
    subs.send("claude-subscription", claude_body(TASK), CLAUDE)
    sent = stub.headers(0)
    assert sent["authorization"] == f"Bearer {TOKEN}" and sent["anthropic-beta"] == CLAUDE["anthropic-beta"]
    assert (sent["user-agent"], sent["x-app"]) == (CLAUDE["user-agent"], "cli")
    assert "x-cleaner-key" not in sent and "x-stainless-os" not in sent and "x-api-key" not in sent
    assert stub.requests[0]["path"] == "/v1/messages?beta=true"
    assert "srv-dc01" not in stub.bodies() and "i.ivanov@contoso.ru" not in stub.bodies()


def test_chatgpt_subscription_forwards_token_and_account(subs, stub):
    stub.script.append(codex_answer())
    subs.send("chatgpt-subscription", codex_request(), CODEX)
    sent = stub.headers(0)
    assert sent["authorization"] == f"Bearer {CHATGPT}" and sent["chatgpt-account-id"] == CODEX["chatgpt-account-id"]
    assert (sent["originator"], sent["session-id"]) == ("codex_exec", "s-1") and "x-cleaner-key" not in sent
    assert stub.requests[0]["path"] == "/backend-api/codex/responses" and "srv-dc01" not in stub.bodies()


def test_subscription_token_is_never_stored_logged_or_echoed(subs, stub, repo, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    seen = []
    forward = subs.service.forward

    def spy(out, *args, **kwargs):
        seen.append(out)
        return forward(out, *args, **kwargs)

    subs.service.forward = spy
    error = {"type": "error", "error": {"type": "authentication_error", "message": f"bad token {TOKEN} (Bearer {TOKEN})"}}
    stub.script += [model_turn("Готово"), {"status": 401, "body": error}]
    subs.send("claude-subscription", claude_body(TASK), CLAUDE)
    refused = subs.call("claude-subscription", claude_body("Ещё раз"), CLAUDE)
    assert refused.status == 401 and TOKEN.encode() not in refused.body and b"***" in refused.body
    assert all(TOKEN not in repr(out) and dict(out.headers)["authorization"] == f"Bearer {TOKEN}" for out in seen)
    call = AgentCall(subs.repo.api_key(subs.keys["claude-subscription"]), subs.repo.user(subs.user_id), "anthropic",
                     "/v1/messages", "", CLAUDE, {})
    assert TOKEN not in repr(call) and TOKEN not in caplog.text
    assert TOKEN not in json.dumps([event.details for event in repo.audit_events(limit=1000)], ensure_ascii=False)
    for path in tmp_path.glob("cleaner.db*"):
        assert TOKEN.encode() not in path.read_bytes(), path.name


def test_subscription_key_stops_working_without_the_admin_role(subs, stub, repo):
    repo.conn.execute("UPDATE users SET role = 'user' WHERE id = ?", (subs.user_id,))
    for access, request, headers in (("claude-subscription", claude_body(TASK), CLAUDE), ("chatgpt-subscription", codex_request(), CODEX)):
        with pytest.raises(AgentRefused) as refused:
            subs.call(access, request, headers)
        assert (refused.value.status, refused.value.kind) == (403, "permission_error")
    assert stub.requests == []


def test_provider_key_never_reaches_a_subscription_and_back(subs, stub, repo, engines, clock):
    """Агент со входом claude.ai шлёт свой OAuth и при ключе подключения: подключению он не уходит, а ключ подключения —
    на адрес подписки."""
    with StubProvider([model_turn("Готово")]) as provider_stub:
        provider = repo.add_provider(Provider("", "Заглушка", "anthropic", provider_stub.url, "x-api-key", PROVIDER_KEY, ("m-1",)))
        key = repo.add_api_key(subs.user_id, "по ключу", "h-provider", "bbbb", upstream=f"provider:{provider}", models=())
        reply = subs.service.handle(AgentCall(repo.api_key(key), repo.user(subs.user_id), "anthropic", "/v1/messages", "",
                                              CLAUDE, claude_body(TASK)))
        b"".join(reply.events)
        to_provider = json.dumps(provider_stub.requests[0]["headers"])
    stub.script.append(model_turn("Готово"))
    subs.send("claude-subscription", claude_body(TASK), CLAUDE)
    assert PROVIDER_KEY in to_provider and TOKEN not in to_provider
    assert PROVIDER_KEY not in json.dumps(stub.requests[0]["headers"])


def test_subscription_needs_the_agents_login(subs, stub):
    without = {name: value for name, value in CLAUDE.items() if name != "authorization"}
    cleaner_key = "ck_" + "a" * 43
    # Ключ Cleaner — не вход подписки, и с лишним пробелом после схемы тоже: иначе он ушёл бы провайдеру.
    for headers in (without, dict(CLAUDE, authorization=f"Bearer {cleaner_key}"), dict(CLAUDE, authorization=f"Bearer  {cleaner_key}")):
        with pytest.raises(AgentRefused) as refused:
            subs.call("claude-subscription", claude_body(TASK), headers)
        assert (refused.value.status, refused.value.kind) == (401, "authentication_error")
    with pytest.raises(AgentRefused) as refused:
        subs.call("claude-subscription", codex_request(), CODEX, protocol="responses")
    assert refused.value.status == 400
    assert stub.requests == []


def test_only_admins_create_subscription_keys(repo, ivan, boss):
    with pytest.raises(ValueError):
        gateway_access(repo, "claude-subscription", (), admin=False)
    assert gateway_access(repo, "chatgpt-subscription", ("gpt-6.1-sol", "gpt-6.1-sol"), admin=True) == (
        "chatgpt-subscription", ("gpt-6.1-sol",))
    assert ivan.post("/keys", name="агент", provider="chatgpt-subscription").status_code == 400
    assert boss.post("/keys", name="агент", provider="chatgpt-subscription").status_code == 303
    [key] = repo.api_keys()
    assert key.upstream == "chatgpt-subscription"


def test_subscription_key_has_no_models_list(browser, repo):
    """GET /v1/models у ключа с подпиской — 404: Claude Code и Codex его не зовут, а список подписки знает провайдер."""
    user_id = repo.create_user("boss2", "hash", "admin")
    key = auth.new_api_key()
    repo.add_api_key(user_id, "подписка", auth.token_hash(key), key[-4:], upstream="chatgpt-subscription", models=())
    client = browser().client
    for path in ("/agent/openai/v1/models", "/agent/anthropic/v1/models"):
        assert client.get(path, headers={"x-cleaner-key": key}).status_code == 404
