"""Страница «Ключи» (FR-13.1, планы 5А и 5Б): выпуск, показ один раз, отзыв, кто что видит, ключи шлюза агентов."""
import html
import json
import re

from cleaner.storage.repo import Provider
from tests.agent_bodies import body, model_turn
from tests.stub_provider import StubProvider

KEY = re.compile(r"ck_[A-Za-z0-9_-]{43}")


def issue(browser, name: str) -> str:
    response = browser.post("/keys", name=name)
    assert response.status_code == 200, response.text
    return KEY.search(response.text).group(0)


def test_key_is_shown_once_then_only_its_tail(ivan):
    response = ivan.post("/keys", name="Отчёты")
    key = KEY.search(response.text).group(0)
    assert "api/v1/chats" in response.text
    page = ivan.get("/keys").text
    assert key not in page and f"…{key[-4:]}" in page and "Отчёты" in page
    assert ivan.client.get("/api/v1/chats", headers={"X-Cleaner-Key": key}).status_code == 200


def test_users_see_and_revoke_only_their_keys_admin_sees_all(browser, ivan, boss, repo):
    petr = browser()
    petr.user("petr")
    petr.login("petr")
    issue(ivan, "ключ Ивана")
    petr_key = issue(petr, "ключ Петра")
    [petr_key_id] = [k.id for k in repo.api_keys(repo.user_by_login("petr").id)]
    page = ivan.get("/keys").text
    assert "ключ Ивана" in page and "ключ Петра" not in page
    assert ivan.post(f"/keys/{petr_key_id}/disable").status_code == 404
    assert not repo.api_key(petr_key_id).disabled
    admin_page = boss.get("/keys").text
    assert all(text in admin_page for text in ("ключ Ивана", "ключ Петра", "ivan", "petr", "Владелец"))
    response = boss.post(f"/keys/{petr_key_id}/disable")
    assert (response.status_code, response.headers["location"]) == (303, "/keys")
    assert petr.client.get("/api/v1/chats", headers={"X-Cleaner-Key": petr_key}).status_code == 401
    assert [(e.event, e.details) for e in repo.audit_events("key_disabled")] == [("key_disabled", {"id": petr_key_id})]
    assert len(repo.audit_events("key_created")) == 2


def test_key_name_is_required_and_limited(ivan, repo):
    for name in ("", "   ", "я" * 101):
        assert ivan.post("/keys", name=name).status_code == 400, len(name)
    assert repo.api_keys() == []
    assert ivan.post("/keys", name="я" * 100).status_code == 200


def test_keys_page_is_in_the_menu_for_everyone(ivan, boss):
    assert 'href="/keys"' in ivan.get("/chats").text and 'href="/keys"' in boss.get("/chats").text


def test_key_forms_need_the_csrf_token(ivan, repo):
    assert ivan.client.post("/keys", data={"name": "без токена"}).status_code == 403
    issue(ivan, "ключ")
    [key] = repo.api_keys()
    assert ivan.client.post(f"/keys/{key.id}/disable", data={}).status_code == 403
    assert not repo.api_key(key.id).disabled


# --- ключи шлюза агентов (план 5Б, задача 9) ------------------------------------------------

def providers(repo, url: str = "https://llm.example/anthropic") -> dict[str, str]:
    return {
        "anthropic": repo.add_provider(Provider("", "DeepSeek", "anthropic", url, "x-api-key", "sk-1", ("m-1", "m-2"))),
        "openai": repo.add_provider(Provider("", "OpenAI", "openai", "https://llm.example/v1", "bearer", "sk-2", ("g-1",))),
        "off": repo.add_provider(Provider("", "Выключено", "anthropic", url, "x-api-key", "sk-3", ("m-1",), enabled=False)),
    }


def test_gateway_key_needs_an_enabled_anthropic_connection_and_its_models(ivan, repo):
    ids = providers(repo)
    form = ivan.get("/keys").text
    assert "DeepSeek" in form and "OpenAI" not in form and "Выключено" not in form
    for provider, model in ((ids["openai"], "g-1"), (ids["off"], "m-1"), ("нет", "m-1"), (ids["anthropic"], "m-9")):
        fields = {"name": "агент", "provider": provider, f"m:{provider}:{model}": "1"}
        assert ivan.post("/keys", **fields).status_code == 400, provider
    assert repo.api_keys() == []
    response = ivan.post("/keys", name="агент", provider=ids["anthropic"], **{f"m:{ids['anthropic']}:m-2": "1", "ner": "1"})
    assert response.status_code == 200
    [key] = repo.api_keys()
    assert (key.upstream, key.models, key.layers) == (f"provider:{ids['anthropic']}", ("m-2",), {"ner": True, "llm": False})
    page = ivan.get("/keys").text
    assert "DeepSeek: m-2" in page and page.count("только API") == 1         # только пункт формы
    issue(ivan, "скрипт")
    assert ivan.get("/keys").text.count("только API") == 2


def test_gateway_key_page_shows_the_claude_code_settings_once(ivan, repo):
    ids = providers(repo)
    response = ivan.post("/keys", name="агент", provider=ids["anthropic"])         # моделей не отмечено — все
    key = KEY.search(response.text).group(0)
    shown = html.unescape(response.text)
    for line in (
        '"ANTHROPIC_BASE_URL": "http://testserver/agent/anthropic"', f'"ANTHROPIC_AUTH_TOKEN": "{key}"',
        '"ANTHROPIC_MODEL": "m-1"', '"ANTHROPIC_DEFAULT_HAIKU_MODEL": "m-1"', '"CLAUDE_CODE_ATTRIBUTION_HEADER": "0"',
        '"NODE_EXTRA_CA_CERTS"', "settings.local.json",
    ):
        assert line in shown, line
    assert repo.api_keys()[0].models == ()
    assert key not in ivan.get("/keys").text and "DeepSeek: все модели" in ivan.get("/keys").text


def test_restart_starts_a_new_chat_for_new_conversations(ivan, repo):
    with StubProvider([model_turn("Раз"), model_turn("Два"), model_turn("Три")]) as stub:
        ids = providers(repo, stub.url)
        key = KEY.search(ivan.post("/keys", name="агент", provider=ids["anthropic"]).text).group(0)
        [stored] = repo.api_keys()

        def send(task: str) -> None:
            response = ivan.client.post("/agent/anthropic/v1/messages", content=json.dumps(body(task)).encode(),
                                        headers={"x-api-key": key, "content-type": "application/json"})
            assert response.status_code == 200, response.text

        send("Первый разговор")
        first = repo.api_key(stored.id).chat_id
        assert first and f'href="/chats/{first}"' in ivan.get("/keys").text
        response = ivan.post(f"/keys/{stored.id}/restart")
        assert (response.status_code, response.headers["location"]) == (303, "/keys")
        assert repo.api_key(stored.id).chat_id is None
        send("Второй разговор")
        second = repo.api_key(stored.id).chat_id
        send("Первый разговор")             # идущий разговор — в своём чате
        assert second not in (None, first) and repo.api_key(stored.id).chat_id == second
    assert [e.details for e in repo.audit_events("key_restarted")] == [{"id": stored.id}]


def test_restart_is_owner_or_admin_only(browser, ivan, boss, repo):
    ids = providers(repo)
    ivan.post("/keys", name="агент", provider=ids["anthropic"])
    [key] = repo.api_keys()
    chat = repo.create_chat(key.user_id, "Агент", kind="agent")
    repo.set_key_chat(key.id, chat)
    petr = browser()
    petr.user("petr")
    petr.login("petr")
    assert petr.post(f"/keys/{key.id}/restart").status_code == 404
    assert repo.api_key(key.id).chat_id == chat
    assert ivan.client.post(f"/keys/{key.id}/restart", data={}).status_code == 403
    assert boss.post(f"/keys/{key.id}/restart").status_code == 303 and repo.api_key(key.id).chat_id is None
