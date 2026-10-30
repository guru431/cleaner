"""Страница «Ключи» (FR-13.1, планы 5А и 5Б): выпуск, показ один раз, отзыв, кто что видит, ключи шлюза агентов."""
import ast
import html
import json
import re
import tomllib

from fastapi.testclient import TestClient

from cleaner.storage.repo import Provider
from cleaner.web.app import create_app
from tests.agent_bodies import body, model_turn
from tests.stub_provider import StubProvider

KEY = re.compile(r"ck_[A-Za-z0-9_-]{43}")


def issue(browser, name: str) -> str:
    response = issue_page(browser, name=name)
    assert response.status_code == 200, response.text
    return KEY.search(response.text).group(0)


def issue_page(browser, **fields):
    response = browser.post("/keys", **fields)
    assert response.status_code == 303, response.text
    return browser.get(response.headers["location"])


def test_key_is_shown_once_then_only_its_tail(ivan):
    response = issue_page(ivan, name="Отчёты")
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
    assert ivan.post("/keys", name="я" * 100).status_code == 303


def test_keys_page_is_in_the_menu_for_everyone(ivan, boss):
    assert 'href="/keys"' in ivan.get("/chats").text and 'href="/keys"' in boss.get("/chats").text


def test_key_forms_need_the_csrf_token(ivan, repo):
    assert ivan.client.post("/keys", data={"name": "без токена"}).status_code == 403
    issue(ivan, "ключ")
    [key] = repo.api_keys()
    assert ivan.client.post(f"/keys/{key.id}/disable", data={}).status_code == 403
    assert not repo.api_key(key.id).disabled


def test_refresh_after_issuing_a_key_does_not_issue_another(ivan, repo):
    response = ivan.post("/keys", name="один ключ")
    assert response.status_code == 303
    assert KEY.search(response.headers["location"]) is None
    first = ivan.get(response.headers["location"])
    assert KEY.search(first.text)
    assert "no-store" in first.headers["cache-control"]
    again = ivan.get(response.headers["location"])
    assert KEY.search(again.text) is None and len(repo.api_keys()) == 1


def test_key_names_cannot_contain_control_characters(ivan, repo):
    for name in ("a\tb", "a\nb", "a\x00b", "a\x7fb"):
        assert ivan.post("/keys", name=name).status_code == 400
    assert repo.api_keys() == []


def test_key_ticket_is_bound_to_the_session_and_expires(ivan, boss, clock):
    response = ivan.post("/keys", name="личный ключ")
    path = response.headers["location"]
    assert KEY.search(boss.get(path).text) is None
    assert KEY.search(ivan.get(path).text)
    expired = ivan.post("/keys", name="просроченный показ")
    clock.advance(minutes=6)
    assert KEY.search(ivan.get(expired.headers["location"]).text) is None


# --- ключи шлюза агентов (план 5Б, задача 9) ------------------------------------------------

def providers(repo, url: str = "https://llm.example/anthropic") -> dict[str, str]:
    return {
        "anthropic": repo.add_provider(Provider("", "DeepSeek", "anthropic", url, "x-api-key", "sk-1", ("m-1", "m-2"))),
        "openai": repo.add_provider(Provider("", "OpenAI", "openai", "https://llm.example/v1", "bearer", "sk-2", ("g-1",))),
        "off": repo.add_provider(Provider("", "Выключено", "anthropic", url, "x-api-key", "sk-3", ("m-1",), enabled=False)),
    }


def test_gateway_key_needs_an_enabled_connection_and_its_models(ivan, repo):
    """План 5В: шлюз говорит и на протоколах OpenAI — подключение OpenAI тоже годится."""
    ids = providers(repo)
    form = ivan.get("/keys").text
    assert "DeepSeek" in form and "OpenAI" in form and "Выключено" not in form
    for provider, model in ((ids["openai"], "m-1"), (ids["off"], "m-1"), ("нет", "m-1"), (ids["anthropic"], "m-9")):
        fields = {"name": "агент", "provider": provider, f"m:{provider}:{model}": "1"}
        assert ivan.post("/keys", **fields).status_code == 400, provider
    assert repo.api_keys() == []
    response = issue_page(ivan, name="агент", provider=ids["anthropic"], **{f"m:{ids['anthropic']}:m-2": "1", "ner": "1"})
    assert response.status_code == 200
    [key] = repo.api_keys()
    assert (key.upstream, key.models, key.layers) == (f"provider:{ids['anthropic']}", ("m-2",), {"ner": True, "llm": False})
    page = ivan.get("/keys").text
    assert "DeepSeek: m-2" in page and page.count("только API") == 1         # только пункт формы
    issue(ivan, "скрипт")
    assert ivan.get("/keys").text.count("только API") == 2


def test_gateway_key_page_shows_the_claude_code_settings_once(ivan, repo):
    ids = providers(repo)
    response = issue_page(ivan, name="агент", provider=ids["anthropic"])         # моделей не отмечено — все
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


def test_admin_sees_subscriptions_user_does_not(ivan, boss, repo):
    providers(repo, "https://llm.example/v1")
    for name in ("Подписка Claude (Claude Code)", "Подписка ChatGPT (Codex)"):
        assert name in boss.get("/keys").text and name not in ivan.get("/keys").text
    form = ivan.get("/keys").text
    assert "DeepSeek (Anthropic)" in form and "OpenAI (OpenAI Chat Completions)" in form


def test_subscription_form_from_a_user_is_400(ivan, repo):
    for access in ("claude-subscription", "chatgpt-subscription"):
        assert ivan.post("/keys", name="агент", provider=access).status_code == 400
    assert repo.api_keys() == []


def test_each_access_shows_its_agent_settings_once(boss, repo):
    """Блок «Ключ показан один раз» — готовая настройка агента по виду доступа (раздел 14): Claude Code по ключу и по
    подписке, Codex по ключу Responses и по подписке ChatGPT, OpenCode и SDK OpenAI по ключу Chat Completions."""
    anthropic = repo.add_provider(Provider("", "DeepSeek", "anthropic", "https://llm.example/anthropic", "x-api-key", "sk-1", ("m-1",)))
    openai = repo.add_provider(Provider("", "Go", "openai", "https://llm.example/v1", "bearer", "sk-2", ("g-1",)))
    responses = repo.add_provider(Provider("", "OpenAI", "responses", "https://api.example/v1", "bearer", "sk-3", ("gpt-5.5",)))
    cases = {
        anthropic: ['"ANTHROPIC_AUTH_TOKEN": "{key}"', '"ANTHROPIC_BASE_URL": "http://testserver/agent/anthropic"'],
        "claude-subscription": ['"ANTHROPIC_CUSTOM_HEADERS": "X-Cleaner-Key: {key}"', "claude-switch.ps1 cleaner-sub",
                                '"ANTHROPIC_BASE_URL": "http://testserver/agent/anthropic"'],
        responses: ['base_url = "http://testserver/agent/openai/v1"', 'wire_api = "responses"', 'env_key = "CLEANER_KEY"',
                    '$env:CLEANER_KEY = "{key}"', "CODEX_CA_CERTIFICATE", 'model = "gpt-5.5"'],
        "chatgpt-subscription": ["requires_openai_auth = true", 'env_http_headers = { "X-Cleaner-Key" = "CLEANER_KEY" }',
                                 '$env:CLEANER_KEY = "{key}"'],
        openai: ['"npm": "@ai-sdk/openai-compatible"', '"baseURL": "http://testserver/agent/openai/v1"',
                 '"apiKey": "{key}"', '"model": "cleaner/g-1"', 'OpenAI(base_url="http://testserver/agent/openai/v1"'],
    }
    for access, lines in cases.items():
        response = issue_page(boss, name=f"агент {access}", provider=access)
        assert response.status_code == 200, response.text
        key = KEY.search(response.text).group(0)
        shown = html.unescape(response.text)
        for line in lines:
            assert line.replace("{key}", key) in shown, (access, line)
        snippets = "".join(re.findall(r'<pre class="text mono">(.*?)</pre>', shown, re.S))
        assert ("ANTHROPIC_AUTH_TOKEN" in snippets) is (access == anthropic)
        assert ("requires_openai_auth" in snippets) is (access == "chatgpt-subscription")
        assert key not in boss.get("/keys").text
    names = {key.name: key.upstream for key in repo.api_keys()}
    assert names["агент claude-subscription"] == "claude-subscription"
    page = boss.get("/keys").text
    assert "Подписка Claude: все модели" in page and "Подписка ChatGPT: все модели" in page


def test_subscription_models_are_free_text(boss, repo):
    response = issue_page(boss, name="агент", provider="chatgpt-subscription", sub_models="gpt-6.1-sol, gpt-5.5,,gpt-5.5")
    assert response.status_code == 200
    assert repo.api_keys()[0].models == ("gpt-6.1-sol", "gpt-5.5")


def snippets(response) -> list[str]:
    return re.findall(r'<pre class="text mono">(.*?)</pre>', html.unescape(response.text), re.S)


def test_opencode_settings_carry_the_key_as_api_key(ivan, repo):
    """AI SDK шлёт apiKey заголовком Authorization: Bearer — шлюз берёт ключ оттуда и провайдеру его не передаёт
    (test_web_agent_openai.py::test_chat_and_responses_stream_through_the_gateway[authorization])."""
    ids = providers(repo)
    response = issue_page(ivan, name="opencode", provider=ids["openai"])
    key = KEY.search(response.text).group(0)
    config = json.loads(snippets(response)[1])             # первый — сам ключ
    assert config["provider"]["cleaner"]["options"] == {"baseURL": "http://testserver/agent/openai/v1", "apiKey": key}
    assert config["model"] == "cleaner/g-1"


def test_model_names_are_escaped_in_toml_and_python(boss, repo):
    """Модель подписки ChatGPT — свободное поле, модель подключения задаёт администратор: кавычка и обратная косая черта
    не ломают ни TOML Codex, ни Python SDK."""
    model = 'a"b\\c'
    response = issue_page(boss, name="codex", provider="chatgpt-subscription", sub_models=model)
    assert response.status_code == 200, response.text
    _, codex = snippets(response)                          # первый — сам ключ
    assert tomllib.loads(codex.split("\n\n# PowerShell")[0])["model"] == model
    provider = repo.add_provider(Provider("", "Go", "openai", "https://llm.example/v1", "bearer", "sk-2", (model,)))
    response = issue_page(boss, name="sdk", provider=provider)
    key = KEY.search(response.text).group(0)
    _, opencode, sdk = snippets(response)
    assert json.loads(opencode)["model"] == f"cleaner/{model}"
    calls = {node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id: node
             for node in ast.walk(ast.parse(sdk)) if isinstance(node, ast.Call)}
    assert {k.arg: k.value.value for k in calls["create"].keywords if k.arg == "model"} == {"model": model}
    assert {k.arg: k.value.value for k in calls["OpenAI"].keywords}["api_key"] == key


def test_cert_is_served_without_login_and_only_the_cert(browser, ivan, app, repo, clock, tmp_path):
    """Сертификат службы — без входа (то же, что клиент получает при TLS); ключ TLS этим путём не отдаётся."""
    cert, tls_key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIBvymyshlennyi\n-----END CERTIFICATE-----\n")
    tls_key.write_bytes(b"REDACTED_PRIVATE_KEY\n")
    anonymous = browser()
    assert anonymous.get("/cert.pem").status_code == 404                     # без TLS сертификата нет
    ids = providers(repo)
    assert 'href="/cert.pem"' not in issue_page(ivan, name="без TLS", provider=ids["anthropic"]).text
    served = create_app(repo, clock, secure_cookies=True, cert_file=str(cert))
    response = TestClient(served).get("/cert.pem")
    assert response.status_code == 200 and response.content == cert.read_bytes()
    assert b"PRIVATE KEY" not in response.content
    assert response.headers["content-type"] == "application/x-pem-file"
    assert response.headers["content-disposition"] == 'attachment; filename="cleaner-cert.pem"'
    # Ключ и сертификат одним файлом (tls_cert = tls_key): отдаются только блоки сертификата (финальное ревью 5Г, M5).
    combined = tmp_path / "combined.pem"
    combined.write_bytes(tls_key.read_bytes() + cert.read_bytes() + b"REDACTED_PRIVATE_KEY\n")
    response = TestClient(create_app(repo, clock, secure_cookies=True, cert_file=str(combined))).get("/cert.pem")
    assert response.status_code == 200 and response.content == cert.read_bytes()
    app.state.cert_file = str(cert)
    page = issue_page(ivan, name="с TLS", provider=ids["anthropic"]).text
    assert 'href="/cert.pem"' in page and "путь к файлу сертификата" in html.unescape(page)
    assert 'href="/cert.pem"' not in ivan.get("/keys").text              # ссылка — при готовых настройках


def test_restart_starts_a_new_chat_for_new_conversations(ivan, repo):
    with StubProvider([model_turn("Раз"), model_turn("Два"), model_turn("Три")]) as stub:
        ids = providers(repo, stub.url)
        key = KEY.search(issue_page(ivan, name="агент", provider=ids["anthropic"]).text).group(0)
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
