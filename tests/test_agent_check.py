"""Самопроверка агента (спецификация 2026-10-28, раздел 14): GET …/v1/cleaner/check с ключом — ключ, доступ, протокол,
модель, TLS и доступность провайдера без текста пользователя. Провайдер — MockTransport: к нему уходит только GET без
тела и без ключа подключения."""
from functools import partial

import httpx
import pytest

from cleaner.egress import forward
from cleaner.storage.repo import Provider
from cleaner.web import auth

PROVIDER_KEY = "sk-" "check-0123456789"     # вымышленный ключ подключения


@pytest.fixture
def agent(app, browser, repo):
    seen: list[httpx.Request] = []

    def receive(request):
        seen.append(request)
        if "down" in request.url.host:
            raise httpx.ConnectError("нет связи")
        return httpx.Response(404)

    app.state.agent.reach = partial(forward.reach, transport=httpx.MockTransport(receive))
    user_id = repo.create_user("petr", auth.hash_password("пароль-для-тестов"), "user")

    def key(base_url: str = "https://llm.example/anthropic", protocol: str = "anthropic") -> str:
        provider_id = repo.add_provider(Provider("", "Заглушка", protocol, base_url, "x-api-key", PROVIDER_KEY, ("m-1", "m-2")))
        value = auth.new_api_key()
        repo.add_api_key(user_id, "агент", auth.token_hash(value), value[-4:], upstream=f"provider:{provider_id}", models=("m-1",))
        return value

    return browser().client, key, seen


def checks(response) -> dict[str, bool | None]:
    assert response.status_code == 200, response.text
    return {item["name"]: item["ok"] for item in response.json()["checks"]}


def test_check_reports_every_step_without_user_data(agent):
    client, key, seen = agent
    value = key()
    response = client.get("/agent/anthropic/v1/cleaner/check", headers={"x-api-key": value})
    assert checks(response) == {"key": True, "access": True, "protocol": True, "model": True, "tls": None, "provider": True}
    assert response.json()["ok"] is True and "HTTP 404" in response.text
    [probe] = seen
    assert probe.method == "GET" and probe.content == b"" and str(probe.url) == "https://llm.example/anthropic"
    assert PROVIDER_KEY not in str(probe.headers) and value not in str(probe.headers)
    assert client.get("/agent/anthropic/v1/cleaner/check").status_code == 401


def test_check_finds_wrong_model_protocol_and_unreachable_provider(agent):
    client, key, _ = agent
    value = key()
    found = checks(client.get("/agent/anthropic/v1/cleaner/check?model=m-2", headers={"x-api-key": value}))
    assert found["model"] is False
    assert checks(client.get("/agent/openai/v1/cleaner/check", headers={"x-cleaner-key": value}))["protocol"] is False
    down = key("https://down.example/v1", "responses")
    response = client.get("/agent/openai/v1/cleaner/check", headers={"authorization": f"Bearer {down}"})
    assert checks(response)["provider"] is False and response.json()["ok"] is False
    assert "/agent/openai/v1/responses" in response.text
