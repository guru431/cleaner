"""Подключения к облачным моделям в настройках (FR-8.1, FR-8.2, FR-8.10, SEC-13)."""
import pytest

from cleaner.egress import ProviderError

KEY = "sk-test-0123456789abcd"


def fields(**changes) -> dict[str, str]:
    base = {
        "name": "Облако", "protocol": "anthropic", "base_url": "https://llm.example/anthropic", "auth_style": "x-api-key",
        "api_key": KEY, "models": "m-1\nm-2\nm-1", "max_tokens": "2048", "extra_body": '{"temperature": 0.2}',
        "enabled": "yes",
    }
    return base | changes


def test_only_admins_manage_connections(ivan):
    assert ivan.get("/settings/providers").status_code == 403
    assert ivan.post("/settings/providers", **fields()).status_code == 403


def test_key_is_shown_only_by_its_last_four_characters(boss, repo):
    assert boss.post("/settings/providers", **fields()).status_code == 303
    [provider] = repo.providers()
    assert (provider.models, provider.max_tokens, provider.extra_body) == (("m-1", "m-2"), 2048, {"temperature": 0.2})
    html = boss.get("/settings/providers").text
    assert KEY not in html and "…abcd" in html
    assert repo.audit_events("provider_changed")[0].details == {"action": "add", "id": provider.id}
    assert KEY not in repr([event.details for event in repo.audit_events()])


@pytest.mark.parametrize("changes", [
    {"base_url": "http://llm.example/v1"}, {"extra_body": '{"tools": []}'}, {"extra_body": "не JSON"},
    {"models": ""}, {"api_key": ""}, {"protocol": "grpc"}, {"max_tokens": "0"},
])
def test_unsafe_or_incomplete_connection_is_refused(boss, repo, changes):
    assert boss.post("/settings/providers", **fields(**changes)).status_code == 400
    assert repo.providers() == []


def test_loopback_http_is_allowed(boss, repo):
    assert boss.post("/settings/providers", **fields(base_url="http://127.0.0.1:8099/v1")).status_code == 303


def test_edit_without_a_key_keeps_it_and_delete_removes(boss, repo):
    boss.post("/settings/providers", **fields())
    [provider] = repo.providers()
    assert boss.post(f"/settings/providers/{provider.id}", **fields(name="Другое", api_key="", enabled="")).status_code == 303
    stored = repo.provider(provider.id)
    assert (stored.name, stored.enabled, stored.api_key) == ("Другое", False, KEY)
    assert boss.post(f"/settings/providers/{provider.id}/delete").status_code == 303
    assert repo.providers() == []
    assert boss.post(f"/settings/providers/{provider.id}/delete").status_code == 404
    assert boss.post("/settings/providers/нет", **fields()).status_code == 404


def test_moving_a_connection_needs_the_key_again(boss, repo):
    """Обзор этапа 3, FR-8.10: сменой адреса с прежним ключом его можно было бы увести на свой узел «Проверить»."""
    boss.post("/settings/providers", **fields())
    [provider] = repo.providers()
    moved = fields(base_url="https://collector.example/anthropic", api_key="")
    assert boss.post(f"/settings/providers/{provider.id}", **moved).status_code == 400
    assert boss.post(f"/settings/providers/{provider.id}", **fields(auth_style="bearer", api_key="")).status_code == 400
    assert repo.provider(provider.id).base_url == "https://llm.example/anthropic"
    same_host = fields(base_url="https://llm.example/anthropic/v2", api_key="")
    assert boss.post(f"/settings/providers/{provider.id}", **same_host).status_code == 303
    assert boss.post(f"/settings/providers/{provider.id}", **fields(base_url="https://collector.example/x", api_key="sk-new-1111")).status_code == 303


def test_check_shows_the_answer_or_the_providers_message(boss, repo, app, monkeypatch):
    boss.post("/settings/providers", **fields())
    [provider] = repo.providers()
    calls = []

    def fake(ctx, connection, state, settings, **kwargs):
        calls.append((ctx, state))
        yield "готово"

    monkeypatch.setattr(app.state.service, "cloud_send", fake)
    page = boss.post(f"/settings/providers/{provider.id}/check", model="m-2").text
    assert "m-2 ответил: готово" in page
    [(ctx, state)] = calls
    assert state is None and ctx.model == "m-2" and ctx.chat_id == ""

    def failing(*args, **kwargs):
        raise ProviderError(status=404, kind="not_found_error", detail="model: m-2 not found")
        yield

    monkeypatch.setattr(app.state.service, "cloud_send", failing)
    page = boss.post(f"/settings/providers/{provider.id}/check", model="m-2").text
    assert "у провайдера нет такого адреса или модели (код 404, not_found_error)" in page and "m-2 not found" in page
    assert boss.post(f"/settings/providers/{provider.id}/check", model="чужая").status_code == 400
