"""Application preview/send boundary; synthetic documents and an in-process cloud only."""
import json

import pytest

from cleaner.core.types import EntityType, Policy
from cleaner.storage.repo import Provider


@pytest.fixture
def integration(api, repo, app):
    client = api()
    provider = repo.add_provider(Provider("", "Test", "openai", "https://llm.example/v1", "bearer",
                                         "synthetic-test-key", ("test-model",)))
    repo.conn.execute("UPDATE api_keys SET upstream = ?, models = ? WHERE id = ?",
                      (f"provider:{provider}", '["test-model"]', client.key_id))
    calls = []

    def cloud(context, *args, **kwargs):
        calls.append(context)
        yield "Ответ <EMAIL_1> и [ссылка](https://external.example/?v=<EMAIL_1>)"

    app.state.service.cloud_send = cloud
    cid = client.post("/api/v1/chats", json={"layers": {"ner": False}}).json()["id"]
    return client, cid, calls


def preview(integration, text="Почта ivan@contoso.ru", **fields):
    client, cid, _ = integration
    return client.post(f"/api/v1/chats/{cid}/requests", json={
        "model": "test-model", "messages": [{"role": "user", "content": text}], **fields,
    })


def send(integration, receipt):
    client, cid, _ = integration
    return client.post(f"/api/v1/chats/{cid}/requests/send", json={"receipt": receipt})


def test_preview_has_no_cloud_side_effect_and_send_restores_browser_safely(integration):
    client, cid, calls = integration
    shown = preview(integration)
    assert shown.status_code == 200, shown.text
    body = shown.json()
    assert body["deliverable"] and body["counts"]["EMAIL"] == 1 and calls == []
    assert "ivan@contoso.ru" not in json.dumps(body)
    assert "<EMAIL_1>" in body["messages"][-1]["content"]
    sent = send(integration, body["receipt"])
    assert sent.status_code == 202, sent.text
    assert len(calls) == 1 and "ivan@contoso.ru" not in " ".join(calls[0].texts())
    events = client.get(f'/api/v1/chats/{cid}/answers/{sent.json()["item_id"]}/events')
    done = json.loads([line[6:] for line in events.text.splitlines() if line.startswith("data: ")][-1])
    assert done["status"] == "done" and "Ответ ivan@contoso.ru" in done["text"]
    assert "https://external.example/?v=ivan@contoso.ru" not in done["text"]
    assert done["raw"].startswith("Ответ <EMAIL_1>")
    assert send(integration, body["receipt"]).status_code == 409


def test_new_preview_expires_previous_one_and_tampering_never_sends(integration):
    old = preview(integration).json()["receipt"]
    newer = preview(integration, "Ещё ivan@contoso.ru").json()["receipt"]
    assert send(integration, old).status_code == 409
    assert send(integration, "!" + newer).status_code == 409
    assert integration[2] == []
    assert send(integration, newer).status_code == 202


def test_expiry_revocation_and_other_owner_are_enforced(integration, api, clock, repo):
    client, cid, calls = integration
    receipt = preview(integration).json()["receipt"]
    other = api("petr")
    assert other.post(f"/api/v1/chats/{cid}/requests/send", json={"receipt": receipt}).status_code == 404
    clock.advance(seconds=601)
    assert send(integration, receipt).status_code == 409
    repo.disable_api_key(client.key_id)
    assert send(integration, receipt).status_code == 401
    assert calls == []


def test_block_policy_and_unscoped_model_cannot_send(integration, repo):
    repo.set_policy(EntityType.EMAIL, Policy.BLOCK)
    shown = preview(integration).json()
    assert not shown["deliverable"] and shown["blocked"]
    assert shown["messages"] == []
    assert send(integration, shown["receipt"]).status_code == 409
    assert preview(integration, model="other-model").status_code == 409
    assert integration[2] == []


def test_policy_change_after_preview_is_checked_again(integration, repo):
    shown = preview(integration).json()
    repo.set_policy(EntityType.EMAIL, Policy.BLOCK)
    assert send(integration, shown["receipt"]).status_code == 409
    assert integration[2] == []


def test_model_list_obeys_key_scope_and_binary_content_is_rejected(integration, api):
    assert integration[0].get("/api/v1/models").json() == {"data": [{"id": "test-model"}]}
    assert api().get("/api/v1/models").status_code == 403
    assert preview(integration, messages=[{"role": "user", "content": [{"type": "image_url"}]}]).status_code == 422


def test_manual_rules_are_context_scoped_and_old_receipt_is_invalid(integration, repo):
    old = preview(integration, "Проект Северное сияние").json()
    fixed = preview(integration, "Проект Северное сияние", rules=[
        {"action": "mask", "value": "Северное сияние", "type": "TERM"},
    ])
    assert fixed.status_code == 200, fixed.text
    assert "Северное сияние" not in json.dumps(fixed.json()["messages"], ensure_ascii=False)
    assert send(integration, old["receipt"]).status_code == 409
    next_request = preview(integration, "Снова Северное сияние").json()
    assert "Северное сияние" not in json.dumps(next_request["messages"], ensure_ascii=False)
    client, _, _ = integration
    other_id = client.post("/api/v1/chats", json={"layers": {"ner": False}}).json()["id"]
    assert repo.load_state(other_id)[0].rules == []


def test_manual_mask_cannot_weaken_secret_policy(integration):
    shown = preview(integration, "Пароль: SyntheticSecretABC123", rules=[
        {"action": "mask", "value": "SyntheticSecretABC123", "type": "TERM"},
    ])
    assert shown.status_code == 409, shown.text


def test_failed_required_layer_is_a_closed_boundary(integration, repo, app, monkeypatch):
    from cleaner.core.detect.base import DetectorError

    repo.set_chat_layer(integration[1], "ner", True)

    def unavailable():
        raise DetectorError("synthetic layer failure")

    monkeypatch.setattr(app.state.service.engines, "ner", unavailable)
    response = preview(integration)
    assert response.status_code == 503 and integration[2] == []
    assert "synthetic layer failure" not in response.text
