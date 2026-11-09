"""Explicit original-text consent uses only the configured local transport."""
import json

import httpx
import pytest

from cleaner.core.types import EntityType, Policy
from cleaner.engines import Engines, GATEWAY_KEY_ENV
from cleaner.storage.repo import Item


@pytest.fixture
def local(api, app, repo, tmp_path):
    program = api()
    cid = program.post("/api/v1/chats", json={"layers": {"ner": False}}).json()["id"]
    sent = []

    def receive(request):
        sent.append(request)
        return httpx.Response(200, text='data: {"choices":[{"delta":{"content":"Local <EMAIL_1>"}}]}\n\ndata: [DONE]\n\n')

    app.state.service.engines = Engines(repo, tmp_path, environ={GATEWAY_KEY_ENV: "invented-local-key"},
                                         transport=httpx.MockTransport(receive))
    app.state.service.cloud_send = lambda *a, **kw: pytest.fail("cloud transport was called")
    repo.set_policy(EntityType.EMAIL, Policy.BLOCK)
    return program, cid, sent


def prepare(local):
    program, cid, _ = local
    return program.post(f"/api/v1/chats/{cid}/local-requests", json={"messages": [{"role": "user", "content": "mail original@contoso.ru"}]})


def test_local_preview_shows_originals_and_needs_no_cloud_provider(local, repo):
    program, cid, sent = local
    shown = prepare(local)
    assert shown.status_code == 200, shown.text
    assert shown.json()["originals"] and shown.json()["destination"]["url"].startswith("http://127.0.0.1")
    assert sent == [] and "original@contoso.ru" in shown.json()["messages"][0]["content"]
    receipt = {"receipt": shown.json()["receipt"]}
    assert program.post(f"/api/v1/chats/{cid}/requests/send", json=receipt).status_code == 409
    result = program.post(f"/api/v1/chats/{cid}/local-requests/send", json=receipt)
    assert result.status_code == 202, result.text
    assert len(sent) == 1 and sent[0].url.host == "127.0.0.1"
    assert json.loads(sent[0].content)["messages"][-1]["content"] == "mail original@contoso.ru"
    item_id = result.json()["item_id"]
    events = program.get(f"/api/v1/chats/{cid}/answers/{item_id}/events")
    assert 'Local <EMAIL_1>' in events.text and repo.item(cid, item_id).source == "local"
    assert program.post(f"/api/v1/chats/{cid}/local-requests/send", json=receipt).status_code == 409
    assert program.post(f"/api/v1/chats/{cid}/answers/{item_id}/stop").status_code == 204


def test_local_answer_events_carry_the_whole_prefix(api, app, repo):
    """Контракт SSE — весь префикс, клиент заменяет показанное: ответ из двух частей не показывается последним куском,
    и при обрыве без done на экране весь полученный текст."""
    program = api()
    cid = program.post("/api/v1/chats", json={}).json()["id"]
    item = repo.add_item(cid, Item("local-answer", 0, "answer", "", None, source="local", status="running"))

    class TwoParts:
        """Ответ, у которого к каждому опросу страницы приходит следующая часть."""

        def __init__(self):
            self.parts = iter(["Local ", "Local answer"])
            self.finished = False

        def text(self):
            text = next(self.parts)
            self.finished = text == "Local answer"
            return text

    app.state.service.live.get = lambda item_id: TwoParts()
    repo.finish_answer(cid, item.id, "Local answer", "done", {})
    events = program.get(f"/api/v1/chats/{cid}/answers/{item.id}/events").text
    shown = [json.loads(line[6:])["text"] for line in events.splitlines() if line.startswith("data: ")]
    assert shown == ["Local ", "Local answer", "Local answer"]       # два события text и done


def test_local_recipient_change_and_other_owner_invalidate_consent(local, repo, api):
    program, cid, sent = local
    shown = prepare(local).json()
    other = api("other")
    path = f"/api/v1/chats/{cid}/local-requests/send"
    assert other.post(path, json={}).status_code == 404
    repo.set_setting("local_llm.model", "another-local-model")
    assert program.post(path, json={"receipt": shown["receipt"]}).status_code == 409
    assert sent == []
    repo.set_setting("local_llm.url", "https://public.example/v1")
    assert prepare(local).status_code == 409 and sent == []
