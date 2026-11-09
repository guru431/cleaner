"""Изображения и файлы на любой глубине вложенности (спецификация 2026-10-28, 7.4 и 8.3; FR-8.8): снимок экрана в
computer_call_output и картинка в блоке незнакомого вида удерживаются пометкой, а не уходят как текст. Служба шлюза
целиком, провайдер — MockTransport; проверяется тело, ушедшее провайдеру. Данные вымышленные."""
import json
from functools import partial

import httpx
import pytest

from cleaner.agent_service import AgentCall, AgentService
from cleaner.core.agent import walk
from cleaner.egress import forward as egress
from cleaner.storage.repo import Provider

PIXELS = "iVBORw0KGgo" + "QUFB" * 1100           # base64 вымышленной картинки, длиннее 4 КиБ
HELD = "[Cleaner: блок не передан — изображение или файл не передаётся]"


@pytest.fixture
def gateway(repo, clock):
    sent: list[dict] = []

    def receive(request):
        sent.append(json.loads(request.content))
        if request.url.path.endswith("/responses"):
            reply = {"output": [{"type": "message", "content": [{"type": "output_text", "text": "Готово"}]}]}
        else:
            reply = {"content": [{"type": "text", "text": "Готово"}]}
        return httpx.Response(200, json=reply)

    user_id = repo.create_user("media", "hash", "user")
    service = AgentService(repo, None, clock, forward=partial(egress.forward, transport=httpx.MockTransport(receive)))

    def call(protocol: str, body: dict) -> str:
        provider_id = repo.add_provider(Provider("", "Stub", protocol, "http://127.0.0.1", "bearer", "stub-only", ("m",)))
        key_id = repo.add_api_key(user_id, "media", "hash-" + provider_id, "aaaa", "provider:" + provider_id, ("m",))
        path = "/responses" if protocol == "responses" else "/v1/messages"
        service.handle(AgentCall(repo.api_key(key_id), repo.user(user_id), protocol, path, "", {}, {"model": "m", "stream": False, **body}))
        return repo.api_key(key_id).chat_id

    return call, sent


CASES = {
    "computer_call_output": ("responses", {"input": [
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Сделай снимок"}]},
        {"type": "computer_call", "call_id": "c1", "action": {"type": "screenshot"}},
        {"type": "computer_call_output", "call_id": "c1",
         "output": {"type": "computer_screenshot", "image_url": f"data:image/png;base64,{PIXELS}"}},
    ]}),
    "unknown_block": ("anthropic", {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "Что на картинке?"},
        {"type": "custom_attachment", "payload": {"preview": {"type": "image", "source": {
            "type": "base64", "media_type": "image/png", "data": PIXELS}}}},
    ]}]}),
}


@pytest.mark.parametrize("case", CASES)
def test_nested_image_is_withheld(gateway, repo, case):
    call, sent = gateway
    chat_id = call(*CASES[case])
    raw = json.dumps(sent[0], ensure_ascii=False)
    assert PIXELS[:64] not in raw and "data:image" not in raw and HELD in raw
    assert repo.agent_receipts(chat_id)[0]["withheld"] == {"media": 1}


def test_signatures_and_plain_text_are_not_media():
    signed = {"type": "custom_thinking", "signature": PIXELS, "text": "обычный текст"}
    assert walk.hold_media(signed) == (signed, False)
    assert walk.hold_media({"type": "text", "text": "ссылка data:text/plain,hello"})[1] is False
