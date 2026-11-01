"""Measure the complete gateway's retained/serialized copies, including encrypted ledger writes.

Run separately from timing tests: tracemalloc materially slows Python execution.
"""
import gc
import json
import tracemalloc
from functools import partial

import httpx
import pytest

from cleaner.agent_service import AgentCall, AgentService
from cleaner.core.agent.protocol import PROTOCOLS
from cleaner.egress import forward as egress
from cleaner.storage.repo import Provider

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_gateway_response_copies_have_a_measured_budget(repo, clock, protocol):
    count, piece = 256, "safe text " * 410
    whole = piece * count

    def encoded(event):
        return b"data: " + json.dumps(event).encode() + b"\n\n"

    class Response(httpx.SyncByteStream):
        def __iter__(self):
            if protocol == "anthropic":
                yield encoded({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
                for _ in range(count):
                    yield encoded({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": piece}})
                yield encoded({"type": "content_block_stop", "index": 0})
                yield encoded({"type": "message_stop"})
            elif protocol == "chat":
                for _ in range(count):
                    yield encoded({"choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}]})
                yield encoded({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
                yield b"data: [DONE]\n\n"
            else:
                for _ in range(count):
                    yield encoded({"type": "response.output_text.delta", "item_id": "m", "output_index": 0, "content_index": 0, "delta": piece})
                yield encoded({"type": "response.output_text.done", "item_id": "m", "output_index": 0, "content_index": 0, "text": whole})
                yield encoded({"type": "response.completed", "response": {"output": [{"type": "message", "id": "m", "content": [{"type": "output_text", "text": whole}]}]}})

    user_id = repo.create_user("memory", "hash", "user")
    proto = PROTOCOLS[protocol]
    provider_id = repo.add_provider(Provider("", "Stub", proto.provider_protocol, "http://127.0.0.1", "bearer", "", ("m",)))
    key_id = repo.add_api_key(user_id, "memory", "hash", "aaaa", "provider:" + provider_id, ("m",))
    service = AgentService(repo, None, clock, forward=partial(egress.forward, transport=httpx.MockTransport(
        lambda _: httpx.Response(200, stream=Response()))))
    body = {"model": "m", "stream": True, "input" if protocol == "responses" else "messages": [{"role": "user", "content": "Задача"}]}
    call = AgentCall(repo.api_key(key_id), repo.user(user_id), protocol, "/responses", "", {}, body)
    gc.collect()
    tracemalloc.start()
    try:
        reply = service.handle(call)
        # The consumer also keeps the complete HTTP response, so the peak includes that extra copy.
        response = b"".join(reply.events)
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert b'"error"' not in response
    assert repo.agent_receipts(repo.api_key(key_id).chat_id)[0]["status"] == 200
    print(f"{protocol}: original={len(whole)}B HTTP={len(response)}B retained={current}B peak={peak}B")
    assert peak < 40 * 1024 * 1024
