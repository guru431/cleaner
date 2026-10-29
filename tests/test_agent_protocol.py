"""Объект протокола шлюза (план 5В, задача 2): всё, что зависит от протокола, — обход тела, вставка инструкции, пометки
удержания, поток, списки заголовков, — за одним объектом. Протокол Anthropic даёт те же тела, что в 5Б."""
import hashlib
import json
from pathlib import Path

import pytest

from cleaner.core.agent.ledger import canonical
from cleaner.core.agent.protocol import PROTOCOLS
from cleaner.core.pipeline import build_agent_outgoing
from tests.agent_bodies import body
from tests.stub_provider import StubProvider
from tests.test_agent_service import TASK, Gateway

FIXTURES = Path(__file__).parent / "fixtures" / "agents" / "claude_code"
# Эталон 5Б, снятый до переноса (обход walk, очистка str.upper, сборка, инструкция по коду AgentService._clean):
# sha256 итогового тела и sha256 единиц (путь, роль, вид, канонический узел).
STAGE_5B = {
    "turn1": ("52ef6eafa7b5f0a22bb7eaf5e7f48e1ee0b440a519b9a8d7b76f33eaaffc4d6c",
              "3f4b9cbb39680111ac2640c162941251eb3d1a13480bd2c80004bd69557eaad9"),
    "turn2": ("ec313550ff9a51ea2af1f1a36f2ecbee1c3d072ed3ed872f8e4c27f45ff8d0bb",
              "612f6db01224fe79db2ce1a4343d40ec8af98604cafd5d4ebcb647ea0d1da066"),
    "resume": ("7e6af1c6bc82780ecfdb3570e6fc36445a826385cf31a090c21872159c630475",
               "4bd8d770a2f6cdfef5f560b028d9c81ff4c4478f3b0959fd73277deabd7d4025"),
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("name", STAGE_5B)
def test_anthropic_protocol_object_reproduces_stage_5b(name):
    proto = PROTOCOLS["anthropic"]
    request = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    units = proto.units(request)
    replaced = {u.path: proto.sanitize_unit(u, str.upper) for u in units if u.kind != "opaque"}
    out = proto.add_instruction(proto.rebuild(request, replaced), "ИНСТРУКЦИЯ")
    shape = json.dumps([[list(u.path), u.role, u.kind, canonical(u.node).decode()] for u in units], ensure_ascii=False)
    assert (_sha(json.dumps(out, ensure_ascii=False, separators=(",", ":")).encode()), _sha(shape.encode())) == STAGE_5B[name]


def test_anthropic_protocol_keeps_the_stage_5b_wire_details():
    proto = PROTOCOLS["anthropic"]
    assert (proto.name, proto.provider_protocol, proto.session_header) == ("anthropic", "anthropic", "x-claude-code-session-id")
    assert proto.sse({"type": "ping"}) == b'event: ping\ndata: {"type":"ping"}\n\n' and proto.end() == b""
    assert proto.error_event("Cleaner: оборвалось") == {"type": "error", "error": {"type": "api_error", "message": "Cleaner: оборвалось"}}
    units = proto.units({"system": "s", "tools": [{"name": "Read", "description": "d", "input_schema": {}}], "messages": [
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"p": "x"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "x"}]},
    ]})
    marks = [proto.placeholder(u, "причина") for u in units]
    text = "[Cleaner: блок не передан — причина]"
    assert marks == [
        {"type": "text", "text": text},
        {"type": "tool_use", "id": "t1", "name": "Read", "input": {"cleaner": text}},
        {"type": "tool_result", "tool_use_id": "t1", "content": text},
        {"name": "Read", "description": text, "input_schema": {"type": "object"}},
    ]
    assert [proto.is_model_block(u) for u in units] == [False, True, False, False]


def test_headers_are_kept_by_list_and_prefix(state, settings):
    headers = {
        "Session-Id": "s-1", "X-Codex-Window-Id": "w-1", "x-codex-turn-metadata": "{}", "x-stainless-os": "Windows",
        "authorization": "Bearer agent-token", "x-cleaner-key": "ck_1", "x-codex-note": "не ASCII",
    }
    out, _ = build_agent_outgoing(
        state, settings, chat_id=state.chat_id, provider_id="p1", path="/responses", query="", headers=headers,
        allowed=frozenset({"session-id"}), prefixes=("x-codex-",), body={"model": "m"}, checked=["m"],
    )
    assert dict(out.headers) == {"session-id": "s-1", "x-codex-window-id": "w-1", "x-codex-turn-metadata": "{}"}


def test_agent_outgoing_repr_hides_headers(state, settings):
    """В заголовках бывает токен подписки (задача 7): repr объекта попадает в журналы исключений."""
    out, _ = build_agent_outgoing(
        state, settings, chat_id=state.chat_id, provider_id="p1", path="/v1/messages", query="",
        headers={"authorization": "Bearer secret-subscription-token"}, allowed=frozenset({"authorization"}),
        body={"model": "m"}, checked=["m"],
    )
    assert dict(out.headers)["authorization"] == "Bearer secret-subscription-token"
    assert "secret-subscription-token" not in repr(out)


def test_usage_goes_to_agent_send_as_numbers(repo, engines, clock):
    """Числа usage провайдера — в событие agent_send (по ним проверяется чтение кэша промпта, AC-5.2); message_delta
    несёт нарастающий итог, а не прирост."""
    events = [
        {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "content": [], "usage": {
            "input_tokens": 12, "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 30, "output_tokens": 1,
            "service_tier": "standard"}}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Готово"}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 7}},
        {"type": "message_stop"},
    ]
    with StubProvider([events]) as stub:
        Gateway(repo, engines, clock, stub).send(body(TASK))
    assert repo.audit_events("agent_send")[0].details["usage"] == {"input": 12, "cache_read": 1000, "cache_write": 30, "output": 7}
