"""SEC-2 covers every new outgoing channel; session ownership and receipts survive process restarts.

Only invented control strings and an in-process HTTP transport are used.
"""
import hashlib
import json
from dataclasses import replace
from functools import partial
from urllib.parse import quote

import httpx
import pytest

from cleaner import agent_service
from cleaner.agent_service import AgentCall, AgentRefused, AgentService
from cleaner.core.agent.protocol import PROTOCOLS
from cleaner.core.agent.stream import DeltaRestorer
from cleaner.core.agent import stream as streams
from cleaner.core.agent import ledger
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import RestoreLimit, originals
from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.egress import forward as egress
from cleaner.storage.repo import Provider

EMAIL = "audit.person@contoso.ru"
MARKER = "AuditMarker"


@pytest.fixture
def gateway(repo, clock):
    sent = []

    def receive(request):
        sent.append(request)
        if request.url.path.endswith("/messages"):
            reply = {"content": [{"type": "text", "text": "Готово"}]}
        elif request.url.path.endswith("/responses"):
            reply = {"output": [{"type": "message", "content": [{"type": "output_text", "text": "Готово"}]}]}
        else:
            reply = {"choices": [{"message": {"role": "assistant", "content": "Готово"}}]}
        return httpx.Response(200, json=reply)

    user_id = repo.create_user("boundary", "hash", "user")
    forward = partial(egress.forward, transport=httpx.MockTransport(receive))
    service = AgentService(repo, None, clock, forward=forward)

    def call(protocol="chat", text=EMAIL, headers=None, query="", **extra):
        proto = PROTOCOLS[protocol]
        provider_id = repo.add_provider(Provider("", "Stub", proto.provider_protocol, "http://127.0.0.1", "bearer", "stub-only", ("m",)))
        key_id = repo.add_api_key(user_id, "boundaries", "hash-" + provider_id, "aaaa", "provider:" + provider_id, ("m",))
        body = {"model": "m", "stream": False, "input" if protocol == "responses" else "messages": [{"role": "user", "content": text}], **extra}
        path = {"anthropic": "/v1/messages", "chat": "/chat/completions", "responses": "/responses"}[protocol]
        return service, AgentCall(repo.api_key(key_id), repo.user(user_id), protocol, path, query, headers or {}, body)

    return call, sent


@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize("where", ["metadata", "unknown", "top_level", "parameter"])
def test_known_original_in_object_key_never_reaches_provider(gateway, repo, protocol, where):
    make, sent = gateway
    key = {"metadata": "metadata", "unknown": "extra", "parameter": "tool_choice"}.get(where)
    extra = {EMAIL: "approved"} if where == "top_level" else {key: {EMAIL: "approved"}}
    service, call = make(protocol, **extra)
    with pytest.raises(AgentRefused) as refused:
        service.handle(call)
    assert refused.value.status == 400 and sent == []
    chat_id = repo.api_key(call.key.id).chat_id
    receipt = repo.agent_receipts(chat_id)[0]
    assert receipt["status"] == 400 and receipt["reason"]


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_schema_property_names_remain_protocol_names(gateway, protocol):
    make, sent = gateway
    schema = {"type": "object", "properties": {EMAIL: {"type": "string"}}, "required": [EMAIL]}
    tool = {"name": "inspect", "description": "Проверить", "input_schema": schema} if protocol == "anthropic" else {
        "type": "function", "function": {"name": "inspect", "description": "Проверить", "parameters": schema},
    }
    if protocol == "responses":
        tool = {"type": "function", **tool["function"]}
    service, call = make(protocol, tools=[tool])
    assert service.handle(call).status == 200
    assert EMAIL in json.loads(sent[0].content)["tools"][0].__str__()


FRESH = "olga.smirnova@fabrikam.ru"       # новое значение: до запроса чат его не знает


def _extra_fields(protocol: str, value: str) -> tuple[dict, list[str]]:
    """Тело с лишними ключами внутри text, tool_use и tool_result и результатом-объектом; формы для квитанции."""
    if protocol == "anthropic":
        return {"messages": [
            {"role": "user", "content": [{"type": "text", "text": "Проверь", "note": value}]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "run", "input": {}, "note": value}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": {"found": value}, "note": value}]},
        ]}, ["messages[].content[].content type=tool_result", "messages[].content[].note type=text",
             "messages[].content[].note type=tool_result", "messages[].content[].note type=tool_use"]
    if protocol == "chat":
        call = {"id": "call_1", "type": "function", "note": value, "function": {"name": "run", "arguments": "{}", "note": value}}
        return {"messages": [
            {"role": "user", "content": [{"type": "text", "text": "Проверь", "note": value}]},
            {"role": "assistant", "content": None, "tool_calls": [call]},
            {"role": "tool", "tool_call_id": "call_1", "content": {"found": value}, "note": value},
        ]}, ["messages[].content", "messages[].content[].note type=text", "messages[].note",
             "messages[].tool_calls[].function.note type=function", "messages[].tool_calls[].note type=function"]
    return {"input": [
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Проверь", "note": value}]},
        {"type": "function_call", "call_id": "call_1", "name": "run", "arguments": "{}", "note": value},
        {"type": "function_call_output", "call_id": "call_1", "output": "ok", "note": value},
    ]}, ["input[].content[].note type=input_text", "input[].note type=function_call", "input[].note type=function_call_output"]


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_extra_fields_inside_known_blocks_are_cleaned_and_shown(gateway, repo, protocol):
    """8.3, риск 7: строка под лишним ключом блока text, tool_use, tool_result и результат-объект очищаются как текст,
    а не уходят как есть; служебные id не меняются; квитанция показывает такие поля."""
    make, sent = gateway
    extra, shapes = _extra_fields(protocol, FRESH)
    service, call = make(protocol, **extra)
    assert service.handle(call).status == 200
    wire = sent[0].content.decode()
    assert FRESH not in wire and wire.count("call_1" if protocol != "anthropic" else "toolu_1") == 2
    receipt = repo.agent_receipts(repo.api_key(call.key.id).chat_id)[0]
    assert receipt["unfamiliar"] == shapes


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_blocked_value_under_an_extra_key_is_withheld_whole(gateway, repo, protocol):
    """Значение типа с «блокировать» под лишним ключом удерживает блок (7.4), и пометка не несёт лишних ключей: иначе
    оригинал ушёл бы в пометке, а проверка утечек отказывала бы запросу на каждом ходе."""
    repo.set_policy(T.PHONE, Policy.BLOCK)
    make, sent = gateway
    extra, _ = _extra_fields(protocol, "+7 (916) 123-45-67")
    service, call = make(protocol, **extra)
    assert service.handle(call).status == 200
    wire = json.dumps(json.loads(sent[0].content), ensure_ascii=False)
    assert "123-45-67" not in wire and "содержит значение типа PHONE" in wire


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_forwarded_header_is_checked_again_at_egress(gateway, repo, monkeypatch, protocol):
    make, sent = gateway
    proto = PROTOCOLS[protocol]
    service, call = make(protocol, headers={proto.session_header: EMAIL})
    build = agent_service.pipeline.build_agent_outgoing
    monkeypatch.setattr(agent_service.pipeline, "build_agent_outgoing", lambda *a, **kw: (build(*a, **kw)[0], []))
    with pytest.raises(AgentRefused) as refused:
        service.handle(call)
    assert refused.value.status == 400 and sent == []
    assert repo.audit_events("agent_refused")[0].details["reason"] == "leak_egress"


@pytest.mark.parametrize("query", ["user=" + EMAIL, "user=" + quote(EMAIL, safe=""), "beta=true&user=" + EMAIL])
def test_unknown_decoded_query_is_refused(gateway, query):
    make, sent = gateway
    service, call = make("anthropic", query=query)
    with pytest.raises(AgentRefused) as refused:
        service.handle(call)
    assert refused.value.status == 400 and refused.value.reason == "query" and sent == []


def test_known_beta_switch_is_canonicalized(gateway):
    make, sent = gateway
    service, call = make("anthropic", query="%62eta=%74rue")
    assert service.handle(call).status == 200
    assert sent[0].url.query == b"beta=true"


@pytest.mark.parametrize("repeated", [False, True])
def test_cache_control_cannot_add_data_to_a_new_or_frozen_block(gateway, repeated):
    make, sent = gateway
    service, call = make("anthropic")
    block = {"type": "text", "text": EMAIL, "cache_control": {"type": "ephemeral"}}
    call = replace(call, body={**call.body, "messages": [{"role": "user", "content": [block]}]})
    if repeated:
        service.handle(call)
        sent.clear()
    block["cache_control"]["audit_note"] = EMAIL
    with pytest.raises(AgentRefused) as refused:
        service.handle(call)
    assert refused.value.status == 400 and sent == []


@pytest.mark.parametrize("protocol,extra", [
    ("anthropic", {"system": [{"type": "text", "text": "x-anthropic-billing-header: " + EMAIL}]}),
    ("anthropic", {"messages": [{"role": "user", "content": [
        {"type": "text", "text": EMAIL}, {"type": "thinking", "thinking": EMAIL},
    ]}]}),
    ("responses", {"input": [{"role": "user", "content": EMAIL}, {"type": "reasoning", "encrypted_content": EMAIL}]}),
])
def test_unverified_opaque_data_cannot_bypass_sec2(gateway, protocol, extra):
    make, sent = gateway
    service, call = make(protocol, **extra)
    with pytest.raises(AgentRefused) as refused:
        service.handle(call)
    assert refused.value.status == 400 and sent == []


def test_provider_model_removal_revokes_existing_agent_key(gateway, repo):
    make, sent = gateway
    service, call = make()
    provider = repo.provider(call.key.upstream.removeprefix("provider:"))
    repo.update_provider(replace(provider, models=("another-model",)), None)
    with pytest.raises(AgentRefused) as refused:
        service.handle(call)
    assert refused.value.status == 400 and sent == []


def test_signed_provider_reasoning_keeps_its_provenance_but_an_edit_does_not(gateway):
    make, sent = gateway
    service, call = make("anthropic")
    reasoning = {"type": "thinking", "thinking": EMAIL, "signature": "provider-signature"}

    def receive(request):
        sent.append(request)
        return httpx.Response(200, json={"content": [reasoning]})

    service.forward = partial(egress.forward, transport=httpx.MockTransport(receive))
    service.handle(call)
    history = {"role": "assistant", "content": [reasoning]}
    second = replace(call, body={**call.body, "messages": [*call.body["messages"], history]})
    service.handle(second)
    assert json.loads(sent[-1].content)["messages"][-1]["content"] == [reasoning]
    edited = {**reasoning, "thinking": EMAIL + " new"}
    second = replace(second, body={**second.body, "messages": [*call.body["messages"], {"role": "assistant", "content": [edited]}]})
    with pytest.raises(AgentRefused):
        service.handle(second)
    assert len(sent) == 2


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_independent_sessions_share_no_frozen_blocks_and_resume_keeps_its_own(gateway, repo, protocol):
    make, sent = gateway
    header = PROTOCOLS[protocol].session_header
    service, call = make(protocol, text=MARKER, headers={header: "session-a"})
    service.handle(call)
    repo.add_dictionary("always", MARKER, T.TERM)
    service.handle(replace(call, headers={header: "session-b"}))
    service.handle(call)
    assert MARKER in sent[0].content.decode() and MARKER not in sent[1].content.decode() and MARKER in sent[2].content.decode()
    assert len(repo.chat_conversations(repo.api_key(call.key.id).chat_id)) == 2


def test_subagents_have_separate_frozen_histories(gateway, repo):
    make, sent = gateway
    headers = {"x-claude-code-session-id": "shared-session", "x-claude-code-agent-id": "worker-a"}
    service, call = make("anthropic", text=MARKER, headers=headers)
    service.handle(call)
    repo.add_dictionary("always", MARKER, T.TERM)
    service.handle(replace(call, headers={**headers, "x-claude-code-agent-id": "worker-b"}))
    assert MARKER not in sent[1].content.decode()


def test_upgrade_resumes_matching_legacy_session_without_adopting_a_different_session(gateway, repo):
    make, sent = gateway
    service, call = make(text=MARKER)
    service.handle(call)
    first = PROTOCOLS[call.protocol].first_user(call.body)
    legacy_id = ledger.conversation_id(ledger.conversation_secret(repo.global_key), call.key.id, first)
    repo.touch_conversation(legacy_id, "old-session")
    repo.add_dictionary("always", MARKER, T.TERM)
    service.handle(replace(call, headers={"x-session-affinity": "old-session"}))
    service.handle(replace(call, headers={"x-session-affinity": "different-session"}))
    assert MARKER in sent[1].content.decode() and MARKER not in sent[2].content.decode()


def test_new_subagent_cannot_adopt_a_legacy_parent_session(gateway, repo):
    make, sent = gateway
    service, call = make("anthropic", text=MARKER)
    service.handle(call)
    first = PROTOCOLS[call.protocol].first_user(call.body)
    legacy_id = ledger.conversation_id(ledger.conversation_secret(repo.global_key), call.key.id, first)
    repo.touch_conversation(legacy_id, "shared-session")
    repo.add_dictionary("always", MARKER, T.TERM)
    service.handle(replace(call, headers={"x-claude-code-session-id": "shared-session", "x-claude-code-agent-id": "new-worker"}))
    assert MARKER not in sent[1].content.decode()


def test_frozen_user_object_keys_keep_the_existing_exception(gateway, repo):
    make, sent = gateway
    service, call = make(text="Задача", **{MARKER: {MARKER: "approved"}})
    service.handle(call)
    repo.add_dictionary("always", MARKER, T.TERM)
    service.handle(call)
    assert json.loads(sent[1].content)[MARKER] == {MARKER: "approved"}


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_protocol_field_names_do_not_collide_with_known_account_name(gateway, repo, protocol):
    make, sent = gateway
    repo.add_dictionary("always", "name", T.ACCOUNT)
    arguments = {"path": "safe.txt"}
    if protocol == "anthropic":
        call_node = {"type": "tool_use", "id": "t", "name": "inspect", "input": arguments}
        extra = {"tool_choice": {"type": "tool", "name": "inspect"}}
    elif protocol == "chat":
        call_node = {"type": "function", "id": "t", "function": {"name": "inspect", "arguments": json.dumps(arguments)}}
        extra = {"tool_choice": {"type": "function", "function": {"name": "inspect"}}}
    else:
        call_node = {"type": "function_call", "id": "t", "call_id": "t", "name": "inspect", "arguments": json.dumps(arguments)}
        extra = {"tool_choice": {"type": "function", "name": "inspect"}}
    service, call = make(protocol, text="Задача", **extra)
    if protocol == "responses":
        body = {**call.body, "input": [*call.body["input"], call_node]}
    else:
        assistant = {"role": "assistant", "content": [call_node]} if protocol == "anthropic" else {"role": "assistant", "content": "", "tool_calls": [call_node]}
        body = {**call.body, "messages": [*call.body["messages"], assistant]}
    assert service.handle(replace(call, body=body)).status == 200
    assert len(sent) == 1


def test_reset_without_session_id_is_persistent_and_explicit_id_starts_another(gateway, repo, clock):
    make, sent = gateway
    service, call = make(text=MARKER)
    service.handle(call)
    old_chat = repo.api_key(call.key.id).chat_id
    repo.add_dictionary("always", MARKER, T.TERM)
    repo.restart_key_chat(call.key.id)
    service = AgentService(repo, None, clock, forward=service.forward)
    service.handle(call)       # A stale ApiKey snapshot cannot bypass the persisted epoch.
    new_chat = repo.api_key(call.key.id).chat_id
    service.handle(replace(call, headers={"x-cleaner-conversation-id": "new-run"}))
    assert old_chat != new_chat and MARKER not in sent[1].content.decode()
    assert len(repo.chat_conversations(new_chat)) == 2


def test_receipts_link_reused_blocks_and_store_no_credentials(gateway, repo):
    make, sent = gateway
    service, call = make(headers={"x-session-affinity": "session-a", "authorization": "Bearer invented-client-secret"})
    service.handle(call)
    service.handle(call)
    chat_id = repo.api_key(call.key.id).chat_id
    receipts = repo.agent_receipts(chat_id)
    assert receipts[0]["new"] == 0 and receipts[0]["repeated"] == 1
    assert receipts[0]["blocks"][0]["digest"] == receipts[1]["blocks"][0]["digest"]
    text = json.dumps(receipts)
    assert "invented-client-secret" not in text and "stub-only" not in text and EMAIL not in text
    raw = repo.conn.execute("SELECT content_enc FROM agent_receipts").fetchone()[0]
    assert b'"protocol"' not in raw and b'"layers"' not in raw
    foreign = repo.create_chat(call.user.id, "other", kind="agent")
    assert repo.agent_receipt(foreign, receipts[0]["id"]) is None


def test_receipts_are_compressed_and_old_ones_still_read(gateway, repo):
    """10.4: квитанция с отпечатками всей истории сжимается перед шифрованием; квитанции до сжатия читаются как прежде."""
    make, _ = gateway
    service, call = make()
    service.handle(call)
    chat_id = repo.api_key(call.key.id).chat_id
    receipt = repo.agent_receipts(chat_id)[0]
    content = {key: value for key, value in receipt.items() if key not in ("id", "conversation", "time")}
    blocks = [{"direction": "in", "digest": hashlib.sha256(b"%d" % n).hexdigest(), "kind": "text", "status": "повторён"}
              for n in range(1000)]
    big = repo.add_agent_receipt(chat_id, receipt["conversation"], dict(content, blocks=blocks))
    raw = repo.conn.execute("SELECT content_enc FROM agent_receipts WHERE id = ?", (big,)).fetchone()[0]
    assert len(raw) * 3 < len(json.dumps(dict(content, blocks=blocks), ensure_ascii=False).encode())      # замер: 3,8 раза
    assert repo.agent_receipt(chat_id, big)["blocks"] == blocks
    old = json.dumps(content, ensure_ascii=False)              # запись до 12.11.2026: JSON без сжатия
    repo.conn.execute(
        "INSERT INTO agent_receipts(id, conversation, created_at, content_enc) VALUES (?, ?, ?, ?)",
        ("old", receipt["conversation"], receipt["time"], repo._enc(repo._dek(chat_id), old, "agent_receipts.content:old")),
    )
    assert repo.agent_receipt(chat_id, "old") == dict(content, id="old", conversation=receipt["conversation"], time=receipt["time"])
    assert {r["id"] for r in repo.agent_receipts(chat_id)} == {receipt["id"], big, "old"}


@pytest.mark.parametrize("spaces", [255, 256, 257, 300, 1024])
@pytest.mark.parametrize("size", [1, 17, 4096])
def test_stream_restoration_keeps_long_unfinished_label(state, settings, spaces, size):
    sanitize(state, EMAIL, settings)
    text = "до < EMAIL" + " " * spaces + "_1 > после "
    restorer = DeltaRestorer(state, settings)
    restored = "".join(restorer.feed(text[i:i + size]) for i in range(0, len(text), size)) + restorer.finish()
    assert restored == originals(state, settings)(text)
    assert restorer.text == ""


def test_restorer_discards_already_emitted_megabyte(state, settings):
    restorer = DeltaRestorer(state, settings)
    chunk = "safe text " * 1000
    for _ in range(100):
        assert restorer.feed(chunk) == chunk
        assert restorer.text == ""


@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize("argument", [False, True])
def test_expanded_text_and_exact_hidden_tool_arguments_share_a_bounded_budget(state, settings, monkeypatch, protocol, argument):
    monkeypatch.setattr(streams, "RESTORED_BYTES", 128)
    monkeypatch.setattr(streams, "ARGUMENT_BYTES", 64)
    sanitize(state, "password=InventedPassword123" if argument else EMAIL, settings)
    entity = next(entity for entity in state.entities.values() if entity.type is (T.SECRET if argument else T.EMAIL))
    entity.restore_value = "expanded-" * 50
    label = "<SECRET_1>" if argument else "<EMAIL_1>"
    value = json.dumps({"value": label})
    if protocol == "anthropic":
        body = {"content": [{"type": "tool_use", "id": "t", "name": "inspect", "input": {"value": label}} if argument else {"type": "text", "text": label}]}
    elif protocol == "chat":
        body = {"choices": [{"message": {"tool_calls": [{"id": "t", "type": "function", "function": {"name": "inspect", "arguments": value}}]} if argument else {"content": label}}]}
    else:
        body = {"output": [{"type": "function_call", "id": "t", "name": "inspect", "arguments": value} if argument else {"type": "message", "content": [{"type": "output_text", "text": label}]}]}
    stream = PROTOCOLS[protocol].stream(state, settings)
    with pytest.raises(RestoreLimit):
        stream.complete(body)
    assert stream.pairs == []


def test_tiny_response_labels_cannot_expand_past_total_remaining_budget(state, settings, monkeypatch):
    monkeypatch.setattr(streams, "RESTORED_BYTES", 40)
    sanitize(state, EMAIL, settings)
    budget = streams.RestorationBudget()
    restore = budget.original(state, settings)
    assert restore("<EMAIL_1>") == EMAIL
    with pytest.raises(RestoreLimit):
        restore("<EMAIL_1>")


def test_limit_during_final_stream_event_is_an_error_and_has_a_receipt(gateway, repo, monkeypatch):
    make, sent = gateway
    service, call = make("responses")
    monkeypatch.setattr(streams, "RESTORED_BYTES", 4)
    event = {"type": "response.completed", "response": {"output": [{"type": "message", "content": [{"type": "output_text", "text": "<EMAIL_1>"}]}]}}

    def forward(out, connection, state, settings, **kwargs):
        return egress.forward(out, connection, state, settings, **kwargs, transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"data: " + json.dumps(event).encode() + b"\n\n")))

    service.forward = forward
    reply = service.handle(replace(call, body={**call.body, "stream": True}))
    output = b"".join(reply.events)
    assert b'"type":"error"' in output
    receipt = repo.agent_receipts(repo.api_key(call.key.id).chat_id)[0]
    assert receipt["status"] == 502 and receipt["reason"] == "response_limit"


@pytest.mark.parametrize(("protocol", "events"), [
    ("responses", b'data: {"type":"response.failed","response":{"error":{"message":"failure"}}}\n\n'),
    ("chat", b'data: {"error":{"message":"failure"}}\n\ndata: [DONE]\n\n'),
])
def test_provider_stream_failure_marks_receipt_and_audit(gateway, repo, protocol, events):
    make, _ = gateway
    service, call = make(protocol)

    def forward(out, connection, state, settings, **kwargs):
        return egress.forward(out, connection, state, settings, **kwargs, transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=events)))

    service.forward = forward
    reply = service.handle(replace(call, body={**call.body, "stream": True}))
    assert b"failure" in b"".join(reply.events)
    [receipt] = repo.agent_receipts(repo.api_key(call.key.id).chat_id)
    assert (receipt["status"], receipt["reason"]) == (502, "provider_stream_error")
    [event] = repo.audit_events("agent_send")
    assert event.details["status"] == 502 and event.details["finished"] is False
    assert event.details["reason"] == "provider_stream_error"


@pytest.mark.parametrize("limit", ["event", "response"])
def test_sse_limits_apply_before_an_unterminated_line_is_buffered(state, settings, monkeypatch, limit):
    monkeypatch.setattr(egress, "EVENT_BYTES", 50 if limit == "event" else 1000)
    monkeypatch.setattr(egress, "RESPONSE_BYTES", 50 if limit == "response" else 1000)

    class InfiniteLine(httpx.SyncByteStream):
        def __iter__(self):
            yield b"data: " + b"x" * 30
            yield b"x" * 30

    from cleaner.core.pipeline import build_agent_outgoing
    from cleaner.egress.cloud import Connection
    out, _ = build_agent_outgoing(state, settings, chat_id=state.chat_id, provider_id="p", path="/responses", query="",
                                 headers={}, allowed=frozenset(), body={}, checked=[])
    upstream = egress.forward(out, Connection("responses", "http://127.0.0.1", "bearer", "", 0), state, settings,
                              transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=InfiniteLine())))
    try:
        with pytest.raises(egress.ProviderLimit):
            list(upstream.lines())
    finally:
        upstream.close()
