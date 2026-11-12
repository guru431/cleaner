"""Служба шлюза (спецификация 2026-10-28, раздел 8; удержание — 7.4; смена чата — 6.3): Claude Code по ключу подключения
Cleaner, заглушка провайдера на петле. Тела — записи настоящего агента с вымышленными контрольными значениями."""
import json
import re
import threading
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest

from cleaner import agent_service
from cleaner.agent_service import AgentCall, AgentRefused, AgentReply, AgentService
from cleaner.core.agent import ledger, walk
from cleaner.core.pipeline import system_prompt
from cleaner.core.types import ChatRule, Policy
from cleaner.core.types import EntityType as T
from cleaner.egress import cloud
from cleaner.storage.repo import Provider, StaleState
from tests.agent_bodies import agent_blocks, assistant, body, events_of, model_turn, tool_result
from tests.stub_provider import StubProvider
from tests.test_acceptance_core import CONTROL, TEXT

TASK = "Проверь узел srv-dc01.corp.contoso.ru и почту i.ivanov@contoso.ru"
HOST = re.compile(r"host-\d+\.sub-\d+\.domain-\d+\.example")
STUB_KEY = 'sk-s' 'tub-0123456789abcdef'  # secret-scan:allow -- synthetic test fixture


class Gateway:
    """Ключ шлюза к заглушке и служба шлюза над хранилищем теста."""

    def __init__(self, repo, engines, clock, stub, layers=None):
        self.repo = repo
        self.stub = stub
        self.user_id = repo.create_user("ivan", "hash", "user")
        self.provider_id = repo.add_provider(
            Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", STUB_KEY, ("m-1", "m-2")),
        )
        self.key_id = repo.add_api_key(
            self.user_id, "агент", "h1", "aaaa", upstream=f"provider:{self.provider_id}", models=("m-1",), layers=layers,
        )
        self.service = AgentService(repo, engines, clock)

    def call(self, request: dict, headers: dict | None = None, path: str = "/v1/messages") -> AgentReply:
        return self.service.handle(AgentCall(
            key=self.repo.api_key(self.key_id), user=self.repo.user(self.user_id), protocol="anthropic", path=path,
            query="beta=true", headers=headers or {"anthropic-version": "2023-06-01", "x-api-key": "ck_agent"},
            body=request,
        ))

    def send(self, request: dict, **kwargs) -> bytes:
        reply = self.call(request, **kwargs)
        assert reply.status == 200, reply.body
        return b"".join(reply.events) if reply.events is not None else reply.body

    def chat_of(self, request: dict) -> str:
        secret = ledger.conversation_secret(self.repo.global_key)
        return self.repo.conversation(ledger.conversation_id(secret, self.key_id, walk.first_user(request))).chat_id


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


@pytest.fixture
def gw(repo, engines, clock, stub) -> Gateway:
    return Gateway(repo, engines, clock, stub)


def answer(request: dict) -> list[dict]:
    """Ответ модели с заменами, которые шлюз выдал в первом сообщении: текст, рассуждение и вызов команды."""
    first = request["messages"][0]["content"][-1]["text"]
    host, mail = HOST.search(first).group(), re.search(r"<EMAIL_\d+>", first).group()
    return model_turn(f"Проверяю {host} и пишу {mail}", ("toolu_1", "Bash", {"command": f"ping {host}"}), thinking=f"узел {host}")


def two_turns(gw: Gateway, final: str = "Готово") -> tuple[dict, dict, list[dict]]:
    """Ход 1 — вызов команды; ход 2 — результат команды с контрольным текстом (TEXT). Тела и блоки ответа хода 1."""
    gw.stub.script += [answer, model_turn(final)]
    first = body(TASK)
    blocks = agent_blocks(gw.send(first))
    second = body(TASK, assistant(*blocks), tool_result("toolu_1", TEXT))
    gw.send(second)
    return first, second, blocks


def test_no_control_value_reaches_the_provider(gw):
    first, second, blocks = two_turns(gw)
    sent = gw.stub.bodies().lower()
    assert [value for value in CONTROL if value.lower() in sent] == []
    assert "i.ivanov@contoso.ru" not in sent and "srv-dc01" not in sent
    for request in gw.stub.requests:
        assert request["body"]["system"][-1] == {"type": "text", "text": system_prompt("angle")}
    assert blocks[2]["input"] == {"command": "ping srv-dc01.corp.contoso.ru"}       # агенту — настоящее имя
    assert "srv-dc01.corp.contoso.ru" in blocks[1]["text"] and "i.ivanov@contoso.ru" in blocks[1]["text"]


def test_reply_snapshot_does_not_change_with_the_next_request(state, settings):
    from cleaner.core.pipeline import sanitize

    sanitize(state, "почта one@contoso.ru", settings)
    snapshot = agent_service._snapshot(state)
    entity = next(iter(state.entities.values()))
    before = list(snapshot.entities[entity.id].forms)
    entity.forms.append("ONE@CONTOSO.RU")
    entity.parts["first"] = "Новое"
    entity.words.append("изменение")
    assert snapshot.entities[entity.id].forms == before
    assert snapshot.entities[entity.id].parts == {}
    assert snapshot.entities[entity.id].words == []


def test_finished_reply_does_not_keep_the_snapshot_alive(gw, monkeypatch):
    import weakref

    snapshots = []
    original = agent_service._snapshot

    def snapshot(state):
        copied = original(state)
        snapshots.append(weakref.ref(copied))
        return copied

    monkeypatch.setattr(agent_service, "_snapshot", snapshot)
    reply = gw.call(body(TASK))
    assert b"message_stop" in b"".join(reply.events)
    assert snapshots and all(reference() is None for reference in snapshots)
    reply.close()


def test_history_is_resent_byte_for_byte(gw, repo):
    first, second, _ = two_turns(gw)
    one, two = (request["body"] for request in gw.stub.requests)
    assert two["system"] == one["system"] and two["tools"] == one["tools"]
    assert two["messages"][0] == one["messages"][0]
    assert two["messages"][1]["content"] == one["messages"][1]["content"][0]["text"]    # окружение — строкой, как у агента
    # Правило «скрывать» после хода 2: идущий разговор повторяет записанное, новый — скрывает.
    chat = gw.chat_of(first)
    state, version = repo.load_state(chat)
    state.rules.append(ChatRule("mask", "почту", T.TERM))
    repo.commit_chat(chat, state, version)
    gw.stub.script += [model_turn("Ещё"), model_turn("Новый")]
    third = body(TASK, *second["messages"][2:4], assistant({"type": "text", "text": "Готово"}),
                 {"role": "user", "content": "дальше"})
    gw.send(third)
    assert gw.stub.requests[2]["body"]["messages"][0] == one["messages"][0]
    gw.send(body("Новая задача: проверь почту"))
    assert "почту" not in json.dumps(gw.stub.requests[3]["body"]["messages"][0], ensure_ascii=False)


def test_model_blocks_return_to_what_the_model_sent(gw):
    first, second, blocks = two_turns(gw)
    model = gw.stub.requests[1]["body"]["messages"][2]["content"]
    host = HOST.search(gw.stub.requests[0]["body"]["messages"][0]["content"][-1]["text"]).group()
    assert model[0]["thinking"] == f"узел {host}" and model[0]["signature"] == "c2lnLXN0dWI="
    assert model[1]["text"].startswith(f"Проверяю {host} и пишу <EMAIL_")
    assert model[2] == {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": f"ping {host}"}}


def test_blocked_media_and_failed_blocks_are_withheld(repo, engines, clock, stub):
    gw = Gateway(repo, engines, clock, stub, layers={"ner": True, "llm": False})
    repo.set_policy(T.PHONE, Policy.BLOCK)

    def detect(text, ctx=None):
        if "СБОЙ" in text:
            raise RuntimeError("слой 4 упал")
        return []

    engines.ner_layer.detect = detect
    image = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
    history = (
        assistant({"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"file_path": "a.png"}}),
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "снимок"}, image]},
            {"type": "text", "text": "Позвони +7 (916) 123-45-67"},
            {"type": "text", "text": "СБОЙ на этом блоке"},
        ]},
    )
    stub.script += [model_turn("Вижу пометки"), model_turn("Дальше")]
    request = body("Посмотри снимок", *history)
    gw.send(request)
    sent = stub.requests[0]["body"]["messages"][3]["content"]
    assert sent[0]["content"] == [{"type": "text", "text": "снимок"},
                                  {"type": "text", "text": ledger.placeholder(ledger.REASONS["media"])}]
    assert sent[1] == {"type": "text", "text": ledger.placeholder(ledger.REASONS["blocked"].format(type="PHONE"))}
    assert sent[2] == {"type": "text", "text": ledger.placeholder(ledger.REASONS["failed"])}
    assert "916" not in stub.bodies() and "iVBORw0KGgo" not in stub.bodies()
    repo.set_policy(T.PHONE, Policy.MASK)
    gw.send(body("Посмотри снимок", *history, assistant({"type": "text", "text": "Вижу пометки"}),
                 {"role": "user", "content": "дальше"}))
    assert stub.requests[1]["body"]["messages"][3]["content"] == sent           # те же пометки
    assert repo.audit_events("agent_withheld")[0].details["reasons"] == {"media": 1, "blocked": 1, "failed": 1}


def test_private_address_equal_to_an_issued_surrogate_is_withheld(gw, repo):
    """Подмена частного адреса берётся из того же диапазона (6.2): настоящий адрес B, совпавший с подменой адреса A, ушёл
    бы как «вставленная замена», а ответ о нём восстановился бы в A. Блок агента с таким адресом держится (7.4);
    обычный частный адрес — заменяется, как прежде."""
    task = "Проверь узел 10.1.2.5"

    def reboot(request):
        fake = re.search(r"10\.\d+\.\d+\.5", request["messages"][0]["content"][-1]["text"]).group()
        return model_turn(f"Перезагружаю {fake}", ("toolu_1", "Bash", {"command": f"ssh {fake} reboot"}))

    gw.stub.script.append(reboot)
    blocks = agent_blocks(gw.send(body(task)))
    fake = re.search(r"10\.\d+\.\d+\.5", gw.stub.requests[0]["body"]["messages"][0]["content"][-1]["text"]).group()
    assert fake != "10.1.2.5"
    assert blocks[0]["text"] == "Перезагружаю 10.1.2.5" and blocks[1]["input"] == {"command": "ssh 10.1.2.5 reboot"}
    gw.stub.script.append(model_turn(f"Узел {fake} перезагружен"))
    other = {"type": "text", "text": "соседний узел 10.7.8.9"}
    second = body(task, assistant(*blocks), {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "toolu_1", "content": f"занято: {fake} отвечает"}, other,
    ]})
    reply = gw.send(second)
    sent = gw.stub.requests[1]["body"]["messages"][3]["content"]
    assert sent[0] == {"type": "tool_result", "tool_use_id": "toolu_1",
                       "content": ledger.placeholder(ledger.REASONS["address"])}
    assert sent[1]["text"].startswith("соседний узел ") and "10.7.8.9" not in sent[1]["text"]
    assert agent_blocks(reply)[0]["text"] == "Узел 10.1.2.5 перезагружен"      # подмена A — по-прежнему в A
    assert repo.agent_receipts(gw.chat_of(second))[0]["withheld"] == {"address": 1}
    assert repo.audit_events("agent_withheld")[0].details["reasons"] == {"address": 1}


def test_withheld_tool_call_keeps_its_pair_with_the_result(gw, monkeypatch):
    """Удержанный вызов инструмента из истории остаётся вызовом с тем же id: результат инструмента ссылается на него, и
    блок text на его месте провайдер отклонил бы."""
    sanitize = agent_service.pipeline.sanitize

    def failing(state, text, *args, **kwargs):
        if "СБОЙ" in text:
            raise RuntimeError("очистка упала")
        return sanitize(state, text, *args, **kwargs)

    monkeypatch.setattr(agent_service.pipeline, "sanitize", failing)
    gw.stub.script.append(model_turn("Дальше"))
    call = {"type": "tool_use", "id": "toolu_7", "name": "Bash", "input": {"command": "echo СБОЙ"}}
    gw.send(body(TASK, assistant(call), tool_result("toolu_7", "ok")))
    sent = gw.stub.requests[0]["body"]["messages"][2]["content"]
    assert sent == [{"type": "tool_use", "id": "toolu_7", "name": "Bash",
                     "input": {"cleaner": ledger.placeholder(ledger.REASONS["failed"])}}]


def test_parallel_requests_share_replacements(gw, repo):
    gw.stub.script += [model_turn("Раз"), model_turn("Два")]
    tasks = ("Первый: узел srv-dc01.corp.contoso.ru", "Второй: узел srv-dc01.corp.contoso.ru")
    errors = []

    def run(task, agent):
        try:
            gw.send(body(task), headers={"x-claude-code-agent-id": agent})        # два субагента
        except Exception as exc:        # noqa: BLE001 — поток теста сообщает об ошибке через список
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(task, f"agent-{n}")) for n, task in enumerate(tasks)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    fakes = {HOST.search(r["body"]["messages"][0]["content"][-1]["text"]).group() for r in gw.stub.requests}
    assert len(fakes) == 1 and gw.chat_of(body(tasks[0])) == gw.chat_of(body(tasks[1]))
    state, _ = repo.load_state(gw.chat_of(body(tasks[0])))
    assert [e.restore_value for e in state.entities.values()].count("srv-dc01") == 1


def test_edit_during_request_is_retried(gw, repo, monkeypatch):
    commit = repo.commit_chat
    calls = []

    def once_stale(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise StaleState("чат изменили в интерфейсе")
        return commit(*args, **kwargs)

    monkeypatch.setattr(repo, "commit_chat", once_stale)
    gw.stub.script.append(model_turn("Готово"))
    assert events_of(gw.send(body(TASK)))[-1]["type"] == "message_stop"
    assert len(calls) == 2 and len(gw.stub.requests) == 1


def test_value_found_in_a_later_block_is_masked_in_the_earlier_ones(gw):
    """Блоки очищаются по одному: учётная запись, найденная в позднем блоке (путь профиля в описании инструмента), в раннем
    осталась бы открытой — и проверка утечек отказывала бы этому запросу при каждом повторе агента."""
    gw.stub.script.append(model_turn("Готово"))
    request = body("Запусти сборку от имени ivanov_ii")
    request["tools"][0] = dict(request["tools"][0], description=r"Читает файлы, например C:\Users\ivanov_ii\notes.txt")
    gw.send(request)
    assert "ivanov_ii" not in gw.stub.bodies()


def test_known_value_in_a_schema_format_still_refuses(gw, repo):
    """Не проверяются на утечки только имена обязательных свойств (required) и типы схемы: остальные служебные значения
    схемы (format, $ref) уходят как есть — известное значение в них по-прежнему отказ (как в 5Б)."""
    gw.stub.script.append(model_turn("Готово"))
    gw.send(body(TASK))
    request = body("Снова")
    schema = request["tools"][0]["input_schema"]
    request["tools"][0] = dict(request["tools"][0], input_schema=dict(schema, properties=dict(
        schema["properties"], host={"type": "string", "format": "srv-dc01.corp.contoso.ru"})))
    with pytest.raises(AgentRefused) as refused:
        gw.call(request)
    assert refused.value.status == 400 and len(gw.stub.requests) == 1


def test_original_in_a_tool_name_refuses_the_request(gw, repo):
    gw.stub.script.append(model_turn("Готово"))
    gw.send(body(TASK))
    request = body("Другая задача")
    request["tools"].append({"name": "srv-dc01", "description": "пинг", "input_schema": {"type": "object"}})
    with pytest.raises(AgentRefused) as refused:
        gw.call(request)
    assert (refused.value.status, refused.value.kind) == (400, "invalid_request_error")
    assert "служебном поле" in refused.value.message and refused.value.message.startswith("Cleaner:")
    assert len(gw.stub.requests) == 1
    assert repo.audit_events("agent_refused")[0].details["reason"] == "leak_structural"


def test_planted_original_is_caught_in_egress(gw, repo, monkeypatch):
    """AC-5.9: оригинал, подложенный в новый блок в обход очистки и проверки ядра, ловит egress — запрос не уходит."""
    gw.stub.script += [model_turn("Готово"), model_turn("Не дойдёт")]
    gw.send(body(TASK))
    build = agent_service.pipeline.build_agent_outgoing
    anthropic = agent_service.PROTOCOLS["anthropic"]
    monkeypatch.setitem(agent_service.PROTOCOLS, "anthropic", replace(anthropic, sanitize_unit=lambda unit, clean: unit.node))
    monkeypatch.setattr(agent_service.pipeline, "build_agent_outgoing", lambda *a, **k: (build(*a, **k)[0], []))
    with pytest.raises(AgentRefused) as refused:
        gw.call(body("Снова srv-dc01.corp.contoso.ru"))
    assert refused.value.status == 400 and len(gw.stub.requests) == 1
    assert repo.audit_events("agent_refused")[0].details["reason"] == "leak_egress"


def test_chat_rotates_by_age_and_size_but_conversations_stay(gw, repo, clock, monkeypatch):
    gw.stub.script += [model_turn(str(n)) for n in range(6)]
    old = body("Разговор A")
    gw.send(old)
    clock.advance(days=20)
    gw.send(body("Разговор A", assistant({"type": "text", "text": "0"}), {"role": "user", "content": "ещё"}))
    clock.advance(days=11)
    fresh = body("Разговор B")
    gw.send(fresh)
    assert gw.chat_of(fresh) != gw.chat_of(old)
    gw.send(body("Разговор A", assistant({"type": "text", "text": "0"}), {"role": "user", "content": "ещё раз"}))
    assert gw.chat_of(old) != gw.chat_of(fresh) and repo.chat(gw.chat_of(old)).kind == "agent"
    monkeypatch.setattr(agent_service, "AGENT_CHAT_ENTITIES", 2)
    gw.send(body("Разговор C: srv-dc01.corp.contoso.ru, i.ivanov@contoso.ru"))
    monkeypatch.setattr(agent_service, "AGENT_CHAT_ENTITIES", 20_000)
    rotated = body("Разговор D")
    gw.send(rotated)
    assert gw.chat_of(rotated) != gw.chat_of(fresh)
    assert repo.api_key(gw.key_id).chat_id == gw.chat_of(rotated)


def test_unavailable_layer_is_503_and_key_without_upstream_is_403(repo, engines, clock, stub):
    gw = Gateway(repo, engines, clock, stub, layers={"ner": False, "llm": True})
    engines.unavailable = "локальная модель недоступна"
    with pytest.raises(AgentRefused) as refused:
        gw.call(body(TASK))
    assert (refused.value.status, refused.value.kind, refused.value.headers) == (503, "overloaded_error", {"retry-after": "10"})
    plain = repo.add_api_key(gw.user_id, "скрипт", "h2", "bbbb")
    with pytest.raises(AgentRefused) as refused:
        gw.service.handle(AgentCall(repo.api_key(plain), repo.user(gw.user_id), "anthropic", "/v1/messages", "", {}, body(TASK)))
    assert (refused.value.status, refused.value.kind) == (403, "permission_error")
    request = body(TASK)
    request["model"] = "m-2"            # есть у подключения, но не разрешена ключу
    with pytest.raises(AgentRefused) as refused:
        gw.call(request)
    assert refused.value.status == 400 and stub.requests == []


def test_cut_stream_sends_error_and_keeps_ledger_clean(gw, repo):
    gw.stub.script.append(model_turn("Начинаю правку", ("toolu_9", "Edit", {"file_path": "a.txt", "old_string": "x"}), cut=True))
    events = events_of(gw.send(body(TASK)))
    assert events[-1]["type"] == "error" and events[-1]["error"]["message"].startswith("Cleaner:")
    partial = [e for e in events if e.get("delta", {}).get("type") == "input_json_delta"]
    assert len(partial) == 1 and partial[0]["delta"]["partial_json"].startswith('{"file_path"')
    chat = gw.chat_of(body(TASK))
    kinds = [json.loads(entry.local)["type"] for entry, _ in repo.ledger_page(chat, 0, 100) if entry.direction == "out"]
    assert kinds == ["text"]


def test_provider_error_comes_back_as_is(gw):
    error = {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}
    gw.stub.script.append({"status": 429, "body": error, "headers": {"retry-after": "7"}})
    reply = gw.call(body(TASK))
    assert (reply.status, reply.headers["retry-after"], json.loads(reply.body)) == (429, "7", error)


def test_opencode_go_session_is_per_conversation(gw, monkeypatch):
    """Два субагента одного ключа: у каждого разговора свой заголовок сессии, у ходов одного — один (ревью 5Г, п. 3)."""
    monkeypatch.setattr(cloud, "SESSION_HEADERS", {"127.0.0.1": "x-opencode-session"})
    agent = {"anthropic-version": "2023-06-01", "x-api-key": "ck_agent", "x-claude-code-session-id": "sess-agent-1",
             "x-opencode-session": "agent-own"}
    gw.stub.script += [answer, model_turn("Готово"), model_turn("Другое")]
    first = body(TASK)
    blocks = agent_blocks(gw.send(first, headers=agent))
    gw.send(body(TASK, assistant(*blocks), tool_result("toolu_1", TEXT)), headers=agent)
    gw.send(body("Другая задача: проверь журнал сборки"), headers=agent)
    one, two, other = (gw.stub.headers(n)["x-opencode-session"] for n in range(3))
    assert one == two != other and uuid.UUID(one).version == 4
    conv = ledger.conversation_id(ledger.conversation_secret(gw.repo.global_key), gw.key_id, walk.first_user(first))
    assert "agent-own" not in (one, other) and gw.stub.headers(0)["x-claude-code-session-id"] == "sess-agent-1" != one
    assert conv not in one and conv[:8] not in one


def test_unknown_message_field_is_cleaned(gw, monkeypatch):
    """8.3: незнакомое поле сообщения Claude Code очищается как текст и, как любой блок, повторяется из журнала."""
    fresh: list[walk.Path] = []
    new = gw.service._new

    def spy(proto, unit, *args):
        fresh.append(unit.path)
        return new(proto, unit, *args)

    monkeypatch.setattr(gw.service, "_new", spy)
    note = ("messages", 0, "note")
    gw.stub.script += [answer, model_turn("Готово")]
    first = body(TASK)
    first["messages"][0]["note"] = "узел srv-dc01.corp.contoso.ru"
    blocks = agent_blocks(gw.send(first))
    assert note in fresh
    fresh.clear()
    second = body(TASK, assistant(*blocks), tool_result("toolu_1", TEXT))
    second["messages"][0]["note"] = first["messages"][0]["note"]
    gw.send(second)
    assert note not in fresh                # ход 2 — из журнала
    one, two = (request["body"]["messages"][0] for request in gw.stub.requests)
    assert HOST.fullmatch(one["note"].removeprefix("узел ")) and "srv-dc01" not in gw.stub.bodies()
    assert two["note"] == one["note"] and one["role"] == two["role"] == "user"


def test_audit_has_no_text_or_keys(gw, repo):
    two_turns(gw)
    events = repo.audit_events(limit=1000)
    send = [e for e in events if e.event == "agent_send"]
    assert len(send) == 2 and send[-1].details["blocks_new"] > 0 and send[0].details["blocks_repeated"] > 0
    raw = json.dumps([e.details for e in events], ensure_ascii=False).lower()
    assert [value for value in (*CONTROL, STUB_KEY, "ck_agent", "проверь") if value.lower() in raw] == []


def test_agent_send_carries_gateway_and_upstream_times(gw, repo):
    """AC-5.7 на живых прогонах: время шлюза до отправки и время провайдера — в каждом agent_send, и с кодом ошибки."""
    error = {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}
    gw.stub.script += [model_turn("Готово"), {"status": 429, "body": error}]
    gw.send(body(TASK))
    assert gw.call(body("Вторая задача")).status == 429

    def timeout(*args, **kwargs):
        raise agent_service.egress.ProviderTimeout()

    gw.service.forward = timeout
    with pytest.raises(AgentRefused):
        gw.call(body("Третья задача"))
    send = repo.audit_events("agent_send")
    assert sorted(event.details["status"] for event in send) == [200, 429, 504]
    for event in send:
        times = (event.details["ms_prepare"], event.details["ms_upstream"])
        assert all(type(ms) is int and ms >= 0 for ms in times), event.details


def test_reply_restore_counters_reach_the_label_report(gw, repo):
    """Отчёт «Сохранность меток» и ответы шлюза: одно событие restore на ответ — счётчики текста модели (аргументы
    вызова не в счёт), подключение, модель запроса, вид метки, source="agent"; оборванный поток — по восстановленному;
    ответ провайдера с ошибкой события не даёт."""
    from cleaner.web.routes_settings import _label_report

    def distorted(request: dict) -> list[dict]:
        first = request["messages"][0]["content"][-1]["text"]
        host, mail = HOST.search(first).group(), re.search(r"<EMAIL_\d+>", first).group()
        return model_turn(f"Проверяю {host}, пишу {mail} и <PERSON_99>", ("toolu_1", "Bash", {"command": f"ping {host}"}))

    def cut(request: dict) -> list[dict]:
        host = HOST.search(request["messages"][0]["content"][-1]["text"]).group()
        return model_turn(f"Начинаю с {host} ", ("toolu_2", "Edit", {"file_path": "a.txt"}), cut=True)

    error = {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}
    gw.stub.script += [distorted, cut, {"status": 529, "body": error}]
    blocks = agent_blocks(gw.send(body(TASK)))
    assert blocks[-1]["input"] == {"command": "ping srv-dc01.corp.contoso.ru"} and "<PERSON_99>" in blocks[0]["text"]
    gw.send(body(TASK + " ещё раз"))
    assert gw.call(body("Третья задача")).status == 529
    events = repo.audit_events("restore")
    assert [{key: event.details[key] for key in ("restored", "altered", "unknown", "provider", "model", "label_style", "source")}
            for event in reversed(events)] == [
        {"restored": 2, "altered": 0, "unknown": 1, "provider": gw.provider_id, "model": "m-1", "label_style": "angle",
         "source": "agent"},
        {"restored": 1, "altered": 0, "unknown": 0, "provider": gw.provider_id, "model": "m-1", "label_style": "angle",
         "source": "agent"},
    ]
    [row] = _label_report(repo, None, None, "agent")
    assert (row["connection"], row["model"], row["sources"], row["answers"], row["labels"], row["unknown"]) == (
        "Заглушка", "m-1", "агенты", 2, 4, 1)
    assert _label_report(repo, None, None, "chat") == []


def test_parallel_request_waits_only_for_cleaning(gw):
    """Запрос, чья модель ещё думает, не держит чат (раздел 13): замок снимается до отправки, и второй запрос того же
    ключа и чата проходит, пока первый ждёт провайдера."""
    received, release = threading.Event(), threading.Event()

    def thinking(request):
        received.set()
        release.wait(5)
        return model_turn("Первый")

    gw.stub.script += [thinking, model_turn("Второй")]
    first: dict[str, bytes] = {}
    worker = threading.Thread(target=lambda: first.update(raw=gw.send(body(TASK))))
    worker.start()
    try:
        assert received.wait(5)
        second = gw.send(body(f"Второй: {TASK}"))
        waiting = worker.is_alive()
    finally:
        release.set()
        worker.join(5)
    assert waiting
    assert gw.chat_of(body(TASK)) == gw.chat_of(body(f"Второй: {TASK}"))
    assert events_of(first["raw"])[-1]["type"] == events_of(second)[-1]["type"] == "message_stop"
    assert "Первый" in first["raw"].decode("utf-8") and "Второй" in second.decode("utf-8")
