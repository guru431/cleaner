"""Приёмка этапа 5В на заглушке провайдера (спецификация 2026-10-28, раздел 21: AC-5.2, 5.3, 5.4, 5.5): полный путь —
маршрут шлюза → служба → заглушка на петле. Агенты — тела настоящих Codex, OpenCode и Claude Code (записи плана 5В и 5Б)
с вымышленным репозиторием; файл «читает» и «правит» тест, как это сделал бы агент."""
import json
import re

import pytest

from cleaner.agent_service import AgentService
from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.storage.repo import Provider
from cleaner.web import auth
from tests.agent_bodies import agent_blocks, assistant, body, events_of, model_turn, tool_result
from tests.stub_provider import StubProvider
from tests.test_acceptance_core import CONTROL, TEXT
from tests.test_agent_chat import call_chunks, chunk, opencode
from tests.test_agent_responses import call_events, completed, message, recorded as codex_recorded, text_events

NOTES = TEXT + "Почта для отчётов: I.Ivanov@Contoso.RU\n"      # почта — и в другом регистре (раздел 11)
HOST = re.compile(r"host-\d+\.sub-\d+\.domain-\d+\.example")
FAKES = re.compile(r"<[A-Z_]+_\d+>|\b(?:host|sub|domain)-\d+\b|\.example\b")
TASK = "Прочитай notes.txt, отметь основную почту и проверь контроллер домена"
OAUTH = 'sk-a' 'nt-oat01-acceptance-0123456789'  # secret-scan:allow -- synthetic test fixture
CHATGPT = "eyJhbGciOi.acceptance-chatgpt.0123456789"


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


def demo(recorded: dict) -> dict:
    """Запись с каталогом вымышленного репозитория «demo-repo»: «contoso-repo» записи совпало бы с контрольным
    значением «contoso» (как в tests/agent_bodies.py)."""
    return json.loads(json.dumps(recorded, ensure_ascii=False).replace("contoso-repo", "demo-repo"))


def leaked(stub: StubProvider) -> list[str]:
    sent = stub.bodies().lower()
    return [value for value in (*CONTROL, "I.Ivanov@Contoso.RU") if value.lower() in sent]


def apply_patch(text: str, patch: str) -> str:
    """Патч apply_patch простым применением строк «-»/«+»: удаляемые строки должны найтись в файле посимвольно."""
    lines = [line for line in patch.splitlines() if not line.startswith(("***", "@@"))]
    old = "\n".join(line[1:] for line in lines if line.startswith("-"))
    new = "\n".join(line[1:] for line in lines if line.startswith("+"))
    assert old and old in text, old
    return text.replace(old, new)


@pytest.fixture
def keys(browser, app, repo, stub):
    """Администратор с ключами: подключения Responses и Chat Completions к заглушке, обе подписки (адреса — заглушка)."""
    user_id = repo.create_user("anna", auth.hash_password("пароль-для-тестов"), "admin")
    out = {}
    for protocol in ("responses", "openai"):
        provider_id = repo.add_provider(Provider("", f"Заглушка {protocol}", protocol, f"{stub.url}/v1", "bearer",
                                                 "sk-stub-01234567", ("m-1",)))
        out[protocol] = (upstream := f"provider:{provider_id}")
    out |= {"claude-subscription": "claude-subscription", "chatgpt-subscription": "chatgpt-subscription"}
    issued = {}
    for name, upstream in out.items():
        key = auth.new_api_key()
        repo.add_api_key(user_id, name, auth.token_hash(key), key[-4:], upstream=upstream)
        issued[name] = key
    app.state.agent = AgentService(repo, app.state.engines, app.state.clock, subscription_urls={
        "claude-subscription": stub.url, "chatgpt-subscription": f"{stub.url}/backend-api/codex"})
    issued["client"] = browser().client
    return issued


# --- Codex: Responses -------------------------------------------------------------------------------

def last_output(request: dict) -> str:
    """Вывод последнего инструмента так, как его увидела модель."""
    for item in reversed(request["input"]):
        if isinstance(item, dict) and item.get("type", "").endswith("_output"):
            output = item["output"]
            return output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
    raise AssertionError("в запросе нет вывода инструмента")


def codex_model() -> list:
    def turn(*items: dict) -> list[dict]:
        events = []
        for index, item in enumerate(items):
            events += text_events(index, item, []) if item["type"] == "message" else call_events(index, item)
        return events + [completed(*items)]

    def read(request):
        return turn(message("msg_1", "Читаю файл."), {"type": "function_call", "id": "fc_1", "call_id": "call_1",
                    "name": "exec_command", "arguments": json.dumps({"cmd": "Get-Content -Encoding UTF8 notes.txt"})})

    def patch(request):
        line = next(line for line in last_output(request).splitlines() if line.startswith("Почта для отчётов"))
        text = f"*** Begin Patch\n*** Update File: notes.txt\n@@\n-{line}\n+{line} (основная)\n*** End Patch\n"
        return turn({"type": "custom_tool_call", "id": "ctc_2", "call_id": "call_2", "name": "apply_patch", "input": text})

    def command(request):
        host = HOST.search(json.dumps(request["input"], ensure_ascii=False)).group()
        return turn({"type": "function_call", "id": "fc_3", "call_id": "call_3", "name": "exec_command",
                     "arguments": json.dumps({"cmd": f"ping -n 1 {host}"})})

    return [read, patch, command, turn(message("msg_4", "Готово"))]


class Codex:
    """Codex глазами шлюза: тело из записи, история — элементы output_item.done, как их хранит Codex."""

    def __init__(self, client, headers: dict):
        self.client, self.headers = client, headers
        self.base = demo(codex_recorded("turn1"))
        self.base["model"] = "m-1"
        self.base["input"][3]["content"][0]["text"] = TASK
        self.history: list[dict] = []

    def turn(self, *items: dict) -> list[dict]:
        self.history += items
        request = dict(self.base, input=[*self.base["input"], *self.history])
        response = self.client.post("/agent/openai/v1/responses", content=json.dumps(request, ensure_ascii=False).encode(),
                                    headers={"content-type": "application/json", **self.headers})
        assert response.status_code == 200, response.text
        events = events_of(response.content)
        assert events[-1]["type"] == "response.completed"
        done = [event["item"] for event in events if event["type"] == "response.output_item.done"]
        self.history += done
        return done


def output(call_id: str, text: str, custom: bool = False) -> dict:
    wrapped = f"Chunk ID: 1a2b3c\nWall time: 0.1 seconds\nProcess exited with code 0\nOutput:\n{text}"
    return {"type": "custom_tool_call_output" if custom else "function_call_output", "call_id": call_id, "output": wrapped}


def run_codex(agent: Codex, stub: StubProvider) -> None:
    stub.script += codex_model()
    read = agent.turn()[-1]
    assert json.loads(read["arguments"]) == {"cmd": "Get-Content -Encoding UTF8 notes.txt"}
    patch = agent.turn(output("call_1", NOTES))[-1]["input"]
    edited = apply_patch(NOTES, patch)                          # строки патча — посимвольно, как в файле
    assert edited.endswith("Почта для отчётов: I.Ivanov@Contoso.RU (основная)\n") and not FAKES.search(edited)
    ping = agent.turn(output("call_2", "Success. Updated the following files:\nM notes.txt\n", custom=True))[-1]
    assert json.loads(ping["arguments"]) == {"cmd": "ping -n 1 srv-dc01.corp.contoso.ru"}
    final = agent.turn(output("call_3", "Reply from 10.1.2.5: bytes=32"))[-1]
    assert final["content"][0]["text"] == "Готово"
    assert len(stub.requests) == 4 and leaked(stub) == []


def codex_headers(key: str) -> dict:
    return {**json.loads((codex_recorded.__globals__["FIXTURES"] / "headers.json").read_text(encoding="utf-8"))["turn1"]["headers"],
            "x-cleaner-key": key}


def test_ac_5_3_codex_by_key_patch_and_command_carry_real_values(keys, stub):
    run_codex(Codex(keys["client"], codex_headers(keys["responses"])), stub)
    assert all(request["path"] == "/v1/responses" for request in stub.requests)


def test_ac_5_3_codex_by_subscription(keys, stub):
    headers = dict(codex_headers(keys["chatgpt-subscription"]), authorization=f"Bearer {CHATGPT}",
                   **{"chatgpt-account-id": "00000000-0000-4000-8000-000000000002"})
    run_codex(Codex(keys["client"], headers), stub)
    assert all(request["path"] == "/backend-api/codex/responses" for request in stub.requests)
    assert {stub.headers(n)["authorization"] for n in range(4)} == {f"Bearer {CHATGPT}"}


# --- OpenCode: Chat Completions ----------------------------------------------------------------------

class OpenCode:
    """OpenCode глазами шлюза: тело из записи; вызовы — из частей потока, аргументы AI SDK пишет заново."""

    def __init__(self, client, key: str):
        self.client, self.key = client, key
        self.history: list[dict] = [{"role": "user", "content": TASK}]

    def turn(self, *messages: dict) -> dict:
        self.history += messages
        response = self.client.post("/agent/openai/v1/chat/completions",
                                    content=json.dumps(demo(opencode(*self.history)), ensure_ascii=False).encode(),
                                    headers={"content-type": "application/json", "authorization": f"Bearer {self.key}"})
        assert response.status_code == 200, response.text
        assert response.text.endswith("data: [DONE]\n\n")
        text, calls = "", {}
        for line in response.text.split("\n\n"):
            if not line.startswith("data: {"):
                continue
            for choice in json.loads(line[6:]).get("choices") or ():
                text += choice["delta"].get("content") or ""
                for part in choice["delta"].get("tool_calls") or ():
                    call = calls.setdefault(part["index"], {"id": "", "name": "", "arguments": ""})
                    call["id"] = part.get("id") or call["id"]
                    call["name"] = (part.get("function") or {}).get("name") or call["name"]
                    call["arguments"] += (part.get("function") or {}).get("arguments") or ""
        reply = {"role": "assistant", "content": text, "tool_calls": [
            {"id": c["id"], "type": "function", "function": {
                "name": c["name"], "arguments": json.dumps(json.loads(c["arguments"]), ensure_ascii=False, separators=(",", ":"))}}
            for c in calls.values()]}
        self.history.append(reply)
        return reply


def test_ac_5_4_opencode_by_chat_completions(keys, stub):
    def call(call_id: str, name: str, arguments: dict) -> list[dict]:
        return [chunk({"role": "assistant", "content": "Делаю"}), *call_chunks(0, call_id, name, json.dumps(arguments, ensure_ascii=False)),
                chunk({}, "tool_calls")]

    def edit(request):
        seen = next(m["content"] for m in reversed(request["messages"]) if m["role"] == "tool")
        line = next(re.sub(r"^\d+: ", "", line) for line in seen.splitlines() if "Почта для отчётов" in line)
        return call("call_2", "edit", {"filePath": "notes.txt", "oldString": line, "newString": f"{line} (основная)"})

    def bash(request):
        host = HOST.search(json.dumps(request["messages"], ensure_ascii=False)).group()
        return call("call_3", "bash", {"command": f"ping -c 1 {host}", "description": "Проверка узла"})

    stub.script += [call("call_1", "read", {"filePath": "notes.txt"}), edit, bash,
                    [chunk({"role": "assistant", "content": "Готово"}), chunk({}, "stop")]]
    agent = OpenCode(keys["client"], keys["openai"])
    read = agent.turn()["tool_calls"][0]
    numbered = "\n".join(f"{n}: {line}" for n, line in enumerate(NOTES.splitlines(), 1))
    change = json.loads(agent.turn({"role": "tool", "tool_call_id": read["id"], "content": numbered})["tool_calls"][0]["function"]["arguments"])
    assert change["oldString"] == "Почта для отчётов: I.Ivanov@Contoso.RU" and change["oldString"] in NOTES
    edited = NOTES.replace(change["oldString"], change["newString"])
    assert edited.endswith("(основная)\n") and not FAKES.search(edited)
    ping = agent.turn({"role": "tool", "tool_call_id": "call_2", "content": "Edit applied successfully."})["tool_calls"][0]
    assert json.loads(ping["function"]["arguments"])["command"] == "ping -c 1 srv-dc01.corp.contoso.ru"
    assert agent.turn({"role": "tool", "tool_call_id": "call_3", "content": "1 packets transmitted"})["content"] == "Готово"
    assert len(stub.requests) == 4 and leaked(stub) == []


# --- Claude Code по подписке --------------------------------------------------------------------------

def test_ac_5_2_claude_subscription_history_is_resent_byte_for_byte(keys, stub, repo):
    """Три хода с рассуждением и подписью через claude-subscription: прежняя история уходит провайдеру побайтно той же,
    рассуждение — как его прислала модель (иначе Anthropic отказал бы по подписи)."""
    stub.script += [
        model_turn("Читаю файл", ("toolu_1", "Read", {"file_path": "notes.txt"}), thinking="план: прочитать файл"),
        lambda request: model_turn("Проверяю узел", ("toolu_2", "Bash", {"command": "ping -c 1 " + HOST.search(
            json.dumps(request["messages"], ensure_ascii=False)).group()}), thinking="узел из файла"),
        model_turn("Готово", thinking="всё сделано"),
    ]
    headers = {"x-cleaner-key": keys["claude-subscription"], "authorization": f"Bearer {OAUTH}", "content-type": "application/json",
               "anthropic-version": "2023-06-01", "anthropic-beta": "claude-code-20250219,oauth-2025-04-20"}
    history: list[dict] = []
    client = keys["client"]

    def turn(*results: dict) -> list[dict]:
        history.extend(results)
        response = client.post("/agent/anthropic/v1/messages?beta=true", content=json.dumps(body(TASK, *history)).encode(),
                               headers=headers)
        assert response.status_code == 200, response.text
        blocks = agent_blocks(response.content)
        history.append(assistant(*blocks))
        return blocks

    read = turn()[-1]
    ping = turn(tool_result(read["id"], NOTES))[-1]
    assert ping["input"] == {"command": "ping -c 1 srv-dc01.corp.contoso.ru"}
    turn(tool_result(ping["id"], "1 packets transmitted"))
    one, two, three = (request["body"] for request in stub.requests)
    assert json.dumps(two["system"]) == json.dumps(one["system"]) == json.dumps(three["system"])
    assert json.dumps(two["tools"]) == json.dumps(three["tools"])
    # Ходы 2 и 3: окружение, ответ модели хода 1 и результат чтения — те же байты.
    assert json.dumps(three["messages"][:4], ensure_ascii=False) == json.dumps(two["messages"][:4], ensure_ascii=False)
    thinking = three["messages"][2]["content"][0]
    assert (thinking["thinking"], thinking["signature"]) == ("план: прочитать файл", "c2lnLXN0dWI=")
    assert three["messages"][4]["content"][0]["thinking"] == "узел из файла"
    assert {stub.headers(n)["authorization"] for n in range(3)} == {f"Bearer {OAUTH}"}
    assert repo.audit_events("agent_refused") == [] and leaked(stub) == []


# --- AC-5.5 в протоколах OpenAI ----------------------------------------------------------------------

SCREENSHOT = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="


def withheld_in_chat(keys, stub) -> None:
    stub.script += [[chunk({"content": "Вижу пометки"}), chunk({}, "stop")], [chunk({"content": "Дальше"}), chunk({}, "stop")]]
    chat = OpenCode(keys["client"], keys["openai"])
    chat.history.append({"role": "assistant", "content": "", "tool_calls": [
        {"id": "call_1", "type": "function", "function": {"name": "read", "arguments": '{"filePath":"notes.txt"}'}}]})
    chat.turn({"role": "tool", "tool_call_id": "call_1", "content": NOTES},
              {"role": "user", "content": [{"type": "text", "text": "И снимок"}, {"type": "image_url", "image_url": {"url": SCREENSHOT}}]})
    chat.turn({"role": "user", "content": "Что дальше?"})
    first, second = (request["body"]["messages"] for request in stub.requests)
    assert json.dumps(first[3], ensure_ascii=False) == json.dumps(second[3], ensure_ascii=False)     # пометка повторяется


def withheld_in_responses(keys, stub) -> None:
    stub.script += [[*text_events(0, message("msg_1", "Вижу пометки"), []), completed(message("msg_1", "Вижу пометки"))],
                    [*text_events(0, message("msg_2", "Дальше"), []), completed(message("msg_2", "Дальше"))]]
    codex = Codex(keys["client"], codex_headers(keys["responses"]))
    codex.history += [{"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "exec_command", "arguments": "{}"},
                      {"type": "function_call", "id": "fc_2", "call_id": "call_2", "name": "view_image", "arguments": "{}"}]
    codex.turn(output("call_1", NOTES), {"type": "function_call_output", "call_id": "call_2", "output": [
        {"type": "input_image", "image_url": SCREENSHOT}]})
    codex.turn({"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Что дальше?"}]})


@pytest.mark.parametrize("protocol", [withheld_in_chat, withheld_in_responses], ids=["chat", "responses"])
def test_ac_5_5_withheld_blocks_in_both_openai_protocols(keys, stub, repo, protocol):
    """Значение типа с политикой «блокировать» в выводе инструмента и снимок экрана уходят пометками; разговор идёт
    дальше, пометки повторяются дословно."""
    repo.set_policy(T.PHONE, Policy.BLOCK)
    protocol(keys, stub)
    sent = stub.bodies()
    assert "+7 (916) 123-45-67" not in sent and "iVBORw0KGgo" not in sent
    assert sent.count("[Cleaner: блок не передан — содержит значение типа PHONE]") == 2
    assert sent.count("[Cleaner: блок не передан — изображение или файл не передаётся]") == 2
    assert len(stub.requests) == 2
