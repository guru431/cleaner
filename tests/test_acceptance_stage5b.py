"""Приёмка этапа 5Б на заглушке провайдера (спецификация 2026-10-28, раздел 21: AC-5.1, 5.5, 5.6, 5.9, 5.10): полный путь —
маршрут шлюза → служба → заглушка на петле. Агент — тела настоящего Claude Code с вымышленным репозиторием; файл
«читает» и «правит» тест, как это сделал бы агент."""
import json
import re
import threading
from dataclasses import replace

import pytest

from cleaner import agent_service
from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.storage.repo import Provider
from cleaner.web import auth
from tests.agent_bodies import agent_blocks, assistant, body, events_of, model_turn, tool_result
from tests.stub_provider import StubProvider
from tests.test_acceptance_core import CONTROL, TEXT

PATH = r"C:\work\demo\notes.txt"
NOTES = TEXT + "Почта для отчётов: I.Ivanov@Contoso.RU\n"      # почта — и в другом регистре (раздел 11)
HOST = re.compile(r"host-\d+\.sub-\d+\.domain-\d+\.example")
FAKES = re.compile(r"<[A-Z_]+_\d+>|\b(?:host|sub|domain)-\d+\b|\.example\b")


@pytest.fixture
def stub():
    with StubProvider() as provider:
        yield provider


class Agent:
    """Claude Code глазами шлюза: ключ шлюза, история разговора, запрос и разбор потока."""

    def __init__(self, client, key: str, task: str, agent_id: str = ""):
        self.client, self.key, self.task, self.agent_id = client, key, task, agent_id
        self.history: list[dict] = []

    def turn(self, *results: dict) -> list[dict]:
        """Ход: прежняя история и новые сообщения; блоки ответа модели — в историю. Возвращает блоки ответа."""
        self.history += results
        headers = {"x-api-key": self.key, "content-type": "application/json", "anthropic-version": "2023-06-01"}
        if self.agent_id:
            headers["x-claude-code-agent-id"] = self.agent_id
        response = self.client.post("/agent/anthropic/v1/messages?beta=true", content=json.dumps(body(self.task, *self.history)).encode(),
                                    headers=headers)
        assert response.status_code == 200, response.text
        assert events_of(response.content)[-1]["type"] == "message_stop"
        blocks = agent_blocks(response.content)
        self.history.append(assistant(*blocks))
        return blocks


@pytest.fixture
def gateway(browser, repo, stub):
    """Пользователь, подключение к заглушке и ключ шлюза; фабрика агентов с этим ключом."""
    user_id = repo.create_user("anna", auth.hash_password("пароль-для-тестов"), "user")
    provider_id = repo.add_provider(Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", "sk-stub-01234567", ("m-1",)))
    key = auth.new_api_key()
    key_id = repo.add_api_key(user_id, "агент", auth.token_hash(key), key[-4:], upstream=f"provider:{provider_id}")

    def make(task: str, agent_id: str = "") -> Agent:
        agent = Agent(browser().client, key, task, agent_id)
        agent.key_id = key_id
        return agent

    return make


def seen_result(request: dict) -> str:
    """Содержимое последнего результата инструмента так, как его увидела модель."""
    for message in reversed(request["messages"]):
        if message["role"] == "user" and isinstance(message["content"], list):
            for block in message["content"]:
                if block.get("type") == "tool_result":
                    return block["content"] if isinstance(block["content"], str) else json.dumps(block["content"], ensure_ascii=False)
    raise AssertionError("в запросе нет результата инструмента")


def leaked(stub: StubProvider) -> list[str]:
    sent = stub.bodies().lower()
    return [value for value in (*CONTROL, "I.Ivanov@Contoso.RU") if value.lower() in sent]


def test_ac_5_1_control_values_never_reach_the_provider_over_three_turns(gateway, stub):
    def edit(request: dict) -> list[dict]:
        line = next(line for line in seen_result(request).splitlines() if line.startswith("Почта для отчётов"))
        return model_turn("Правлю", ("toolu_2", "Edit", {"file_path": PATH, "old_string": line, "new_string": f"{line} (основная)"}))

    def command(request: dict) -> list[dict]:
        host = HOST.search(json.dumps(request["messages"], ensure_ascii=False)).group()        # из прочитанного файла
        return model_turn("Проверяю узел", ("toolu_3", "Bash", {"command": f"ping -c 1 {host}"}))

    stub.script += [
        model_turn("Читаю файл", ("toolu_1", "Read", {"file_path": PATH})), edit, command, model_turn("Готово"),
    ]
    agent = gateway("Прочитай notes.txt, отметь основную почту и проверь контроллер домена")
    read = agent.turn()[-1]
    assert read["input"] == {"file_path": PATH}
    change = agent.turn(tool_result(read["id"], NOTES))[-1]["input"]
    assert change["old_string"] == "Почта для отчётов: I.Ivanov@Contoso.RU"          # посимвольно, как в файле
    assert change["old_string"] in NOTES
    edited = NOTES.replace(change["old_string"], change["new_string"])
    assert edited.endswith("Почта для отчётов: I.Ivanov@Contoso.RU (основная)\n") and not FAKES.search(edited)
    ping = agent.turn(tool_result("toolu_2", "Файл изменён"))[-1]["input"]
    assert ping == {"command": "ping -c 1 srv-dc01.corp.contoso.ru"}
    assert agent.turn(tool_result("toolu_3", "1 packets transmitted, 1 received"))[-1]["text"] == "Готово"
    assert len(stub.requests) == 4 and leaked(stub) == []


def test_ac_5_5_blocked_value_and_screenshot_go_as_placeholders(gateway, stub, repo):
    repo.set_policy(T.PHONE, Policy.BLOCK)
    stub.script += [
        model_turn("Читаю", ("toolu_1", "Read", {"file_path": PATH})),
        model_turn("Смотрю снимок", ("toolu_2", "Read", {"file_path": "screen.png"})),
        model_turn("Вижу пометки"), model_turn("Продолжаю"),
    ]
    agent = gateway("Прочитай notes.txt и снимок экрана")
    agent.turn()
    agent.turn(tool_result("toolu_1", NOTES))
    screenshot = [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgoAAAANSUhEUg=="}}]
    agent.turn(tool_result("toolu_2", screenshot))
    agent.turn({"role": "user", "content": "Что дальше?"})
    sent = stub.bodies()
    assert "+7 (916) 123-45-67" not in sent and "iVBORw0KGgo" not in sent
    assert "[Cleaner: блок не передан — содержит значение типа PHONE]" in sent
    assert "[Cleaner: блок не передан — изображение или файл не передаётся]" in sent
    last = stub.requests[-1]["body"]["messages"]
    assert json.dumps(stub.requests[2]["body"]["messages"][3], ensure_ascii=False) == json.dumps(last[3], ensure_ascii=False)


def test_ac_5_6_two_subagents_share_replacements(gateway, stub, repo):
    stub.script += [model_turn("Раз"), model_turn("Два")]
    agents = [gateway(f"Субагент {n}: проверь srv-dc01.corp.contoso.ru и i.ivanov@contoso.ru", f"agent-{n}") for n in (1, 2)]
    errors: list[BaseException] = []

    def run(agent: Agent) -> None:
        try:
            agent.turn()
        except BaseException as exc:            # noqa: BLE001 — ошибку потока теста — в основной поток
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(agent,)) for agent in agents]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    sent = [request["body"]["messages"][0]["content"][-1]["text"] for request in stub.requests]
    assert len({HOST.search(text).group() for text in sent}) == 1
    assert len({re.search(r"<EMAIL_\d+>", text).group() for text in sent}) == 1
    assert {request["headers"].get("x-claude-code-agent-id") for request in stub.requests} == {"agent-1", "agent-2"}
    assert leaked(stub) == []


def test_ac_5_9_planted_original_never_leaves(gateway, stub, monkeypatch):
    stub.script += [model_turn("Раз"), model_turn("Не дойдёт")]
    agent = gateway("Проверь srv-dc01.corp.contoso.ru")
    agent.turn()
    build = agent_service.pipeline.build_agent_outgoing
    anthropic = agent_service.PROTOCOLS["anthropic"]
    monkeypatch.setitem(agent_service.PROTOCOLS, "anthropic", replace(anthropic, sanitize_unit=lambda unit, clean: unit.node))
    monkeypatch.setattr(agent_service.pipeline, "build_agent_outgoing", lambda *a, **k: (build(*a, **k)[0], []))
    response = agent.client.post("/agent/anthropic/v1/messages", content=json.dumps(body("Снова srv-dc01.corp.contoso.ru")).encode(),
                                 headers={"x-api-key": agent.key, "content-type": "application/json"})
    assert response.status_code == 400 and response.json()["error"]["type"] == "invalid_request_error"
    assert "srv-dc01" not in response.text and len(stub.requests) == 1


def test_ac_5_10_rule_applies_to_the_next_request_not_to_frozen_blocks(gateway, stub, repo, browser):
    stub.script += [model_turn("Раз"), model_turn("Два")]
    agent = gateway("Позвони +7 (916) 123-45-67")
    agent.turn()
    chat = repo.api_key(agent.key_id).chat_id
    anna = browser()
    anna.login("anna")
    page = anna.get(f"/chats/{chat}").text
    assert "Журнал отправленного" in page and "+7 (916) 123-45-67" in page
    state, _ = repo.load_state(chat)
    [phone] = [e for e in state.entities.values() if e.type is T.PHONE]
    response = anna.post(f"/chats/{chat}/entities/{phone.id}/unmask")
    assert response.status_code == 303, response.text
    agent.turn({"role": "user", "content": "И ещё раз: +7 (916) 123-45-67"})
    first, second = (request["body"]["messages"] for request in stub.requests)
    assert second[0] == first[0] and "+7 (916) 123-45-67" not in json.dumps(second[0], ensure_ascii=False)
    assert second[-2]["content"] == "И ещё раз: +7 (916) 123-45-67"          # новый блок — по новому правилу
    assert "в 0 блоках" in anna.get(f"/chats/{chat}").text                    # открытое значение — не утечка
