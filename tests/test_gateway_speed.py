"""Скорость шлюза агентов (спецификация 2026-10-28, раздел 13; AC-5.7): полный путь — маршрут шлюза (TestClient) →
служба → заглушка провайдера на петле, слои 1–3.

Добавка — p95 сорока запросов через шлюз (после двух прогревочных) минус медиана сорока прямых запросов httpx к
заглушке с телом, которое она получила от шлюза: у p95 из двадцати исход решало одно значение (аудит 09.11.2026). Пороги —
раздел 13: 0,3 с на запросе из повторённых блоков с телом 1 МиБ, в том числе на чате с 20 000 сущностей; 3 с на
100 000 знаков нового содержимого (NFR-4). Только integration: первый запрос очищает 1 МиБ (около 15 с), пороги в
секундах краснеют от нагрузки машины.

Абсолютный порог не видит, как тает запас: каждая добавка сравнивается и с прошлым замером на этой же машине
(`data/gateway-speed.json`, вне Git; кэш pytest не годится — его отключают через PYTEST_ADDOPTS). Рост больше чем в
полтора раза и больше чем на 50 мс — отказ с обоими числами, а выросшее значение точкой отсчёта не становится; после
осознанного изменения файл удаляют (аудит 09.11.2026: добавка выросла на 54 % за пять дней).

  pytest tests/test_gateway_speed.py -m integration -rP      # строки «gateway-speed …» — в выводе прошедших тестов
"""
import json
import math
import statistics
import time
from pathlib import Path

import httpx
import pytest

from cleaner.agent_service import AgentCall, AgentService
from cleaner.storage.repo import Provider
from cleaner.web import auth
from tests.agent_bodies import body, events_of, model_turn
from tests.gateway_load import add_result, fictional_lines, fill_state, long_body
from tests.stub_provider import StubProvider

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]     # предел 30 с из pytest.ini — не для замеров

MIB = 1024 * 1024
ADDED = 0.3                     # с, p95 добавки на повторённых блоках
NFR_4 = 3.0                     # с на 100 000 знаков нового содержимого
FIRST_TEXT = 0.6                # с до первой дельты текста: добавка и одно слово
WARMUP, COUNT = 2, 40
GROWTH, GROWTH_ABS = 1.5, 0.05  # рост к прошлому замеру на этой машине: во сколько раз и на сколько секунд
HISTORY = Path(__file__).resolve().parents[1] / "data" / "gateway-speed.json"
TASK = "Разбери журналы входа за ночь и найди сбойные узлы"
PATHS = {"anthropic": "/agent/anthropic/v1/messages?beta=true", "responses": "/agent/openai/v1/responses"}
ENDS = {"anthropic": "message_stop", "responses": "response.completed"}


@pytest.fixture
def stub():
    with StubProvider() as provider:        # без сценария — короткий поток
        yield provider


@pytest.fixture
def keys(browser, app, repo, stub):
    """Ключи к подключениям Anthropic и Responses на заглушке: протокол → (ключ, id ключа); client — клиент маршрутов."""
    user_id = repo.create_user("anna", auth.hash_password("пароль-для-тестов"), "admin")
    out = {}
    for protocol, url, style in (("anthropic", stub.url, "x-api-key"), ("responses", f"{stub.url}/v1", "bearer")):
        provider_id = repo.add_provider(Provider("", f"Заглушка {protocol}", protocol, url, style, "sk-stub-01234567", ("m-1",)))
        key = auth.new_api_key()
        out[protocol] = key, repo.add_api_key(user_id, protocol, auth.token_hash(key), key[-4:], upstream=f"provider:{provider_id}")
    app.state.agent = AgentService(repo, app.state.engines, app.state.clock)
    out["client"] = browser().client
    return out


def _raw(request: dict) -> bytes:
    return json.dumps(request, ensure_ascii=False).encode("utf-8")


def through_gateway(keys, protocol: str, requests: list[dict]) -> list[float]:
    """Время каждого запроса через маршрут шлюза до конца потока; тело кодируется до замера, как его прислал бы агент."""
    key, _ = keys[protocol]
    headers = {"content-type": "application/json"} | (
        {"x-api-key": key, "anthropic-version": "2023-06-01"} if protocol == "anthropic" else {"authorization": f"Bearer {key}"})
    times = []
    for request in requests:
        raw = _raw(request)
        started = time.perf_counter()
        response = keys["client"].post(PATHS[protocol], content=raw, headers=headers)
        times.append(time.perf_counter() - started)
        assert response.status_code == 200, response.text[:500]
        assert events_of(response.content)[-1]["type"] == ENDS[protocol]
    return times


def direct(stub: StubProvider) -> float:
    """Медиана COUNT прямых запросов к заглушке с телом, которое она получила от шлюза последним. Один httpx.Client на все:
    шлюз тоже держит соединения с провайдером в пуле (egress.forward, задача 3 плана 5Г)."""
    last = stub.requests[-1]
    raw = _raw(last["body"])
    times = []
    with httpx.Client(base_url=stub.url, trust_env=False) as client:
        for _ in range(COUNT):
            started = time.perf_counter()
            response = client.post(last["path"], content=raw, headers={"content-type": "application/json"})
            times.append(time.perf_counter() - started)
            assert response.status_code == 200
    return statistics.median(times)


def report(request, times: list[float], base: float, by_median: bool = False) -> float:
    """Добавка: p95 (или медиана) времени через шлюз минус прямое время; строка «gateway-speed …» — в вывод теста.
    Сравнение с прошлым замером этого теста на этой машине — до проверки абсолютного порога."""
    name = request.node.name
    p50, p95 = statistics.median(times), sorted(times)[math.ceil(0.95 * len(times)) - 1]
    added = (p50 if by_median else p95) - base
    history = json.loads(HISTORY.read_text(encoding="utf-8")) if HISTORY.exists() else {}
    previous = history.get(name)
    change = f" previous={previous:.3f} ({(added / previous - 1) * 100:+.0f} %)" if previous else ""
    print(f"gateway-speed {name}: p50={p50:.3f} p95={p95:.3f} direct={base:.3f} added={added:.3f}{change}")
    if previous:            # выросшая добавка не становится новой точкой отсчёта сама собой
        assert not (added > previous * GROWTH and added - previous > GROWTH_ABS), (
            f"добавка выросла с {previous:.3f} до {added:.3f} с к прошлому замеру на этой машине")
    HISTORY.parent.mkdir(exist_ok=True)
    HISTORY.write_text(json.dumps(history | {name: round(added, 4)}, indent=1), encoding="utf-8")
    return added


def last_send(repo) -> dict:
    return repo.audit_events("agent_send", limit=1)[0].details


@pytest.mark.parametrize("protocol", ["anthropic", "responses"])
def test_repeated_1_mib_body_adds_at_most_300_ms(keys, stub, repo, request, protocol):
    payload = long_body(protocol, MIB, TASK)
    through_gateway(keys, protocol, [payload])          # первый запрос: тело очищается и ложится в журнал
    times = through_gateway(keys, protocol, [payload] * (WARMUP + COUNT))[WARMUP:]
    assert last_send(repo)["blocks_new"] == 0
    assert report(request, times, direct(stub)) <= ADDED


def test_next_turn_with_a_small_new_block_adds_at_most_300_ms(keys, stub, repo, request):
    payload = long_body("anthropic", MIB, TASK)
    through_gateway(keys, "anthropic", [payload])
    turns = [add_result("anthropic", payload, 100 + n, fictional_lines(3, 5_000 + 3 * n)[:200]) for n in range(WARMUP + COUNT)]
    times = through_gateway(keys, "anthropic", turns)[WARMUP:]
    assert last_send(repo)["blocks_new"] == 2                 # вызов команды и её вывод
    assert report(request, times, direct(stub)) <= ADDED


def test_repeated_body_on_a_chat_of_20000_entities_adds_at_most_300_ms(keys, stub, repo, request):
    payload = long_body("anthropic", MIB, TASK)
    through_gateway(keys, "anthropic", [payload] * (1 + WARMUP))
    # Чат дополняется до 20 000 сущностей после прогрева: версия меняется, первый замеряемый запрос читает состояние из базы.
    chat_id = repo.api_key(keys["anthropic"][1]).chat_id
    state, version = repo.load_state(chat_id)
    fill_state(state, repo.settings(), 20_000)
    repo.commit_chat(chat_id, state, version)
    times = through_gateway(keys, "anthropic", [payload] * COUNT)
    assert last_send(repo)["blocks_new"] == 0 and len(repo.load_state(chat_id)[0].entities) >= 20_000
    assert report(request, times, direct(stub)) <= ADDED


def test_new_100k_chars_are_cleaned_within_nfr_4(keys, stub, repo, request):
    payload = long_body("anthropic", MIB, TASK)
    through_gateway(keys, "anthropic", [payload])
    texts = [fictional_lines(1_000, start)[:100_000] for start in (10_000, 20_000, 30_000)]
    assert {len(text) for text in texts} == {100_000}
    times = through_gateway(keys, "anthropic", [add_result("anthropic", payload, 200 + n, text) for n, text in enumerate(texts)])
    assert last_send(repo)["blocks_new"] == 2
    assert report(request, times, direct(stub), by_median=True) <= NFR_4


def test_first_text_reaches_the_agent_before_the_model_goes_on(repo, engines, clock, stub, request):
    """Уровень службы (как Gateway в tests/test_agent_service.py), чат с 20 000 сущностей, состояние — из базы: первая
    дельта текста приходит агенту раньше FIRST_TEXT, пока модель ещё думает над остатком."""
    user_id = repo.create_user("ivan", "hash", "user")
    provider_id = repo.add_provider(Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", "sk-stub-01234567", ("m-1",)))
    key_id = repo.add_api_key(user_id, "агент", "h1", "aaaa", upstream=f"provider:{provider_id}")
    service = AgentService(repo, engines, clock)

    def call(request_body: dict):
        return service.handle(AgentCall(
            key=repo.api_key(key_id), user=repo.user(user_id), protocol="anthropic", path="/v1/messages", query="beta=true",
            headers={"anthropic-version": "2023-06-01", "x-api-key": "ck_agent"}, body=request_body,
        ))

    task = body(TASK)
    b"".join(call(task).events)                         # разговор и журнал; заглушка без сценария
    chat_id = repo.api_key(key_id).chat_id
    state, version = repo.load_state(chat_id)
    fill_state(state, repo.settings(), 20_000)
    repo.commit_chat(chat_id, state, version)
    turn = model_turn("Проверяю узел и журнал")
    delta = turn[2]
    thinking = [*turn[:2], {**delta, "delta": {"type": "text_delta", "text": "Проверяю узел "}}, {"pause": 1.0},
                {**delta, "delta": {"type": "text_delta", "text": "и журнал"}}, *turn[-3:]]
    stub.script += [thinking, thinking]

    def first_text(events) -> tuple[float, float]:
        started, first = time.perf_counter(), None
        for chunk in events():
            if first is None and b"text_delta" in chunk:
                first = time.perf_counter() - started
        return first, time.perf_counter() - started

    first, total = first_text(lambda: call(task).events)
    raw = _raw(stub.requests[-1]["body"])
    with httpx.Client(base_url=stub.url, trust_env=False) as client:
        def upstream():
            with client.stream("POST", "/v1/messages", content=raw, headers={"content-type": "application/json"}) as response:
                yield from response.iter_raw()

        base, _ = first_text(upstream)
    print(f"gateway-speed {request.node.name}: p50={first:.3f} p95={first:.3f} direct={base:.3f} added={first - base:.3f}"
          f" total={total:.3f}")
    assert total >= 1.0 and first < FIRST_TEXT
