"""Память шлюза агентов под нагрузкой (спецификация 2026-10-28, раздел 13; план 5Г, задача 5) — только Linux.

  cd <корень доставленного дерева> && /opt/cleaner/.venv/bin/python scripts/checks/gateway_memory.py
Временный каталог данных, заглушка провайдера на петле (tests/stub_provider.py), служба шлюза без слоёв 4–5. Восемь
ключей (по числу STATE_CACHE и AGENT_WORKERS) с чатами по 20 000 сущностей: одно состояние fill_state записывается в восемь
чатов. Затем три круга по восемь параллельных запросов с телом 1 МиБ, в каждом круге — новый вывод команды в 100 000
знаков. Печать в МиБ: RSS после запуска и после заполнения (VmRSS), пик за круги (VmHWM, сброшенный перед кругами) и
разница «пик − после запуска». Данные — вымышленные (tests/gateway_load.py). Первый круг очищает тела целиком:
на workstation два круга шли около 14 минут.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

ROUNDS = 3
MIB = 1024 * 1024
TASK = "Разбери журналы входа за ночь и найди сбойные узлы"


def status(name: str) -> float:
    """Строка name из /proc/self/status — в МиБ."""
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith(f"{name}:"):
            return int(line.split()[1]) / 1024
    raise KeyError(name)


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("только Linux: память берётся из /proc/self/status")
        return 0
    from cleaner.agent_service import STATE_CACHE, AgentCall, AgentService
    from cleaner.clock import SystemClock
    from cleaner.egress import forward
    from cleaner.storage import db
    from cleaner.storage.repo import Provider, Repository
    from cleaner.web.app import AGENT_WORKERS
    from tests.gateway_load import add_result, fictional_lines, fill_state, long_body
    from tests.stub_provider import StubProvider

    started = status("VmRSS")           # модули службы загружены, данных ещё нет
    print(f"после запуска: RSS {started:.0f} МиБ; ключей {STATE_CACHE} (STATE_CACHE), потоков {AGENT_WORKERS} (AGENT_WORKERS)")
    with tempfile.TemporaryDirectory(prefix="cleaner-memory-") as data, StubProvider() as stub:
        conn = db.connect(Path(data) / "cleaner.db")
        db.migrate(conn)
        repo = Repository(conn, os.urandom(32), SystemClock())
        service = AgentService(repo, None, SystemClock())
        user_id = repo.create_user("anna", "hash", "user")
        provider_id = repo.add_provider(Provider("", "Заглушка", "anthropic", stub.url, "x-api-key", "sk-stub-01234567", ("m-1",)))
        keys = [repo.add_api_key(user_id, f"агент {n}", f"h{n}", f"{n:04d}", upstream=f"provider:{provider_id}")
                for n in range(STATE_CACHE)]
        filled = None
        for key_id in keys:
            chat_id = repo.create_chat(user_id, f"Агент {key_id[:6]}", kind="agent")
            repo.set_key_chat(key_id, chat_id)
            state, version = repo.load_state(chat_id)
            if filled is None:
                fill_state(state, repo.settings(), 20_000)
                filled = state
            repo.commit_chat(chat_id, replace(filled, chat_id=chat_id), version)
        print(f"после заполнения: RSS {status('VmRSS'):.0f} МиБ, сущностей в чате {len(filled.entities)}")
        try:
            Path("/proc/self/clear_refs").write_text("5", encoding="ascii")     # сброс VmHWM: пик — только за круги
        except OSError:
            print("VmHWM не сброшен: пик — с начала процесса")

        payload = long_body("anthropic", MIB, TASK)

        def send(key_id: str, number: int) -> None:
            request = add_result("anthropic", payload, 100 + number, fictional_lines(1_000, 10_000 + 1_000 * number)[:100_000])
            reply = service.handle(AgentCall(
                key=repo.api_key(key_id), user=repo.user(user_id), protocol="anthropic", path="/v1/messages",
                query="beta=true", headers={"anthropic-version": "2023-06-01"}, body=request,
            ))
            assert reply.status == 200 and reply.events is not None, reply.status
            assert b"message_stop" in b"".join(reply.events)

        with ThreadPoolExecutor(AGENT_WORKERS) as pool:
            for round_ in range(ROUNDS):
                begun = time.perf_counter()
                list(pool.map(send, keys, [round_ * len(keys) + n for n in range(len(keys))]))
                print(f"круг {round_ + 1} за {time.perf_counter() - begun:.0f} с: RSS {status('VmRSS'):.0f} МиБ, "
                      f"пик {status('VmHWM'):.0f} МиБ", flush=True)
        forward.close_clients()
        conn.close()
    peak = status("VmHWM")
    print(f"пик за круги: {peak:.0f} МиБ; пик − после запуска: {peak - started:.0f} МиБ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
