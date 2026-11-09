"""Сторож выхода в сеть службы (идея «Сторож выхода в сеть во время работы службы»). Перехватчик аудита снять нельзя,
поэтому проверяется Watch напрямую: решение по событиям socket.* и отказ исключением с записью в журнал; настоящий
перехватчик — в отдельном процессе."""
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from cleaner.egress.watch import EgressRefused, Watch

PROVIDER = "api.provider.example"


class Fixture:
    def __init__(self):
        self.targets = ["10.20.0.5", PROVIDER]           # локальный шлюз адресом, подключение — именем
        self.reports = []
        self.lookups = []
        self.watch = Watch(lambda: self.targets, lambda *event: self.reports.append(event), self.resolve)

    def resolve(self, name, port, **kwargs):
        self.lookups.append(name)
        # Свой запрос сторожа проходит через его же перехватчик, как у настоящего getaddrinfo.
        self.watch.hook("socket.getaddrinfo", (name, port, 0, 0, 0))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.44", port)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::44", port, 0, 0))]

    def connect(self, host, port=443):
        self.watch.hook("socket.connect", (None, (host, port)))

    def lookup(self, host, port=443):
        self.watch.hook("socket.getaddrinfo", (host, port, 0, 0, 0))


@pytest.fixture
def guard():
    return Fixture()


def test_settings_hosts_loopback_and_local_sockets_pass(guard):
    for host in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost", "10.20.0.5"):
        guard.connect(host)
    guard.watch.hook("socket.connect", (None, "/run/cleaner.sock"))          # AF_UNIX
    guard.lookup("10.20.0.10", 5464)                                        # числовой адрес: uvicorn разбирает свой
    guard.lookup(PROVIDER)
    guard.connect("192.0.2.44")                                             # адрес разрешённого имени
    guard.connect("2001:db8::44%eth0")
    guard.watch.hook("socket.sendto", (None, ("127.0.0.53", 53)))           # DNS по петле
    assert guard.lookups == [PROVIDER] and guard.reports == []


@pytest.mark.parametrize("event, args, kind", [
    ("socket.getaddrinfo", ("huggingface.co", 443, 0, 0, 0), "name"),
    ("socket.connect", (None, ("1.1.1.1", 443)), "public"),
    ("socket.connect", (None, ("2606:4700::1111", 443, 0, 0)), "public"),
    ("socket.connect", (None, ("10.20.0.6", 30000)), "private"),
    ("socket.connect", (None, ("cdn.example", 80)), "name"),
    ("socket.sendto", (None, ("8.8.8.8", 53)), "public"),
])
def test_address_outside_the_settings_is_refused_and_logged_once(guard, event, args, kind):
    for _ in range(2):
        with pytest.raises(EgressRefused) as refused:
            guard.watch.hook(event, args)
        assert isinstance(refused.value, OSError)
    [(logged_kind, port, origin)] = guard.reports
    assert (logged_kind, port) == (kind, args[1] if event == "socket.getaddrinfo" else args[1][1])
    assert origin == __name__
    assert guard.lookups == []                                              # имя не ушло и в DNS сторожа


def test_allowed_list_follows_the_settings(guard):
    guard.lookup(PROVIDER)
    guard.targets.remove(PROVIDER)                                          # подключение выключили
    with pytest.raises(EgressRefused):
        guard.connect("192.0.2.44")
    with pytest.raises(EgressRefused):
        guard.lookup(PROVIDER)
    guard.targets.append("llm.example")
    guard.connect("llm.example")


def test_address_is_not_written_to_the_journal(guard):
    """FR-11.2: имя узла может прийти из документа — в журнал идут вид, порт и модуль, не адрес."""
    with pytest.raises(EgressRefused) as refused:
        guard.lookup("files.client-secret.example")
    assert "client-secret" not in repr(guard.reports) and "client-secret" not in str(refused.value)


_PROCESS = """
import asyncio, socket
from cleaner.egress import watch

reports = []
watch.install(watch.Watch(lambda: ["localhost"], lambda *event: reports.append(event)))
with socket.create_server(("127.0.0.1", 0)) as server:
    socket.create_connection(server.getsockname(), timeout=2).close()

    async def loop_connect():
        reader, writer = await asyncio.open_connection(*server.getsockname())
        writer.close()

    asyncio.run(loop_connect())
for call in (lambda: socket.getaddrinfo("files.example", 443), lambda: socket.create_connection(("192.0.2.1", 443), timeout=5)):
    try:
        call()
    except watch.EgressRefused:
        pass
    else:
        raise SystemExit("пропущено")
print(sorted(kind for kind, port, origin in reports))
"""


def test_audit_hook_refuses_in_a_real_process():
    """Настоящие события аудита (их аргументы, asyncio, петля): петля работает, имя и внешний адрес — отказ сразу,
    а не по истечении ожидания соединения."""
    done = subprocess.run(
        [sys.executable, "-c", _PROCESS], cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=20,
    )
    assert done.returncode == 0, done.stderr.decode(errors="replace")[-2000:]
    assert done.stdout.decode().split() == ["['name',", "'private']"]
