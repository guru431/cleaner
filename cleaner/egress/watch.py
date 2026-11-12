"""Сторож выхода в сеть процесса службы (SEC-1, NFR-2). Тест импортов видит только код пакета, а библиотеки моделей
и документов (transformers, huggingface_hub, docling) умеют ходить в сеть сами; учётной записи cleaner экран открывает
любой IPv4:443. Сторож — перехватчик событий аудита Python (sys.addaudithook): ставится только командой serve и
снять его нельзя, поэтому в тестах проверяется сам Watch, а не процесс с ним.

Разрешены петля, сокеты AF_UNIX и узлы из настроек: локальный шлюз, настроенные подключения (и выключенные: их
проверку администратор запускает явно), подписки ключей шлюза. Список берётся из настроек при каждой проверке,
поэтому правка настроек действует сразу.

- socket.getaddrinfo: имя, которого нет в списке, — отказ до запроса DNS: само имя тоже уходит наружу, серверу DNS.
  Числовой адрес разрешается без сети (так uvicorn разбирает адрес, который слушает) — его проверит connect.
  Для разрешённого имени сторож сам узнаёт его адреса: событие аудита не видит ответа getaddrinfo, а соединение идёт
  уже по адресу (у httpx с asyncio — и из другого потока). Ответ самому вызывающему запоминает обёртка
  socket.getaddrinfo (Watch.wrap): при балансировке DNS он отличается от ответа сторожу.
- socket.gethostbyname (и gethostbyname_ex — событие у них одно): как getaddrinfo. Имя разрешается в коде C мимо
  обёртки, поэтому его адреса сторож узнаёт своим запросом.
- socket.connect и socket.sendto: петля (и IPv4 в IPv6), адрес из списка или адрес разрешённого имени; иначе отказ.
- socket.gethostbyaddr и socket.getnameinfo: обратный запрос DNS отдаёт адрес серверу DNS, а адрес может прийти из
  документа, — проверка та же, что у connect: петля, адрес из списка или адрес разрешённого имени. Имя в gethostbyaddr
  сначала разрешается — как имя в connect: из списка или отказ. Флагов getnameinfo событие не видит, поэтому и
  числовой ответ без сети (NI_NUMERICHOST) для адреса не из списка — отказ: так служба адреса не разбирает.

Отказ — исключение EgressRefused (OSError: клиенты считают его ошибкой соединения) и событие журнала egress_refused,
одно на вид, порт и модуль-источник. Адрес назначения в журнал не пишется: имя узла может прийти из документа
(ссылка на внешнее изображение в DOCX или HTML, которую попробует загрузить разборщик), а журнал не шифруется и
оригиналов содержать не должен (FR-11.2). Модуль, откуда шёл вызов, и порт — код, а не данные пользователя.
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import threading
from collections.abc import Callable, Iterable

_LOOKUPS = frozenset({"socket.getaddrinfo", "socket.gethostbyname"})        # аргументы: имя, (порт, …)
_EVENTS = _LOOKUPS | {"socket.connect", "socket.sendto", "socket.gethostbyaddr", "socket.getnameinfo"}
# Модули, через которые идёт соединение: источник — первый модуль вне их.
_PLUMBING = (
    "socket", "ssl", "selectors", "asyncio", "concurrent", "threading", "anyio", "httpx", "httpcore", "h11", "h2",
    "urllib", "urllib3", "requests", "http", "cleaner.egress.watch",
)
_KEEP_ADDRESSES = 64                 # адресов одного имени: у сетей доставки их бывает много, но не бесконечно
_KEEP_REPORTS = 256                  # разных отказов в журнал за жизнь процесса


class EgressRefused(ConnectionError):
    """Сторож службы не пустил соединение: адреса нет среди разрешённых."""


def _name(host: object) -> str:
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    return str(host or "").strip().rstrip(".").lower()


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])           # IPv6 с зоной: fe80::1%eth0
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _kind(address: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> str:
    if address is None:
        return "name"
    return "private" if address.is_private else "public"


def _destination(event: str, args: tuple) -> object:
    """Назначение события с адресом: кортеж (узел, порт, …) у connect, sendto и getnameinfo, (узел,) у gethostbyaddr;
    у connect AF_UNIX — путь к файлу сокета."""
    if event == "socket.gethostbyaddr":
        return (args[0],)
    return args[0] if event == "socket.getnameinfo" else args[1]


def _origin() -> str:
    frame = sys._getframe(1)
    while frame is not None:
        module = str(frame.f_globals.get("__name__", ""))
        if module and not any(module == part or module.startswith(part + ".") for part in _PLUMBING):
            return module
        frame = frame.f_back
    return "?"


class Watch:
    """targets — узлы из настроек (имена и адреса), report(kind, port, origin) — запись отказа в журнал,
    resolve — getaddrinfo для адресов разрешённых имён."""

    def __init__(
        self, targets: Callable[[], Iterable[str]], report: Callable[[str, object, str], None],
        resolve: Callable[..., list] = socket.getaddrinfo,
    ):
        self._targets = targets
        self._report = report
        self._resolve = resolve
        self._resolved: dict[str, dict[str, None]] = {}      # имя → адреса в порядке получения (старые — первыми)
        self._reported: set[tuple[str, object, str]] = set()
        self._lock = threading.Lock()
        self._inside = threading.local()

    def _hosts(self) -> frozenset[str]:
        return frozenset(name for name in map(_name, self._targets()) if name)

    def _learn(self, name: str, port: object) -> None:
        """Адреса разрешённого имени. Свой getaddrinfo проходит сторожа (то же имя), но без повторного запроса."""
        if getattr(self._inside, "active", False):
            return
        self._inside.active = True
        try:
            found = {str(_ip(str(info[4][0]))) for info in self._resolve(name, port or 443, proto=socket.IPPROTO_TCP)}
        except OSError:
            return              # имя не разрешилось — не разрешится и у вызывающего, он получит свою ошибку
        finally:
            self._inside.active = False
        self._remember(name, found)

    def _remember(self, name: str, found: set[str]) -> None:
        """Сверх предела вытесняются самые старые адреса, а не все: иначе ответ соседнему потоку стёр бы адрес, к
        которому этот поток соединяется сразу после своего getaddrinfo."""
        with self._lock:
            known = self._resolved.setdefault(name, {})
            for address in found:
                known.pop(address, None)
                known[address] = None
            for address in list(known)[:max(0, len(known) - _KEEP_ADDRESSES)]:
                del known[address]

    def wrap(self, getaddrinfo: Callable[..., list]) -> Callable[..., list]:
        """socket.getaddrinfo, который запоминает и ответ вызывающему. Балансировка DNS отдаёт на каждый запрос свой
        набор адресов пула, и ответ на запрос сторожа (_learn) может не содержать адреса, к которому пойдёт соединение.
        Обхода это не открывает: getaddrinfo сам вызывает событие аудита, и неразрешённое имя получает отказ до
        запроса — запоминаются только адреса из ответа для имени из настроек, как и у _learn, в любом потоке."""
        def guarded(host, port, *args, **kwargs):
            infos = getaddrinfo(host, port, *args, **kwargs)
            name = _name(host)
            if name and name != "localhost" and _ip(name) is None:
                self._remember(name, {str(_ip(str(info[4][0]))) for info in infos})
            return infos

        return guarded

    def decide(self, event: str, args: tuple) -> str | None:
        """None — можно; иначе вид назначения для журнала: name, private или public."""
        if event in _LOOKUPS:
            name = _name(args[0])
            if not name or name == "localhost" or _ip(name) is not None:
                return None
            if name not in self._hosts():
                return "name"
            self._learn(name, args[1] if len(args) > 1 else None)
            return None
        address = _destination(event, args)
        if not isinstance(address, tuple):
            return None                                         # AF_UNIX: путь к файлу сокета
        name = _name(address[0])
        ip = _ip(name)
        if ip is None:                                          # имя в connect разрешается внутри, без события
            return None if name == "localhost" or name in self._hosts() else "name"
        if ip.is_loopback:
            return None
        hosts = self._hosts()
        if any(_ip(host) == ip for host in hosts):
            return None
        with self._lock:
            if any(str(ip) in self._resolved.get(host, ()) for host in hosts):
                return None
        return _kind(ip)

    def hook(self, event: str, args: tuple) -> None:
        if event not in _EVENTS:
            return
        kind = self.decide(event, args)
        if kind is None:
            return
        if event in _LOOKUPS:
            port = args[1] if len(args) > 1 else None
        else:
            address = _destination(event, args)
            port = address[1] if len(address) > 1 else None
        origin = _origin()
        key = (kind, port if isinstance(port, (int, str)) else None, origin)
        with self._lock:
            fresh = key not in self._reported and len(self._reported) < _KEEP_REPORTS
            self._reported.add(key)
        if fresh:
            try:
                self._report(*key)
            except Exception:           # журнал недоступен — отказ всё равно в силе
                pass
        raise EgressRefused(f"выход в сеть запрещён сторожем службы ({origin}, порт {key[1]})")


def install(watch: Watch) -> None:
    """Только в процессе службы: снять перехватчик аудита нельзя. socket.create_connection (httpx, httpcore) и
    asyncio берут socket.getaddrinfo при вызове — подмена видна им; кто её обходит, получает прежнюю проверку."""
    sys.addaudithook(watch.hook)
    socket.getaddrinfo = watch.wrap(socket.getaddrinfo)
