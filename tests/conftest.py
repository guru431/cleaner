import contextlib
import ipaddress
import re
import shutil
import socket
from concurrent.futures import Executor, Future
from datetime import datetime, timedelta, timezone

import anyio.from_thread
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from cleaner.core.detect.base import DetectorError
from cleaner.core.risk import check as risk_check
from cleaner.core.types import ChatState, Settings
from cleaner.core.types import EntityType as T
from cleaner.core.types import Span
from cleaner.egress import forward
from cleaner.ingest.extract import Extractor
from cleaner.storage import db
from cleaner.storage.repo import Repository
from cleaner.web import auth
from cleaner.web.app import create_app
from cleaner.web.jobs import Jobs

_CSRF = re.compile(r'name="csrf" value="([^"]+)"')
TEST_PASSWORD = "пароль-для-тестов"


def _loopback(host) -> bool:
    if host is None or host == "localhost":
        return True
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _loopback_only(request, monkeypatch):
    """NFR-8: быстрый набор работает без сети — проверяется фактом на каждом тесте, а не импортами.
    У библиотек моделей и документов свои загрузчики (huggingface_hub, docling): тест импортов их
    не видит, а новый путь к сети в быстром наборе упадёт здесь. Петля разрешена (тестовые серверы)."""
    if request.node.get_closest_marker("integration") or request.node.get_closest_marker("manual"):
        return
    connect, connect_ex, getaddrinfo = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    def check(address) -> None:
        if isinstance(address, tuple) and not _loopback(address[0]):
            raise OSError(f"быстрый набор: соединение с {address[0]} запрещено")

    def guarded_connect(self, address):
        check(address)
        return connect(self, address)

    def guarded_connect_ex(self, address):
        check(address)
        return connect_ex(self, address)

    def guarded_getaddrinfo(host, *args, **kwargs):
        check((host,))         # запрос к DNS — уже выход в сеть
        return getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)


@pytest.fixture(autouse=True)
def _close_pooled_clients():
    """Клиенты пула egress живут в модуле: после теста — закрыть, чтобы следующий на том же порту петли их не получил."""
    yield
    forward.close_clients()


@pytest.fixture
def state() -> ChatState:
    return ChatState(chat_id="test", net_key=bytes(range(32)))


@pytest.fixture
def settings() -> Settings:
    return Settings()


class FakeNer:
    """Слой 4 для тестов: помечает заданные строки и считает вызовы."""

    name = "ner"

    def __init__(self) -> None:
        self.marks: dict[str, T] = {}
        self.calls = 0

    def detect(self, text: str, ctx=None) -> list[Span]:
        self.calls += 1
        return [
            Span(m.start(), m.end(), type_, "ner", 0.9)
            for value, type_ in self.marks.items() for m in re.finditer(re.escape(value), text)
        ]


class FakeSecondPass:
    """Слой 5 для тестов: запоминает очищенный слоями 1–4 текст, помечает заданные строки в оригинале."""

    def __init__(self) -> None:
        self.marks: dict[str, T] = {}
        self.seen: list[str] = []

    def find(self, text: str, sanitized: str, state) -> list[Span]:
        self.seen.append(sanitized)
        return [
            Span(m.start(), m.end(), type_, "llm")
            for value, type_ in self.marks.items() for m in re.finditer(re.escape(value), text)
        ]


class FakeCompleter:
    """Локальная модель для тестов: отдаёт заготовленные ответы по очереди и запоминает запросы."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.requests: list[dict] = []
        self.error: Exception | None = None

    def answer(self, messages, *, max_tokens) -> tuple[str, bool]:
        return self.complete(messages, max_tokens=max_tokens), self.truncated

    truncated = False

    def complete(self, messages, *, max_tokens, json_schema=None) -> str:
        self.requests.append({"messages": messages, "max_tokens": max_tokens, "json_schema": json_schema})
        if self.error is not None:
            raise self.error
        return self.answers.pop(0) if self.answers else '{"items": []}'


class FakeDocuments:
    """Разбор документов для тестов: вместо Docling — заданный текст."""

    def __init__(self) -> None:
        self.text = "Документ: почта doc@x.example"

    def convert(self, data: bytes, kind: str) -> str:
        return self.text

    def pdf_pages(self, data: bytes, pages) -> dict[int, str]:
        return {number: self.text for number in pages}


class FakeEngines:
    """Тяжёлые и сетевые части для тестов: модели и локальная модель подменены, сети нет."""

    models_dir = None                          # моделей на диске нет: в паспорте замера ревизий моделей нет

    def __init__(self) -> None:
        self.ner_layer = FakeNer()
        self.second = FakeSecondPass()
        self.completer = FakeCompleter()
        self.unavailable: str | None = None     # причина, по которой включённый слой недоступен
        self.documents = FakeDocuments()
        self.ocr_text = "Скан: почта scan@x.example"

    def _check(self) -> None:
        if self.unavailable:
            raise DetectorError(self.unavailable)

    def status(self) -> dict:
        return {"key": True, "models": {}}

    def client(self):
        self._check()
        return self.completer

    def ner(self):
        self._check()
        return self.ner_layer

    def llm(self):
        self._check()
        return self.second

    def extractor(self) -> Extractor:
        return Extractor(self.documents, lambda image, mime: self.ocr_text)

    def risk(self):
        self._check()
        return lambda sanitized: risk_check(self.completer, sanitized)


@pytest.fixture
def engines() -> FakeEngines:
    return FakeEngines()


class Immediate(Executor):
    """Исполнитель для тестов: задание выполняется сразу, в потоке запроса."""

    def submit(self, fn, /, *args, **kwargs):
        future = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except BaseException as exc:
            future.set_exception(exc)
        return future


@pytest.fixture
def jobs() -> Jobs:
    return Jobs(Immediate())


class FakeClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.current

    def advance(self, **delta: float) -> None:
        self.current += timedelta(**delta)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture(scope="session")
def migrated(tmp_path_factory):
    """База со схемой и всеми миграциями — один раз на прогон: схема и миграции, каждая своей транзакцией с записью
    на диск, стоили каждому тесту с базой около 35 мс из 60 (замер 21.10.2026). Миграции проверяет test_db."""
    path = tmp_path_factory.mktemp("schema") / "cleaner.db"
    conn = db.connect(path)
    db.migrate(conn)
    conn.close()                    # последнее соединение переносит журнал WAL в файл базы
    return path


@pytest.fixture
def repo(tmp_path, clock, migrated):
    shutil.copyfile(migrated, tmp_path / "cleaner.db")
    conn = db.connect(tmp_path / "cleaner.db")
    # Без сброса на диск после каждой транзакции: на Windows он стоил тестам секунды, а сохранность при отключении
    # питания тестам не нужна. Служба работает с умолчанием SQLite.
    conn.execute("PRAGMA synchronous = OFF")
    yield Repository(conn, bytes(range(32)), clock)
    conn.close()


@pytest.fixture
def wal_reader(tmp_path, repo):
    """Другое соединение держит снимок базы (копия, eval): контрольная точка с усечением журнала WAL не
    проходит. Соединение службы его не ждёт — без пятисекундного busy_timeout."""
    repo.conn.execute("PRAGMA busy_timeout = 0")
    reader = db.connect(tmp_path / "cleaner.db")
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM chats").fetchone()
    yield reader
    reader.execute("COMMIT")
    reader.close()


class Browser:
    """Браузер для тестов: свои cookie, вход, формы с токеном."""

    def __init__(self, client: TestClient, repo: Repository):
        self.client = client
        self.repo = repo
        self.csrf = ""

    def user(self, login: str, role: str = "user") -> str:
        return self.repo.create_user(login, auth.hash_password(TEST_PASSWORD), role)

    def login(self, login: str, password: str = TEST_PASSWORD):
        token = _CSRF.search(self.client.get("/login").text).group(1)
        response = self.client.post("/login", data={"login": login, "password": password, "csrf": token})
        if response.status_code == 303:
            session = self.repo.session(auth.token_hash(self.client.cookies["cleaner_session"]))
            self.csrf = session.csrf
        return response

    def get(self, path: str, **params: str):
        return self.client.get(path, params=params or None)

    def post(self, path: str, **fields: str):
        return self.client.post(path, data={"csrf": self.csrf, **fields})

    def upload(self, path: str, filename: str, data: bytes):
        return self.client.post(path, data={"csrf": self.csrf}, files={"file": (filename, data, "application/octet-stream")})

    def chat(self, title: str = "Консультация") -> str:
        """Новый чат, его id. Маршрут появляется в задаче 7."""
        response = self.post("/chats", title=title)
        assert response.status_code == 303, response.text
        return response.headers["location"].rsplit("/", 1)[1]


@pytest.fixture
def app(repo, clock, monkeypatch, engines, jobs):
    # Быстрый Argon2 только в тестах: хэш хранит свои параметры, проверка пароля от этого не меняется.
    monkeypatch.setattr(auth, "_hasher", PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1))
    return create_app(
        repo, clock, secure_cookies=False, engines=engines, jobs=jobs, sends=Jobs(Immediate()), files=Jobs(Immediate()),
        measures=Jobs(Immediate()),
    )


@pytest.fixture
def browser(app, repo):
    clients: list[TestClient] = []
    portals = contextlib.ExitStack()

    def make() -> Browser:
        client = TestClient(app, follow_redirects=False)
        # Один цикл событий на клиента, как у службы, — без запуска lifespan (with TestClient): без него клиент
        # заводил поток с новым циклом на каждый запрос, и на Windows это стоило около 50 мс запроса (замер 21.10.2026).
        client.portal = portals.enter_context(anyio.from_thread.start_blocking_portal(**client.async_backend))
        clients.append(client)
        return Browser(client, repo)

    with portals:
        yield make
        for client in clients:
            client.close()


@pytest.fixture
def ivan(browser) -> Browser:
    """Вошедший пользователь."""
    b = browser()
    b.user("ivan")
    b.login("ivan")
    return b


@pytest.fixture
def boss(browser) -> Browser:
    """Вошедший администратор."""
    b = browser()
    b.user("boss", "admin")
    b.login("boss")
    return b


class Api:
    """Программа для тестов /api/v1: свой клиент без cookie, ключ — заголовком X-Cleaner-Key."""

    def __init__(self, client: TestClient, key: str, user_id: str = "", key_id: str = ""):
        self.client = client
        self.key = key
        self.user_id = user_id
        self.key_id = key_id

    def _headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        return {"X-Cleaner-Key": self.key, **(headers or {})}

    def get(self, path: str, headers: dict[str, str] | None = None):
        return self.client.get(path, headers=self._headers(headers))

    def post(self, path: str, json=None, headers: dict[str, str] | None = None, **extra):
        return self.client.post(path, json=json, headers=self._headers(headers), **extra)

    def delete(self, path: str, headers: dict[str, str] | None = None):
        return self.client.delete(path, headers=self._headers(headers))


@pytest.fixture
def api(browser, repo):
    """Программа с ключом пользователя login; учётная запись создаётся, если её нет."""

    def make(login: str = "ivan", role: str = "user") -> Api:
        user = repo.user_by_login(login)
        user_id = user.id if user else repo.create_user(login, auth.hash_password(TEST_PASSWORD), role)
        key = auth.new_api_key()
        key_id = repo.add_api_key(user_id, f"тест {login}", auth.token_hash(key), key[-4:])
        return Api(browser().client, key, user_id, key_id)

    return make


@pytest.fixture
def no_network(monkeypatch):
    """Любая попытка соединения — ошибка: работа без сети проверяется фактом (NFR-2), а не настройкой."""
    import socket

    def refuse(*args, **kwargs):
        raise OSError("сеть запрещена в этом тесте")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
