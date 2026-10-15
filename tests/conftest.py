import re
from concurrent.futures import Executor, Future
from datetime import datetime, timedelta, timezone

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from cleaner.core.detect.base import DetectorError
from cleaner.core.risk import check as risk_check
from cleaner.core.types import ChatState, Settings
from cleaner.core.types import EntityType as T
from cleaner.core.types import Span
from cleaner.ingest.extract import Extractor
from cleaner.storage import db
from cleaner.storage.repo import Repository
from cleaner.web import auth
from cleaner.web.app import create_app
from cleaner.web.jobs import Jobs

_CSRF = re.compile(r'name="csrf" value="([^"]+)"')
TEST_PASSWORD = "пароль-для-тестов"


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


@pytest.fixture
def repo(tmp_path, clock):
    conn = db.connect(tmp_path / "cleaner.db")
    db.migrate(conn)
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
    return create_app(repo, clock, secure_cookies=False, engines=engines, jobs=jobs)


@pytest.fixture
def browser(app, repo):
    clients: list[TestClient] = []

    def make() -> Browser:
        client = TestClient(app, follow_redirects=False)
        clients.append(client)
        return Browser(client, repo)

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


@pytest.fixture
def no_network(monkeypatch):
    """Любая попытка соединения — ошибка: работа без сети проверяется фактом (NFR-2), а не настройкой."""
    import socket

    def refuse(*args, **kwargs):
        raise OSError("сеть запрещена в этом тесте")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
