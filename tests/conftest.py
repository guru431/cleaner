import re
from datetime import datetime, timedelta, timezone

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from cleaner.core.types import ChatState, Settings
from cleaner.storage import db
from cleaner.storage.repo import Repository
from cleaner.web import auth
from cleaner.web.app import create_app

_CSRF = re.compile(r'name="csrf" value="([^"]+)"')
TEST_PASSWORD = "пароль-для-тестов"


@pytest.fixture
def state() -> ChatState:
    return ChatState(chat_id="test", net_key=bytes(range(32)))


@pytest.fixture
def settings() -> Settings:
    return Settings()


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

    def chat(self, title: str = "Консультация") -> str:
        """Новый чат, его id. Маршрут появляется в задаче 7."""
        response = self.post("/chats", title=title)
        assert response.status_code == 303, response.text
        return response.headers["location"].rsplit("/", 1)[1]


@pytest.fixture
def app(repo, clock, monkeypatch):
    # Быстрый Argon2 только в тестах: хэш хранит свои параметры, проверка пароля от этого не меняется.
    monkeypatch.setattr(auth, "_hasher", PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1))
    return create_app(repo, clock, secure_cookies=False)


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
