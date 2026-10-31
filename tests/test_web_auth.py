import asyncio
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import urlencode

import anyio
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException

from cleaner.web import auth
from cleaner.web.app import BodyLimit, HSTS, MAX_BODY_BYTES, SECURITY_HEADERS, _UPLOAD_HEADROOM, create_app


def test_pages_need_a_login(browser):
    response = browser().get("/")
    assert (response.status_code, response.headers["location"]) == (303, "/login")


@pytest.mark.parametrize("prefix", ["/agent/anthropic", "/agent/openai"])
def test_agent_errors_accept_structured_http_exception_details(app, browser, prefix):
    @app.get(prefix + "/synthetic-error")
    def structured_error():
        raise HTTPException(400, {"reason": "synthetic"})

    response = browser().get(prefix + "/synthetic-error")
    assert response.status_code == 400
    assert response.json()["error"]["message"].startswith("Cleaner:")
    assert "synthetic" in response.json()["error"]["message"]


def test_login_and_logout(browser, repo):
    b = browser()
    b.user("ivan")
    response = b.login("ivan")
    assert (response.status_code, response.headers["location"]) == (303, "/")
    assert b.get("/").headers["location"] == "/chats"
    b.post("/logout")
    assert b.get("/").headers["location"] == "/login"
    assert [e.event for e in repo.audit_events()] == ["logout", "login"]


def test_wrong_password_and_unknown_login_look_the_same(browser, repo):
    b = browser()
    b.user("ivan")
    wrong, unknown = b.login("ivan", "не тот пароль"), b.login("petr", "не тот пароль")
    assert wrong.status_code == unknown.status_code == 401
    assert "Неверный логин или пароль" in wrong.text and "Неверный логин или пароль" in unknown.text
    assert [e.event for e in repo.audit_events()] == ["login_failed", "login_failed"]


def test_login_form_without_its_token_is_refused(browser):
    b = browser()
    b.user("ivan")
    b.client.get("/login")
    response = b.client.post("/login", data={"login": "ivan", "password": "пароль-для-тестов", "csrf": "чужой"})
    assert response.status_code == 403


def test_repeated_failures_slow_down_the_login(browser, clock):
    b = browser()
    b.user("ivan")
    for _ in range(5):
        assert b.login("ivan", "неверно").status_code == 401
    assert b.login("ivan").status_code == 429            # после пяти неудач — пауза, даже с верным паролем
    clock.advance(seconds=1)
    assert b.login("ivan", "неверно").status_code == 401
    assert b.login("ivan").status_code == 429            # теперь пауза 2 секунды
    clock.advance(seconds=2)
    assert b.login("ivan").status_code == 303


def test_session_expires_after_eight_idle_hours(browser, clock):
    b = browser()
    b.user("ivan")
    b.login("ivan")
    clock.advance(hours=7, minutes=59)
    assert b.get("/").headers["location"] == "/chats"
    clock.advance(hours=8, seconds=1)
    assert b.get("/").headers["location"] == "/login"


def test_disabled_user_loses_the_session(browser, repo):
    b = browser()
    user = b.user("ivan")
    b.login("ivan")
    repo.set_disabled(user, True)
    assert b.get("/").headers["location"] == "/login"
    assert b.login("ivan").status_code == 401


@pytest.mark.parametrize("change", ["password", "disabled"])
def test_account_changed_during_the_password_check_gets_no_session(browser, repo, monkeypatch, change):
    """Аудит 21.10.2026: пока Argon2 проверял старый пароль, его сменили или учётную запись отключили. Смена уже
    закрыла сессии — вход по проверенному, но отозванному паролю новую не открывает."""
    b = browser()
    user = b.user("ivan")
    real = auth.check_password

    async def changed_meanwhile(password_hash, password):
        ok = await real(password_hash, password)
        if change == "password":
            repo.set_password(user, "$argon2id$другой-хэш")
        else:
            repo.set_disabled(user, True)
        return ok

    monkeypatch.setattr(auth, "check_password", changed_meanwhile)
    response = b.login("ivan")
    assert response.status_code == 401 and "Неверный логин или пароль" in response.text
    assert repo.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert [e.event for e in repo.audit_events()] == ["login_failed"]


def test_form_without_the_session_token_is_refused(browser):
    b = browser()
    b.user("ivan")
    b.login("ivan")
    assert b.client.post("/logout", data={"csrf": "чужой"}).status_code == 403
    assert b.get("/").headers["location"] == "/chats"


def test_every_response_carries_the_security_headers(browser):
    b = browser()
    for response in (
        b.get("/login"), b.get("/static/app.css"), b.get("/static/app.js"), b.get("/static/theme.js"),
        b.get("/static/icons.svg"), b.get("/missing"),
    ):
        for name, value in SECURITY_HEADERS.items():
            assert response.headers[name] == value, (response.url, name)


def test_unexpected_error_shows_a_page_without_details(browser, repo, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    b = browser()
    b.user("ivan")
    b.login("ivan")

    def broken(token_hash):
        raise RuntimeError("секрет Qq77 в тексте ошибки")

    monkeypatch.setattr(repo, "touch_session", broken)
    response = b.get("/")
    assert response.status_code == 500 and "Qq77" not in response.text and "Qq77" not in caplog.text
    assert response.headers["Content-Security-Policy"] == SECURITY_HEADERS["Content-Security-Policy"]
    assert repo.audit_events("error")[0].details == {"kind": "RuntimeError", "path": "/"}


def test_password_check_runs_outside_the_event_loop(browser, monkeypatch):
    """Обзор 1Б, P3: Argon2 в цикле событий останавливал все остальные запросы на время проверки."""
    places = []
    real = auth.verify_password

    def spy(password_hash, password):
        try:
            asyncio.get_running_loop()
            places.append("event loop")
        except RuntimeError:
            places.append("worker thread")
        return real(password_hash, password)

    monkeypatch.setattr(auth, "verify_password", spy)
    b = browser()
    b.user("ivan")
    assert b.login("ivan").status_code == 303
    assert places == ["worker thread"]


def _chunks(total: int, size: int = 1024 * 1024):
    """Тело частями (chunked): без заголовка Content-Length."""
    sent = 0
    while sent < total:
        yield b"a" * min(size, total - sent)
        sent += size


@pytest.mark.parametrize("path", ["/login", "/logout"])
def test_oversized_body_without_content_length_is_refused(browser, path):
    """Обзор 1Б, P3: предел тела действует на каждый запрос, вход тоже, и считает принятые байты."""
    b = browser()
    b.user("ivan")
    b.login("ivan")
    response = b.client.post(
        path, content=_chunks(MAX_BODY_BYTES + 1), headers={"content-type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 413
    assert response.headers["Content-Security-Policy"] == SECURITY_HEADERS["Content-Security-Policy"]


@pytest.mark.parametrize(("path", "upload"), [
    ("/chats/abc/upload", True), ("/api/v1/chats/abc/files", True),
    ("/reports/upload", False), ("/api/v1/chats/abc/extra/files", False),
])
def test_only_upload_routes_get_the_file_body_limit(path, upload):
    app = SimpleNamespace(state=SimpleNamespace(max_file_bytes=128))
    limiter = BodyLimit(None, limit=64)
    assert limiter._limit({"path": path, "app": app}) == (128 + _UPLOAD_HEADROOM if upload else 64)


def test_spraying_random_logins_does_not_reset_a_throttled_account(clock):
    """Обзор 1Б, P3: вытесняются только записи без действующей паузы."""
    throttle = auth.Throttle(clock)
    for _ in range(6):
        throttle.failed("ivan")
    for number in range(auth.Throttle._KEEP):
        throttle.failed(f"random{number}")
    assert throttle.wait("ivan") == 2.0
    assert len(throttle.failures) <= auth.Throttle._KEEP


def test_spraying_random_logins_after_the_pause_keeps_the_account_count(clock):
    """Обзор 1В: пауза учётной записи истекла — перебор случайных логинов всё равно не обнуляет её счёт.
    Вытесняются записи с меньше чем пятью неудачами; есть ли логин в базе, не важно: иначе по ответам
    401 и 429 после перебора было бы видно, какие логины существуют."""
    throttle = auth.Throttle(clock)
    for _ in range(6):
        throttle.failed("ivan")
    clock.advance(seconds=3)
    for number in range(auth.Throttle._KEEP):
        throttle.failed(f"random{number}")
    throttle.failed("ivan")
    assert throttle.wait("ivan") == 4.0
    assert len(throttle.failures) <= auth.Throttle._KEEP


def test_password_checks_over_the_limit_get_try_later_and_are_not_failures(browser, repo, monkeypatch):
    """Обзор 1В: Argon2 — 64 МиБ на проверку, а анонимных входов в пуле потоков до сорока одновременно.
    Сверх предела проверка ждёт свободного места, не дождалась — «попробуйте позже»."""
    gate = threading.Event()
    with ThreadPoolExecutor(1) as slots:
        monkeypatch.setattr(auth, "_hashing", slots)
        monkeypatch.setattr(auth, "HASH_WAIT", 0.2)
        b = browser()
        b.user("ivan")
        assert b.login("ivan", "неверно").status_code == 401         # место освобождается и после неудачи
        slots.submit(gate.wait, 5)                                    # единственное место занято другим входом
        busy = b.login("ivan")
        gate.set()
        assert busy.status_code == 503 and "попробуйте позже" in busy.text
        assert b.login("ivan").status_code == 303
    assert [e.event for e in repo.audit_events()] == ["login", "login_failed"]


def _shared_threads(total: int) -> None:
    anyio.to_thread.current_default_thread_limiter().total_tokens = total


def test_logins_waiting_for_a_password_slot_hold_no_shared_threads(browser, monkeypatch):
    """Находка «Small gaps…»: вход, ждущий места для Argon2, держал поток общего пула Starlette до 5 с, и сорок
    параллельных POST /login останавливали все страницы. Теперь ожидание — в цикле событий, без потока."""
    entered, gate = threading.Semaphore(0), threading.Event()

    class Held(PasswordHasher):
        def verify(self, hash, password):
            entered.release()
            gate.wait(5)
            return super().verify(hash, password)

    b = browser()
    b.user("ivan")
    # Пауза после пяти неудач здесь ни при чём: шесть неверных паролей разом, и под нагрузкой машины последний вход
    # доходил до проверки паузы после пяти записанных неудач — 429 вместо 401 (аудит 21.10.2026).
    monkeypatch.setattr(auth.Throttle, "FREE", auth.HASH_SLOTS + 3)
    with b.client as client:                    # один цикл событий на все запросы, как у uvicorn
        monkeypatch.setattr(auth, "_hasher", Held(time_cost=1, memory_cost=1024, parallelism=1))
        client.portal.call(_shared_threads, auth.HASH_SLOTS)     # общий пул — четыре потока вместо сорока
        client.get("/login")
        form = {"login": "ivan", "password": "неверно", "csrf": client.cookies["cleaner_login"]}
        statuses: list[int] = []
        logins = [threading.Thread(target=lambda: statuses.append(client.post("/login", data=form).status_code))
                  for _ in range(auth.HASH_SLOTS + 2)]
        page = threading.Thread(target=lambda: statuses.append(client.get("/login").status_code))
        try:
            for login in logins:
                login.start()
            assert all(entered.acquire(timeout=5) for _ in range(auth.HASH_SLOTS))     # места заняты, двое ждут
            page.start()
            page.join(2)
            assert statuses == [200]            # страница не ждёт, пока входы освободят потоки
        finally:
            gate.set()
            for thread in (*logins, page):
                thread.join(5)
    assert sorted(statuses) == [200] + [401] * (auth.HASH_SLOTS + 2)


def test_admin_password_hashing_waits_for_the_same_slots(monkeypatch):
    """Находка «Small gaps…»: хэш нового пароля (создание пользователя, смена пароля) шёл мимо предела в четыре места."""
    monkeypatch.setattr(auth, "_hasher", PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1))
    gate, hashed = threading.Event(), []
    with ThreadPoolExecutor(1) as slots:
        monkeypatch.setattr(auth, "_hashing", slots)
        slots.submit(gate.wait, 5)                                    # единственное место занято входом
        admin = threading.Thread(target=lambda: hashed.append(auth.hash_password("пароль-администратора")))
        admin.start()
        admin.join(0.2)
        waited = list(hashed)
        gate.set()
        admin.join(5)
    assert waited == [] and hashed[0].startswith("$argon2id$")


def test_hsts_header_only_under_tls(repo, clock):
    for secure, expected in ((True, HSTS), (False, None)):
        with TestClient(create_app(repo, clock, secure_cookies=secure)) as client:
            assert client.get("/login").headers.get("Strict-Transport-Security") == expected


def test_largest_allowed_text_fits_under_the_body_limit():
    """Review Focus: предел тела не отказывает тексту, который служба принимает (500 000 знаков);
    худший случай — четырёхбайтные знаки, 12 байт каждый в закодированной форме."""
    body = urlencode({"csrf": "x" * 43, "text": "😀" * 500_000})
    assert len(body) < MAX_BODY_BYTES
