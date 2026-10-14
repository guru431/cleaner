import logging

from cleaner.web.app import SECURITY_HEADERS


def test_pages_need_a_login(browser):
    response = browser().get("/")
    assert (response.status_code, response.headers["location"]) == (303, "/login")


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


def test_form_without_the_session_token_is_refused(browser):
    b = browser()
    b.user("ivan")
    b.login("ivan")
    assert b.client.post("/logout", data={"csrf": "чужой"}).status_code == 403
    assert b.get("/").headers["location"] == "/chats"


def test_every_response_carries_the_security_headers(browser):
    b = browser()
    for response in (b.get("/login"), b.get("/static/app.css"), b.get("/static/app.js"), b.get("/missing")):
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
