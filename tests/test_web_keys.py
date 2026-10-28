"""Страница «Ключи» (FR-13.1, план 5А): выпуск, показ один раз, отзыв, кто что видит."""
import re

KEY = re.compile(r"ck_[A-Za-z0-9_-]{43}")


def issue(browser, name: str) -> str:
    response = browser.post("/keys", name=name)
    assert response.status_code == 200, response.text
    return KEY.search(response.text).group(0)


def test_key_is_shown_once_then_only_its_tail(ivan):
    response = ivan.post("/keys", name="Отчёты")
    key = KEY.search(response.text).group(0)
    assert "api/v1/chats" in response.text
    page = ivan.get("/keys").text
    assert key not in page and f"…{key[-4:]}" in page and "Отчёты" in page
    assert ivan.client.get("/api/v1/chats", headers={"X-Cleaner-Key": key}).status_code == 200


def test_users_see_and_revoke_only_their_keys_admin_sees_all(browser, ivan, boss, repo):
    petr = browser()
    petr.user("petr")
    petr.login("petr")
    issue(ivan, "ключ Ивана")
    petr_key = issue(petr, "ключ Петра")
    [petr_key_id] = [k.id for k in repo.api_keys(repo.user_by_login("petr").id)]
    page = ivan.get("/keys").text
    assert "ключ Ивана" in page and "ключ Петра" not in page
    assert ivan.post(f"/keys/{petr_key_id}/disable").status_code == 404
    assert not repo.api_key(petr_key_id).disabled
    admin_page = boss.get("/keys").text
    assert all(text in admin_page for text in ("ключ Ивана", "ключ Петра", "ivan", "petr", "Владелец"))
    response = boss.post(f"/keys/{petr_key_id}/disable")
    assert (response.status_code, response.headers["location"]) == (303, "/keys")
    assert petr.client.get("/api/v1/chats", headers={"X-Cleaner-Key": petr_key}).status_code == 401
    assert [(e.event, e.details) for e in repo.audit_events("key_disabled")] == [("key_disabled", {"id": petr_key_id})]
    assert len(repo.audit_events("key_created")) == 2


def test_key_name_is_required_and_limited(ivan, repo):
    for name in ("", "   ", "я" * 101):
        assert ivan.post("/keys", name=name).status_code == 400, len(name)
    assert repo.api_keys() == []
    assert ivan.post("/keys", name="я" * 100).status_code == 200


def test_keys_page_is_in_the_menu_for_everyone(ivan, boss):
    assert 'href="/keys"' in ivan.get("/chats").text and 'href="/keys"' in boss.get("/chats").text


def test_key_forms_need_the_csrf_token(ivan, repo):
    assert ivan.client.post("/keys", data={"name": "без токена"}).status_code == 403
    issue(ivan, "ключ")
    [key] = repo.api_keys()
    assert ivan.client.post(f"/keys/{key.id}/disable", data={}).status_code == 403
    assert not repo.api_key(key.id).disabled
