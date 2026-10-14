import re

import regex

from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy


def test_settings_are_for_admins_only(ivan):
    for path in (
        "/settings", "/settings/policies", "/settings/dictionary", "/settings/patterns",
        "/settings/builtin", "/settings/users", "/settings/audit",
    ):
        assert ivan.get(path).status_code == 403, path
    assert ivan.post("/settings/policies", **{"policy-CARD": "block"}).status_code == 403


def test_policies_are_saved_and_logged(boss, repo):
    boss.post("/settings/policies", **{"policy-CARD": "block", "policy-SECRET": "hide"})
    assert repo.policies()[T.CARD] is Policy.BLOCK
    assert [e.details for e in repo.audit_events("policy_changed")] == [{"type": "CARD", "policy": "block"}]
    assert boss.post("/settings/policies", **{"policy-CARD": "всегда"}).status_code == 400
    assert repo.policies()[T.CARD] is Policy.BLOCK


def test_dictionary_entries_are_added_shown_escaped_and_deleted(boss, repo):
    boss.post(
        "/settings/dictionary", list="always", value="<b>Ромашка</b>", type="ORG",
        aliases="Romashka\nРомашка-М", comment="клиент",
    )
    [row] = repo.dictionary()
    assert (row.type, row.value, row.aliases, row.comment) == (T.ORG, "<b>Ромашка</b>", ("Romashka", "Ромашка-М"), "клиент")
    assert "&lt;b&gt;Ромашка&lt;/b&gt;" in boss.get("/settings/dictionary").text
    boss.post(f"/settings/dictionary/{row.id}/delete")
    assert repo.dictionary() == []
    assert [e.details for e in repo.audit_events("dictionary_changed")] == [
        {"action": "delete", "list": "always"}, {"action": "add", "list": "always"},
    ]
    assert boss.post("/settings/dictionary", list="always", value="Без типа").status_code == 400


def test_csv_import_shows_a_preview_before_writing(boss, repo):
    repo.add_dictionary("never", "known.example")
    csv_text = "﻿Name;DNSHostName\r\nsrv1;srv1.corp.example\r\nsrv2;known.example\r\nsrv3;srv1.corp.example\r\n"
    fields = {"csv": csv_text, "delimiter": "semicolon", "list": "never"}
    preview = boss.post("/settings/dictionary/import", column="DNSHostName", action="preview", **fields)
    assert preview.status_code == 200 and "новых для списка: 1" in preview.text
    assert len(repo.dictionary()) == 1                                       # предпросмотр ничего не пишет
    boss.post("/settings/dictionary/import", column="DNSHostName", action="save", **fields)
    assert sorted(r.value for r in repo.dictionary()) == ["known.example", "srv1.corp.example"]
    assert [e.details for e in repo.audit_events("dictionary_import")] == [{"list": "never", "count": 1}]
    assert boss.post("/settings/dictionary/import", column="Нет", action="save", **fields).status_code == 400


def test_pattern_is_tried_on_a_sample_before_saving(boss, repo, monkeypatch):
    fields = {"name": "Инвентарный", "regex": r"INV-\d{6}", "type": "TERM"}
    tried = boss.post("/settings/patterns", sample="INV-123456 и INV-12", action="test", **fields)
    assert "Совпадений: 1" in tried.text and repo.patterns() == []
    boss.post("/settings/patterns", sample="INV-123456", action="save", **fields)
    assert [p.regex for p in repo.patterns()] == [r"INV-\d{6}"]
    for bad in ("(", r"\d*"):                                        # не разбирается; находит пустую строку
        response = boss.post("/settings/patterns", name="Плохой", regex=bad, type="TERM", sample="1", action="save")
        assert response.status_code == 400, bad

    def too_slow(*args, **kwargs):
        raise TimeoutError

    monkeypatch.setattr(regex, "finditer", too_slow)
    slow = boss.post("/settings/patterns", name="Медленный", regex="(a+)+$", type="TERM", sample="a" * 30 + "b", action="save")
    assert slow.status_code == 400 and "долго" in slow.text
    assert len(repo.patterns()) == 1


def test_builtin_lists_are_shown_and_extended_through_the_never_list(boss, repo):
    page = boss.get("/settings/builtin").text
    assert "microsoft.com" in page and "administrator" in page
    response = boss.post("/settings/dictionary", list="never", value="intranet.example", back="builtin")
    assert response.headers["location"] == "/settings/builtin"
    assert repo.settings().never == frozenset({"intranet.example"})


def test_users_are_created_given_new_passwords_and_disabled(boss, browser, repo):
    boss.post("/settings/users", login="petr", password="длинный-пароль-1", role="user")
    petr = repo.user_by_login("petr")
    other = browser()
    assert other.login("petr", "длинный-пароль-1").status_code == 303
    boss.post(f"/settings/users/{petr.id}/password", password="другой-пароль-22")
    assert other.get("/").headers["location"] == "/login"                    # смена пароля закрывает сессии
    boss.post(f"/settings/users/{petr.id}/disable", disabled="yes")
    assert other.login("petr", "другой-пароль-22").status_code == 401
    assert boss.post("/settings/users", login="short", password="коротко", role="user").status_code == 400
    assert boss.post("/settings/users", login="petr", password="длинный-пароль-1", role="user").status_code == 400
    me = repo.user_by_login("boss")
    assert boss.post(f"/settings/users/{me.id}/disable", disabled="yes").status_code == 400
    assert {"user_created", "password_changed", "user_disabled"} <= {e.event for e in repo.audit_events()}


def test_audit_is_filtered_by_event_user_and_day(browser, repo, clock):
    ivan = repo.create_user("ivan", "hash", "user")
    repo.audit("restore", ivan, restored=2)                                   # 14.10
    clock.advance(days=1)
    admin = browser()
    admin.user("boss", "admin")
    admin.login("boss")                                                       # 15.10

    def events(**params: str) -> list[str]:
        return re.findall(r'<td class="event">([^<]+)</td>', admin.get("/settings/audit", **params).text)

    assert events() == ["login", "restore"]
    assert events(event="restore") == ["restore"]
    assert events(user=ivan) == ["restore"]
    assert events(since="2026-10-15") == ["login"]
    assert events(until="2026-10-14") == ["restore"]
    assert admin.get("/settings/audit", since="вчера").status_code == 400
