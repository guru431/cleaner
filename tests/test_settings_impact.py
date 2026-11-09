"""Shared previews never disclose another owner's text or mutate a chat."""
import re
import threading

import pytest

from cleaner import settings_impact
from cleaner.core.types import EntityType as T, Policy, default_policies
from cleaner.service import ChatService
from cleaner.web import routes_settings


def test_impact_is_read_only_private_and_can_be_rolled_back(repo):
    admin = repo.create_user("admin", "hash", "admin")
    other = repo.create_user("other", "hash", "user")
    chat = repo.create_chat(other, "Private")
    service = ChatService(repo)
    service.add_input(chat, other, "mail private.person@contoso.ru")
    state, version = repo.load_state(chat)
    operation = {"kind": "policies", "policies": {"EMAIL": "block"}}
    shown = settings_impact.preview(repo, admin, operation)
    assert shown["mine"]["chats"] == 0 and shown["others"] is None      # один чужой владелец — ниже порога
    assert shown["own"] == [] and "private.person" not in str(shown)
    assert repo.load_state(chat)[1] == version and repo.policies()[T.EMAIL] is Policy.MASK
    settings_impact.apply(repo, admin, shown["receipt"])
    assert repo.policies()[T.EMAIL] is Policy.BLOCK and repo.load_state(chat)[1] == version
    with pytest.raises(ValueError, match="изменились"):
        settings_impact.apply(repo, admin, shown["receipt"])
    undo = settings_impact.preview(repo, admin, {"kind": "undo"})
    settings_impact.apply(repo, admin, undo["receipt"])
    assert repo.policies()[T.EMAIL] is Policy.MASK


def test_changed_settings_invalidate_confirmation_but_chat_activity_does_not(repo):
    """Ходы агентов и новые тексты поднимают версии чатов; подтверждение связано с настройками и эталоном."""
    owner = repo.create_user("admin", "hash", "admin")
    chat = repo.create_chat(owner, "Own")
    agent = repo.create_chat(owner, "Agent", kind="agent")
    shown = settings_impact.preview(repo, owner, {"kind": "policies", "policies": {"EMAIL": "off"}})
    ChatService(repo).add_input(chat, owner, "new text")
    repo.conn.execute("UPDATE chats SET version = version + 1 WHERE id = ?", (agent,))
    settings_impact.apply(repo, owner, shown["receipt"])
    assert repo.policies()[T.EMAIL] is Policy.OFF
    shown = settings_impact.preview(repo, owner, {"kind": "policies", "policies": {"EMAIL": "block"}})
    repo.set_policy(T.PHONE, Policy.HIDE)
    with pytest.raises(ValueError, match="изменились"):
        settings_impact.apply(repo, owner, shown["receipt"])
    assert repo.policies()[T.EMAIL] is Policy.OFF


def test_preview_does_not_hold_the_service_lock_while_recounting(repo, monkeypatch):
    """Пересчёт идёт по снимку отдельного соединения: сессии, шлюз и задания его не ждут."""
    admin = repo.create_user("admin", "hash", "admin")
    chat = repo.create_chat(admin, "Own")
    ChatService(repo).add_input(chat, admin, "mail owner@contoso.ru")
    waited = []
    original = settings_impact.sanitize

    def probe(*args, **kwargs):
        if not waited:
            def other_request():
                repo.user(admin)
                repo.set_setting("probe", "1")
            thread = threading.Thread(target=other_request)
            thread.start()
            thread.join(timeout=5)
            waited.append(thread.is_alive())
        return original(*args, **kwargs)

    monkeypatch.setattr(settings_impact, "sanitize", probe)
    shown = settings_impact.preview(repo, admin, {"kind": "policies", "policies": {"EMAIL": "block"}})
    assert waited == [False] and shown["mine"]["chats"] == 1
    assert repo.setting("probe") == "1"


def test_chat_deleted_during_a_preview_does_not_wait_and_the_wal_is_truncated_after(tmp_path, repo, monkeypatch):
    """Ревью: снимок оценки — другое соединение; удаление чата ждало его три раза по 5 с под общим замком (служба
    стояла) и кончалось CheckpointBusy, а страницы удалённого чата с обёрткой его ключа оставались в cleaner.db-wal
    (FR-1.4). Удаление не ждёт снимок своего процесса: усечение откладывается до его закрытия."""
    repo.conn.execute("PRAGMA busy_timeout = 0")            # прежнее ожидание — сразу CheckpointBusy, без 15 с
    admin = repo.create_user("admin", "hash", "admin")
    service = ChatService(repo)
    chat = repo.create_chat(admin, "Own")
    service.add_input(chat, admin, "mail owner@contoso.ru")
    doomed = repo.create_chat(admin, "Вымышленный")
    [wrapped] = repo.conn.execute("SELECT dek_wrapped FROM chats WHERE id = ?", (doomed,)).fetchone()
    deferred = []
    original = settings_impact.sanitize

    def probe(*args, **kwargs):
        if not deferred:
            service.delete_chat(doomed, admin)
            deferred.append(bytes(wrapped) in (tmp_path / "cleaner.db-wal").read_bytes())
        return original(*args, **kwargs)

    monkeypatch.setattr(settings_impact, "sanitize", probe)
    settings_impact.preview(repo, admin, {"kind": "policies", "policies": {"EMAIL": "block"}})
    assert deferred == [True] and repo.chat(doomed) is None
    assert repo.audit_events("error") == [] and repo.audit_events("chat_deleted")[0].details == {"wal": "deferred"}
    assert bytes(wrapped) not in b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))


def _row(list_, value, type_=None):
    return {"id": "", "list": list_, "value": value, "type": type_, "aliases": [], "comment": ""}


def test_apply_writes_the_same_audit_events_as_direct_edits(repo):
    admin = repo.create_user("admin", "hash", "admin")

    def run(operation):
        settings_impact.apply(repo, admin, settings_impact.preview(repo, admin, operation)["receipt"])

    run({"kind": "policies", "policies": {"EMAIL": "block", "PHONE": "mask"}})
    assert [e.details for e in repo.audit_events("policy_changed")] == [{"type": "EMAIL", "policy": "block"}]
    run({"kind": "add", "rows": [_row("always", "Ромашка-Плюс", "ORG")]})
    assert [e.details for e in repo.audit_events("dictionary_changed")] == [{"action": "add", "list": "always"}]
    run({"kind": "add", "rows": [_row("never", "альфа"), _row("never", "бета")], "import": True})
    assert [e.details for e in repo.audit_events("dictionary_import")] == [{"list": "never", "count": 2}]
    entry = next(r.id for r in repo.dictionary() if r.list == "always")
    run({"kind": "delete", "id": entry})
    assert repo.audit_events("dictionary_changed")[0].details == {"action": "delete", "list": "always"}
    assert "Ромашка" not in str([e.details for e in repo.audit_events()])


def test_csv_import_of_one_new_row_is_logged_as_an_import(boss, repo):
    """Импорт отличается по признаку из маршрута импорта, а не по числу записей: CSV с одной новой строкой —
    dictionary_import, как при прямом сохранении импорта."""
    fields = {"csv": "Name\r\nsrv1.corp.example\r\n", "delimiter": "semicolon", "list": "never", "column": "Name"}
    shown = boss.post("/settings/dictionary/import", action="impact", **fields)
    assert shown.status_code == 200, shown.text
    assert repo.audit_events("settings_previewed")[0].details["kind"] == "import"
    receipt = re.search(r'name="receipt" value="([^"]+)"', shown.text).group(1)
    assert boss.post("/settings/impact/apply", receipt=receipt).status_code == 303
    assert [e.details for e in repo.audit_events("dictionary_import")] == [{"list": "never", "count": 1}]
    assert repo.audit_events("dictionary_changed") == []


def test_other_owners_counts_hidden_below_threshold_and_preview_is_audited(repo):
    """Одна запись словаря не отвечает, есть ли строка в текстах конкретного человека; оценка — в журнале."""
    admin = repo.create_user("admin", "hash", "admin")
    service = ChatService(repo)
    owners = [repo.create_user(f"user{n}", "hash", "user") for n in range(settings_impact.MIN_OWNERS)]
    for owner in owners[:-1]:
        service.add_input(repo.create_chat(owner, "Договор"), owner, "договор с Ромашка-Плюс")
    operation = {"kind": "add", "rows": [_row("always", "Ромашка-Плюс", "ORG")]}
    hidden = settings_impact.preview(repo, admin, operation)
    assert hidden["others"] is None
    service.add_input(repo.create_chat(owners[-1], "Договор"), owners[-1], "договор с Ромашка-Плюс")
    shown = settings_impact.preview(repo, admin, operation)
    assert shown["others"]["chats"] == settings_impact.MIN_OWNERS and shown["owners"] == settings_impact.MIN_OWNERS
    events = repo.audit_events("settings_previewed", user_id=admin)
    assert len(events) == 2 and events[0].details == {"kind": "add", "policies": 0, "added": 1, "removed": 0}
    assert "Ромашка" not in str([e.details for e in events])


def test_impact_http_requires_admin_and_displays_own_differences(boss, ivan, repo):
    chat = boss.chat()
    boss.post(f"/chats/{chat}/input", text="mail owner@contoso.ru")
    response = boss.post("/settings/policies", action="impact", **{"policy-EMAIL": "block"})
    assert response.status_code == 200 and "Подтвердить и применить" in response.text
    assert "скрыты" in response.text                     # чужих затронутых чатов нет — счётчиков нет
    assert repo.policies()[T.EMAIL] is Policy.MASK
    assert ivan.post("/settings/impact/undo").status_code == 403


def test_every_entity_type_is_in_exactly_one_policy_group():
    grouped = [type_ for _, types in routes_settings.POLICY_GROUPS for type_ in types]
    assert sorted(grouped) == sorted(T) and len(grouped) == len(set(grouped))


def test_policies_page_groups_types_marks_changes_and_resets_to_default(boss, repo):
    repo.set_policy(T.EMAIL, Policy.BLOCK)
    page = boss.get("/settings/policies").text
    for title, _ in routes_settings.POLICY_GROUPS:
        assert title in page
    assert page.count("изменено") == 1 and 'name="reset" value="EMAIL"' in page and "sticky-bottom" in page
    response = boss.post("/settings/policies", action="impact", reset="EMAIL", **{"policy-EMAIL": "block"})
    assert response.status_code == 200
    receipt = response.text.split('name="receipt" value="', 1)[1].split('"', 1)[0]
    assert boss.post("/settings/impact/apply", receipt=receipt).status_code == 303
    assert repo.policies()[T.EMAIL] is default_policies()[T.EMAIL]
