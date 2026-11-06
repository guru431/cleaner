"""Shared previews never disclose another owner's text or mutate a chat."""
import pytest

from cleaner import settings_impact
from cleaner.core.types import EntityType as T, Policy
from cleaner.service import ChatService


def test_impact_is_read_only_private_and_can_be_rolled_back(repo):
    admin = repo.create_user("admin", "hash", "admin")
    other = repo.create_user("other", "hash", "user")
    chat = repo.create_chat(other, "Private")
    service = ChatService(repo)
    service.add_input(chat, other, "mail private.person@contoso.ru")
    state, version = repo.load_state(chat)
    operation = {"kind": "policies", "policies": {"EMAIL": "block"}}
    shown = settings_impact.preview(repo, admin, operation)
    assert shown["counts"]["chats"] == shown["counts"]["items"] == shown["counts"]["blocked"] == 1
    assert shown["own"] == [] and "private.person" not in str(shown)
    assert repo.load_state(chat)[1] == version and repo.policies()[T.EMAIL] is Policy.MASK
    settings_impact.apply(repo, admin, shown["receipt"])
    assert repo.policies()[T.EMAIL] is Policy.BLOCK and repo.load_state(chat)[1] == version
    with pytest.raises(ValueError, match="изменились"):
        settings_impact.apply(repo, admin, shown["receipt"])
    undo = settings_impact.preview(repo, admin, {"kind": "undo"})
    settings_impact.apply(repo, admin, undo["receipt"])
    assert repo.policies()[T.EMAIL] is Policy.MASK


def test_changed_chat_or_settings_invalidates_confirmation(repo):
    owner = repo.create_user("admin", "hash", "admin")
    chat = repo.create_chat(owner, "Own")
    shown = settings_impact.preview(repo, owner, {"kind": "policies", "policies": {"EMAIL": "off"}})
    ChatService(repo).add_input(chat, owner, "new text")
    with pytest.raises(ValueError, match="изменились"):
        settings_impact.apply(repo, owner, shown["receipt"])
    assert repo.policies()[T.EMAIL] is Policy.MASK


def test_impact_http_requires_admin_and_displays_own_differences(boss, ivan, repo):
    chat = boss.chat()
    boss.post(f"/chats/{chat}/input", text="mail owner@contoso.ru")
    response = boss.post("/settings/policies", action="impact", **{"policy-EMAIL": "block"})
    assert response.status_code == 200 and "Подтвердить и применить" in response.text
    assert repo.policies()[T.EMAIL] is Policy.MASK
    assert ivan.post("/settings/impact/undo").status_code == 403
