"""Предпросмотр последствий глобальных правок и отмена последней правки (идея аудита 21.10.2026)."""
import re

import pytest

from cleaner.core.types import EntityType as T
from cleaner.service import ChatService, EditRefused
from cleaner.storage.codec import state_to_json


@pytest.fixture
def chat(repo):
    user = repo.create_user("ivan", "hash", "user")
    return user, repo.create_chat(user, "Чат")


def sanitized(repo, chat_id: str) -> list[str]:
    return [item.sanitized for item in repo.items(chat_id) if item.kind == "input"]


def test_preview_counts_the_consequences_and_writes_nothing(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    first = service.add_input(chat_id, user, "Проект Заря запущен, Заря растёт")
    service.add_input(chat_id, user, "без проекта")
    service.add_answer(chat_id, user, "ответ облака")
    service.add_input(chat_id, user, "снова Заря")
    stored, version = state_to_json(repo.load_state(chat_id)[0]), repo.load_state(chat_id)[1]
    preview = service.mask_value(chat_id, user, first.id, "Заря", T.TERM, dry=True)
    # Ничего не записано: ни состояние, ни тексты, ни журнал правок, ни снимок отмены.
    assert (state_to_json(repo.load_state(chat_id)[0]), repo.load_state(chat_id)[1]) == (stored, version)
    assert sanitized(repo, chat_id) == ["Проект Заря запущен, Заря растёт", "без проекта", "снова Заря"]
    assert repo.audit_events("edit") == [] and repo.undo_action(chat_id) is None
    assert preview.version == version and [t.seq for t in preview.texts] == [1, 4]
    one, two = preview.texts
    assert (one.hidden, one.opened, one.relabeled, one.exposed, one.sent) == (2, 0, 0, 1, True)    # ответ — после него
    assert two.sent is False
    assert (one.before, one.after) == ("Проект Заря запущен, Заря растёт", "Проект <TERM_1> запущен, <TERM_1> растёт")


def test_example_is_a_window_around_the_first_difference(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "а" * 300 + " Заря " + "б" * 300)
    [change] = service.mask_value(chat_id, user, item.id, "Заря", T.TERM, dry=True).texts
    assert change.before == "…" + "а" * 39 + " Заря " + "б" * 39 + "…"
    assert change.after == "…" + "а" * 39 + " <TERM_1> " + "б" * 39 + "…"


def test_edit_after_a_preview_is_refused_when_the_chat_changed(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "Проект Заря")
    preview = service.mask_value(chat_id, user, item.id, "Заря", T.TERM, dry=True)
    service.add_input(chat_id, user, "ещё текст")              # новая запись состояния — другая версия чата
    with pytest.raises(EditRefused, match="Чат изменился"):
        service.mask_value(chat_id, user, item.id, "Заря", T.TERM, version=preview.version)
    assert sanitized(repo, chat_id)[0] == "Проект Заря"
    fresh = service.mask_value(chat_id, user, item.id, "Заря", T.TERM, dry=True)
    service.mask_value(chat_id, user, item.id, "Заря", T.TERM, version=fresh.version)
    assert sanitized(repo, chat_id)[0] == "Проект <TERM_1>"
    assert repo.audit_events("edit")[-1].details == {"action": "mask", "texts": 1}


def test_undoing_a_mask_keeps_its_label_for_that_value(repo, chat):
    """FR-5.2: текст с <TERM_1> мог уйти до отмены. Номер не возвращается в счётчик: новое значение получает
    <TERM_2>, ответ с <TERM_1> восстанавливается прежним значением, а то же значение снова получает <TERM_1>."""
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "Проект Заря и Восток")
    service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
    assert sanitized(repo, chat_id) == ["Проект <TERM_1> и Восток"]
    assert repo.undo_action(chat_id)[0] == "mask"
    raw = repo.conn.execute("SELECT undo_enc FROM chats WHERE id = ?", (chat_id,)).fetchone()[0]
    assert "Заря".encode() not in raw                           # снимок — под ключом чата (SEC-4)
    service.undo(chat_id, user)
    assert sanitized(repo, chat_id) == ["Проект Заря и Восток"]
    assert repo.undo_action(chat_id) is None and repo.audit_events("edit_undo")[0].details == {"action": "mask", "texts": 1}
    with pytest.raises(EditRefused, match="Отменять нечего"):
        service.undo(chat_id, user)
    service.mask_value(chat_id, user, item.id, "Восток", T.TERM)
    assert sanitized(repo, chat_id) == ["Проект Заря и <TERM_2>"]
    service.add_answer(chat_id, user, "Про <TERM_1>")
    assert service.view(chat_id).items[-1].result.text == "Про Заря"
    service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
    assert sanitized(repo, chat_id) == ["Проект <TERM_1> и <TERM_2>"]


def test_undoing_a_merge_brings_back_the_former_labels(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "Иванов и Ivanov")
    for value in ("Иванов", "Ivanov"):
        service.mask_value(chat_id, user, item.id, value, T.PERSON)
    state, _ = repo.load_state(chat_id)
    first, second = sorted((e for e in state.entities.values() if e.type is T.PERSON), key=lambda e: e.number)
    preview = service.merge(chat_id, user, first.id, second.id, dry=True)
    assert [(t.hidden, t.opened, t.relabeled) for t in preview.texts] == [(0, 0, 1)]
    service.merge(chat_id, user, first.id, second.id, version=preview.version)
    assert sanitized(repo, chat_id) == ["<PERSON_1> и <PERSON_1>"]
    back = service.undo(chat_id, user, dry=True)
    assert back.action == "merge" and [t.relabeled for t in back.texts] == [1]
    service.undo(chat_id, user, version=back.version)
    assert sanitized(repo, chat_id) == ["<PERSON_1> и <PERSON_2>"]


def test_undoing_a_retype_and_an_unmask(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "почта a@x.example")
    email = next(iter(repo.load_state(chat_id)[0].entities.values()))
    service.retype(chat_id, user, email.id, T.TERM)
    assert sanitized(repo, chat_id) == ["почта <TERM_1>"]
    service.undo(chat_id, user)
    assert sanitized(repo, chat_id) == ["почта <EMAIL_1>"]
    service.unmask(chat_id, user, ["a@x.example"])
    assert sanitized(repo, chat_id) == ["почта a@x.example"]
    service.undo(chat_id, user)
    [stored] = repo.items(chat_id)
    # Вариант без замены мог уйти открытым — после отмены значение снова скрывается, и текст помечен (FR-6.8).
    assert (stored.id, stored.sanitized, stored.exposed) == (item.id, "почта <EMAIL_1>", [email.id])


def test_undo_is_refused_once_the_chat_was_written_after_the_edit(repo, chat):
    """Снимок не содержит того, что появилось после правки: отмена отказывает, а не теряет новые замены."""
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "Проект Заря")
    service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
    service.add_input(chat_id, user, "почта a@x.example")
    assert repo.undo_action(chat_id) is None
    with pytest.raises(EditRefused, match="после неё в чате записано новое"):
        service.undo(chat_id, user, dry=True)
    with pytest.raises(EditRefused, match="после неё в чате записано новое"):
        service.undo(chat_id, user)
    assert sanitized(repo, chat_id) == ["Проект <TERM_1>", "почта <EMAIL_1>"]
    with pytest.raises(EditRefused, match="Отменять нечего"):     # устаревший снимок стёрт
        service.undo(chat_id, user)


def test_only_the_last_edit_is_undone(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "Заря и Восток")
    service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
    service.mask_value(chat_id, user, item.id, "Восток", T.TERM)
    service.undo(chat_id, user)
    assert sanitized(repo, chat_id) == ["<TERM_1> и Восток"]
    service.refresh(chat_id, user)                              # не правка правил: снимка не оставляет
    assert repo.undo_action(chat_id) is None


# --- веб ------------------------------------------------------------------------------


def first_item(repo, chat_id: str) -> str:
    return repo.items(chat_id)[0].id


def hidden(page: str, name: str) -> str:
    return re.search(rf'<input type="hidden" name="{name}" value="([^"]*)">', page).group(1)


def test_review_buttons_lead_to_the_preview_and_the_confirmation_applies_it(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Проект Заря")
    ivan.post(f"/chats/{chat_id}/input", text="снова Заря")
    item_id = first_item(repo, chat_id)
    review = ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert f'action="/chats/{chat_id}/mask/preview"' in review and "Отменить последнюю правку" not in review
    preview = ivan.post(f"/chats/{chat_id}/mask/preview", item_id=item_id, value="Заря", type="TERM")
    assert preview.status_code == 200 and "текстов изменится — 2" in preview.text
    assert "Скрывать во всём чате «Заря» как «Термин»" in preview.text and "&lt;TERM_1&gt;" in preview.text
    assert f'action="/chats/{chat_id}/mask"' in preview.text and hidden(preview.text, "value") == "Заря"
    assert [i.sanitized for i in repo.items(chat_id)] == ["Проект Заря", "снова Заря"]       # предпросмотр не пишет
    done = ivan.post(
        f"/chats/{chat_id}/mask", item_id=item_id, value="Заря", type="TERM", version=hidden(preview.text, "version"),
    )
    assert done.headers["location"] == f"/chats/{chat_id}/items/{item_id}"
    assert [i.sanitized for i in repo.items(chat_id)] == ["Проект <TERM_1>", "снова <TERM_1>"]
    review = ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert f'action="/chats/{chat_id}/undo/preview"' in review and "Отменить последнюю правку…" in review
    assert f'action="/chats/{chat_id}/unmask/preview"' in review and "Снять замену во всём чате…" in review
    back = ivan.post(f"/chats/{chat_id}/undo/preview", item_id=item_id)
    assert "Отменить последнюю правку: скрыть значение во всём чате" in back.text and "Отменить правку</button>" in back.text
    ivan.post(f"/chats/{chat_id}/undo", item_id=item_id, version=hidden(back.text, "version"))
    assert [i.sanitized for i in repo.items(chat_id)] == ["Проект Заря", "снова Заря"]


def test_stale_confirmation_is_refused(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Проект Заря")
    item_id = first_item(repo, chat_id)
    preview = ivan.post(f"/chats/{chat_id}/unmask/preview", item_id=item_id, value="Заря").text
    ivan.post(f"/chats/{chat_id}/input", text="ещё")
    refused = ivan.post(f"/chats/{chat_id}/unmask", item_id=item_id, value="Заря", version=hidden(preview, "version"))
    assert refused.status_code == 400 and "Чат изменился" in refused.text
    assert ivan.post(f"/chats/{chat_id}/unmask", item_id=item_id, value="Заря", version="x").status_code == 400


def test_entity_table_edits_lead_to_the_preview(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="a@x.example b@x.example")
    table = ivan.get(f"/chats/{chat_id}/entities", type="EMAIL").text
    state, _ = repo.load_state(chat_id)
    first, second = sorted(state.entities.values(), key=lambda e: e.number)
    for path in (f"entities/{first.id}/unmask", f"entities/{first.id}/retype", "entities/merge"):
        assert f'action="/chats/{chat_id}/{path}/preview"' in table, path
    merge = ivan.post(f"/chats/{chat_id}/entities/merge/preview", keep=first.id, surrogate="<EMAIL_2>", back="type=EMAIL")
    assert "Присоединить &lt;EMAIL_2&gt; к &lt;EMAIL_1&gt;" in merge.text and "сменится замена у вхождений — 1" in merge.text
    assert hidden(merge.text, "back") == "type=EMAIL" and 'href="/chats/' + chat_id + '/entities?type=EMAIL"' in merge.text
    retype = ivan.post(f"/chats/{chat_id}/entities/{first.id}/retype/preview", type="TERM").text
    assert "Сменить тип &lt;EMAIL_1&gt; на «Термин»" in retype
    unmask = ivan.post(f"/chats/{chat_id}/entities/{first.id}/unmask/preview").text
    assert "открыто станет вхождений — 1" in unmask and "a@x.example &lt;EMAIL_2&gt;" in unmask
    assert ivan.post(f"/chats/{chat_id}/entities/missing/retype/preview", type="TERM").status_code == 404
    ivan.post(f"/chats/{chat_id}/entities/{first.id}/unmask", version=hidden(unmask, "version"))
    assert "Отменить последнюю правку…" in ivan.get(f"/chats/{chat_id}/entities").text
