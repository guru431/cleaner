import pytest

from cleaner.core import leakcheck
from cleaner.core.detect import infra
from cleaner.core.leakcheck import Leak
from cleaner.core.types import EntityType as T
from cleaner.service import AnswerView, ChatService, EditRefused, InputView, TextTooLong
from cleaner.storage.codec import state_to_json
from cleaner.storage.repo import StaleState


@pytest.fixture
def chat(repo):
    user = repo.create_user("ivan", "hash", "user")
    return user, repo.create_chat(user, "Чат")


def test_input_is_sanitized_stored_and_logged_without_the_text(repo, chat):
    user, chat_id = chat
    item = ChatService(repo).add_input(chat_id, user, "почта a@x.example")
    assert item.sanitized == "почта <EMAIL_1>"
    assert [i.sanitized for i in repo.items(chat_id)] == ["почта <EMAIL_1>"]
    [event] = repo.audit_events("sanitize")
    assert event.details == {"replaced": {"EMAIL": 1}, "notices": 0, "leaks": 0, "blocked": 0}


def test_failing_layer_leaves_the_chat_untouched(repo, chat, monkeypatch):
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "почта a@x.example")
    state_before = state_to_json(repo.load_state(chat_id)[0])
    items_before = repo.items(chat_id)

    def broken(text, ctx):
        raise RuntimeError("слой сломан")

    monkeypatch.setattr(infra, "detect", broken)
    with pytest.raises(RuntimeError):
        service.add_input(chat_id, user, "узел 10.1.2.5")
    assert state_to_json(repo.load_state(chat_id)[0]) == state_before
    assert repo.items(chat_id) == items_before


def test_concurrent_change_is_retried_on_fresh_state(repo, chat, monkeypatch):
    user, chat_id = chat
    service = ChatService(repo)
    commit = repo.commit_chat
    interfered = []

    def someone_was_faster(chat_id_, state, version, new_items=(), updated_items=()):
        if not interfered:
            interfered.append(True)
            fresh, fresh_version = repo.load_state(chat_id_)
            commit(chat_id_, fresh, fresh_version)
        return commit(chat_id_, state, version, new_items, updated_items)

    monkeypatch.setattr(repo, "commit_chat", someone_was_faster)
    service.add_input(chat_id, user, "почта a@x.example")
    assert [i.sanitized for i in repo.items(chat_id)] == ["почта <EMAIL_1>"]


def test_endless_conflict_gives_up(repo, chat, monkeypatch):
    user, chat_id = chat

    def always_stale(*args, **kwargs):
        raise StaleState(chat_id)

    monkeypatch.setattr(repo, "commit_chat", always_stale)
    with pytest.raises(StaleState):
        ChatService(repo).add_input(chat_id, user, "текст")


def test_answer_is_restored_in_the_view(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "почта a@x.example")
    service.add_answer(chat_id, user, "Ответьте на <EMAIL_1>")
    first, second = service.view(chat_id).items
    assert isinstance(first, InputView) and first.deliverable
    assert isinstance(second, AnswerView) and second.result.text == "Ответьте на a@x.example"


def test_masking_a_value_marks_texts_where_it_was_open(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "Проект Заря запущен")
    service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
    [stored] = repo.items(chat_id)
    assert stored.sanitized == "Проект <TERM_1> запущен"
    state, _ = repo.load_state(chat_id)
    assert [state.entities[e].restore_value for e in stored.exposed] == ["Заря"]


def test_unmask_retype_merge_and_restore_value(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "Иванов и Ivanov, почта a@x.example")
    service.mask_value(chat_id, user, item.id, "Иванов", T.PERSON)
    service.mask_value(chat_id, user, item.id, "Ivanov", T.PERSON)
    service.unmask(chat_id, user, ["a@x.example", "  "])
    state, _ = repo.load_state(chat_id)
    first, second = sorted((e for e in state.entities.values() if e.type is T.PERSON), key=lambda e: e.number)
    service.merge(chat_id, user, first.id, second.id)
    service.set_restore_value(chat_id, user, first.id, "Иванов И. И.")
    assert repo.items(chat_id)[0].sanitized == "<PERSON_1> и <PERSON_1>, почта a@x.example"
    service.add_answer(chat_id, user, "Пишет <PERSON_1>")
    assert service.view(chat_id).items[-1].result.text == "Пишет Иванов И. И."
    email = next(e for e in state.entities.values() if e.type is T.EMAIL)
    service.retype(chat_id, user, email.id, T.TERM)
    assert len(repo.audit_events("edit")) == 6


def test_blank_or_absent_fragment_is_refused(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = service.add_input(chat_id, user, "Проект Заря")
    for value in ("   ", "нет в тексте"):
        with pytest.raises(EditRefused):
            service.mask_value(chat_id, user, item.id, value, T.TERM)
    with pytest.raises(EditRefused):
        service.unmask(chat_id, user, [" "])
    with pytest.raises(KeyError):
        service.set_restore_value(chat_id, user, "нет-такой-сущности", "x")


def test_leaks_are_logged_on_sanitizing_and_on_refresh(repo, chat, monkeypatch):
    user, chat_id = chat
    service = ChatService(repo)
    monkeypatch.setattr(leakcheck, "check", lambda text, state, settings: [Leak(0, 1, None)])
    service.add_input(chat_id, user, "клиент")
    service.refresh(chat_id, user)
    assert [e.details for e in repo.audit_events("leak")] == [{"count": 1}, {"count": 1}]


def test_text_over_the_limit_is_refused(repo, chat):
    user, chat_id = chat
    with pytest.raises(TextTooLong):
        ChatService(repo, max_text_chars=10).add_input(chat_id, user, "x" * 11)


def test_refresh_applies_a_new_dictionary_value(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "клиент Ромашка")
    repo.add_dictionary("always", "Ромашка", T.ORG)
    assert not service.view(chat_id).items[0].deliverable
    service.refresh(chat_id, user)
    assert repo.items(chat_id)[0].sanitized == "клиент <ORG_1>"
    assert service.view(chat_id).items[0].deliverable
