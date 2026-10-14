import pytest

from cleaner.core import leakcheck
from cleaner.core.detect import infra
from cleaner.core.detect.base import DetectorError
from cleaner.core.leakcheck import Leak
from cleaner.core.types import EntityType as T
from cleaner.service import AnswerView, ChatService, EditRefused, InputView, TextTooLong
from cleaner.storage.codec import state_to_json
from cleaner.storage.repo import Item, StaleState


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
    assert event.details == {
        "replaced": {"EMAIL": 1}, "notices": 0, "leaks": 0, "blocked": 0, "source": "paste", "layers": [],
    }


def test_failing_layer_fails_the_text_and_leaves_the_chat_untouched(repo, chat, monkeypatch):
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "почта a@x.example")
    state_before = state_to_json(repo.load_state(chat_id)[0])

    def broken(text, ctx):
        raise RuntimeError("слой сломан: a@x.example")

    monkeypatch.setattr(infra, "detect", broken)
    item = service.add_input(chat_id, user, "узел 10.1.2.5")
    assert (item.status, item.sanitized) == ("failed", None)
    assert item.meta["error"].startswith("Внутренняя ошибка очистки")
    assert state_to_json(repo.load_state(chat_id)[0]) == state_before
    [event] = repo.audit_events("error")
    assert event.details == {"kind": "RuntimeError", "stage": "process"}


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


def test_endless_conflict_fails_the_text(repo, chat, monkeypatch):
    user, chat_id = chat

    def always_stale(*args, **kwargs):
        raise StaleState(chat_id)

    monkeypatch.setattr(repo, "commit_chat", always_stale)
    item = ChatService(repo).add_input(chat_id, user, "текст")
    assert (item.status, item.meta["error"]) == (
        "failed", "Чат меняли одновременно, текст не обработан — запустите его ещё раз",
    )


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


@pytest.fixture
def with_ner(repo):
    repo.set_layer_defaults({"ner": True, "llm": False})


def test_input_waits_in_the_queue_until_the_job_runs(repo, chat, engines, with_ner):
    user, chat_id = chat
    queue = []
    service = ChatService(repo, engines=engines, submit=lambda fn, *args: queue.append((fn, args)))
    item = service.add_input(chat_id, user, "почта a@x.example")
    assert (item.status, item.sanitized) == ("queued", None)
    fn, args = queue.pop()
    fn(*args)
    [stored] = repo.items(chat_id)
    assert (stored.status, stored.sanitized, stored.meta) == ("done", "почта <EMAIL_1>", {"layers": ["ner"]})


def test_editing_reuses_layer_4_findings_without_calling_the_model(repo, chat, engines, with_ner):
    """Обзор плана 2+4, пункт 5: правка — секунды, а не минуты ожидания модели."""
    user, chat_id = chat
    engines.ner_layer.marks = {"Петров": T.PERSON}
    service = ChatService(repo, engines=engines)
    item = service.add_input(chat_id, user, "Петров, проект Заря")
    service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
    assert engines.ner_layer.calls == 1
    assert repo.items(chat_id)[0].sanitized == "<PERSON_1>, проект <TERM_1>"


def test_unavailable_enabled_layer_fails_the_text(repo, chat, engines, with_ner):
    """FR-3.7: включённый слой недоступен — результата нет, состояние чата прежнее."""
    user, chat_id = chat
    engines.unavailable = "Слой 4 недоступен: модели не загружены"
    service = ChatService(repo, engines=engines)
    state_before = state_to_json(repo.load_state(chat_id)[0])
    item = service.add_input(chat_id, user, "почта a@x.example")
    assert (item.status, item.sanitized, item.meta["error"]) == ("failed", None, "Слой 4 недоступен: модели не загружены")
    assert state_to_json(repo.load_state(chat_id)[0]) == state_before


def test_disabled_layer_is_skipped_and_recorded(repo, chat, engines, with_ner):
    user, chat_id = chat
    engines.ner_layer.marks = {"Петров": T.PERSON, "Сидоров": T.PERSON}
    service = ChatService(repo, engines=engines)
    service.add_input(chat_id, user, "Петров")
    service.set_layer(chat_id, user, "ner", False)
    service.refresh(chat_id, user)
    first = repo.items(chat_id)[0]
    # Известное значение чата ищется и без слоя 4 (FR-3.4), а отметка о слоях — честная.
    assert (first.sanitized, first.meta["layers"]) == ("<PERSON_1>", [])
    second = service.add_input(chat_id, user, "Сидоров")
    assert (second.sanitized, second.meta["layers"], engines.ner_layer.calls) == ("Сидоров", [], 1)
    assert service.layers(chat_id) == {"ner": False, "llm": False}
    assert [e.details for e in repo.audit_events("layer_changed")] == [{"layer": "ner", "enabled": False}]
    with pytest.raises(EditRefused):
        service.set_layer(chat_id, user, "rules", False)


def test_layer_5_reads_the_text_cleaned_by_the_other_layers(repo, chat, engines, with_ner):
    user, chat_id = chat
    engines.second.marks = {"sunflower77": T.SECRET}
    service = ChatService(repo, engines=engines)
    service.set_layer(chat_id, user, "llm", True)
    item = service.add_input(chat_id, user, "a@x.example, на стикере sunflower77")
    assert engines.second.seen == ["<EMAIL_1>, на стикере sunflower77"]
    assert (item.sanitized, item.meta["layers"]) == ("<EMAIL_1>, на стикере <SECRET_1>", ["ner", "llm"])


def test_failed_text_can_be_run_again(repo, chat, engines, with_ner):
    user, chat_id = chat
    engines.unavailable = "Слой 4 недоступен"
    service = ChatService(repo, engines=engines)
    item = service.add_input(chat_id, user, "почта a@x.example")
    engines.unavailable = None
    service.retry(chat_id, user, item.id)
    assert repo.item(chat_id, item.id).sanitized == "почта <EMAIL_1>"
    with pytest.raises(KeyError):
        service.retry(chat_id, user, "0" * 32)


def test_text_in_progress_cannot_be_retried_or_edited(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    item = repo.add_item(chat_id, Item("a" * 32, 0, "input", "проект Заря", None, status="running"))
    with pytest.raises(EditRefused):
        service.retry(chat_id, user, item.id)
    with pytest.raises(EditRefused):
        service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
    [entry] = service.view(chat_id).items
    assert not entry.deliverable


def test_extracted_text_is_kept_when_cleaning_fails_so_it_can_be_retried(repo, chat, engines, with_ner):
    user, chat_id = chat
    service = ChatService(repo, engines=engines)
    original_ner = engines.ner

    def broken_ner():
        raise DetectorError("Слой 4 недоступен")

    engines.ner = broken_ner
    item = service.add_file(chat_id, user, "letter.eml", b"From: a@x.example\n\nbody")
    stored = repo.item(chat_id, item.id)
    assert (stored.status, stored.original, stored.meta["kind"]) == ("failed", "Документ: почта doc@x.example", "eml")
    engines.ner = original_ner
    service.retry(chat_id, user, item.id)
    assert repo.item(chat_id, item.id).sanitized == "Документ: почта <EMAIL_1>"
