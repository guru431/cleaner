import pytest

from cleaner.core import leakcheck
from cleaner.core.detect import infra
from cleaner.core.detect.base import DetectorError
from cleaner.core.leakcheck import Leak
from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
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


def in_request(service: ChatService, chat_id: str) -> list[int | None]:
    return [e.result.counters.get("in_request") for e in service.view(chat_id).items if isinstance(e, AnswerView)]


def test_replacements_in_the_request_are_counted_since_the_previous_answer(repo, chat):
    """FR-7.5, решение владельца 15.10.2026: «замен в запросе» — замены во входных текстах после предыдущего ответа
    (у первого — с начала чата), а не размер таблицы замен чата: здесь в ней 2, затем 3 замены."""
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "почта a@x.example и b@x.example")
    service.add_input(chat_id, user, "снова a@x.example")
    service.add_answer(chat_id, user, "Ответ про <EMAIL_1>")
    service.add_input(chat_id, user, "ещё c@x.example")
    service.add_answer(chat_id, user, "Ответ про <EMAIL_3>")
    service.add_answer(chat_id, user, "Ещё ответ без нового вопроса")
    assert in_request(service, chat_id) == [3, 1, 0]


def test_pasted_answer_audit_has_the_replacements_of_its_request(repo, chat):
    """FR-11.1: «замен в запросе» — и в записи журнала о восстановлении вставленного ответа, как в чате."""
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "почта a@x.example и b@x.example")
    service.add_answer(chat_id, user, "Ответ про <EMAIL_1>")
    service.add_input(chat_id, user, "ещё c@x.example")
    service.add_answer(chat_id, user, "Ответ про <EMAIL_3>")
    assert [e.details["in_request"] for e in reversed(repo.audit_events("restore"))] == in_request(service, chat_id) == [2, 1]


def test_instruction_before_an_answer_is_part_of_its_request(repo, chat):
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "почта a@x.example")
    service.add_answer(chat_id, user, "Ответ")
    service.add_input(chat_id, user, "Копию пиши на b@x.example и c@x.example", source="instruction")
    service.add_answer(chat_id, user, "Ответ")
    assert in_request(service, chat_id) == [1, 2]


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


def test_view_does_not_repeat_the_leak_check_while_nothing_changed(repo, chat, monkeypatch):
    """Вид чата строится при каждой загрузке страниц чата, проверки и таблицы замен, а проверка утечек линейна по
    тексту: пять текстов по 100 000 знаков — 0,45 с на каждую загрузку. Повторный вид без изменений её не повторяет."""
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "почта a@x.example")
    service.add_input(chat_id, user, "почта b@x.example")
    calls = []
    check = leakcheck.check
    monkeypatch.setattr(leakcheck, "check", lambda *args: calls.append(args[0]) or check(*args))
    service.view(chat_id)
    service.view(chat_id)
    assert calls == ["почта <EMAIL_1>", "почта <EMAIL_2>"]


def test_remembered_leak_checks_are_bounded_by_their_findings(repo, chat, monkeypatch):
    """Память ограничена и числом находок: один текст с тысячами находок иначе занял бы её сам. Итог, который не
    помещается, не запоминается — и проверяется заново, с тем же результатом."""
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "Ромашка и снова Ромашка")
    service.add_input(chat_id, user, "почта b@x.example")
    repo.add_dictionary("always", "Ромашка", T.ORG)
    monkeypatch.setattr("cleaner.service._VIEW_FOUND", 1)
    calls = []
    check = leakcheck.check
    monkeypatch.setattr(leakcheck, "check", lambda *args: calls.append(args[0]) or check(*args))
    assert [len(entry.leaks) for entry in service.view(chat_id).items] == [2, 0]
    assert [len(entry.leaks) for entry in service.view(chat_id).items] == [2, 0]
    assert calls == ["Ромашка и снова Ромашка", "почта <EMAIL_1>", "Ромашка и снова Ромашка"]


def test_view_checks_again_after_any_change_the_check_depends_on(repo, chat):
    """Проверку утечек пропустить нельзя: она зависит от очищенного текста, состояния чата и общих настроек, и каждое
    их изменение видно в следующем виде, хотя прежний результат уже запомнен."""
    user, chat_id = chat
    service = ChatService(repo)
    service.add_input(chat_id, user, "клиент Ромашка, почта a@x.example")
    service.add_input(chat_id, user, "почта b@x.example")

    def leaks() -> list[int]:
        return [len(entry.leaks) for entry in service.view(chat_id).items]

    assert leaks() == [0, 0]
    repo.add_dictionary("always", "Ромашка", T.ORG)                  # словарь; второй текст — свой результат
    assert leaks() == [1, 0]
    repo.set_policy(T.ORG, Policy.OFF)                               # политика типа
    assert leaks() == [0, 0]
    repo.set_policy(T.ORG, Policy.MASK)
    assert leaks() == [1, 0]
    never = repo.add_dictionary("never", "ромашка")                  # список «никогда не скрывать»
    assert leaks() == [0, 0]
    repo.delete_dictionary(never)
    assert leaks() == [1, 0]
    sanitized = repo.items(chat_id)[0].sanitized
    service.unmask(chat_id, user, ["Ромашка"])                       # состояние чата: правило «открыть»
    assert repo.items(chat_id)[0].sanitized == sanitized and leaks() == [0, 0]


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


def test_file_text_over_the_limit_is_refused_before_it_is_stored(repo, chat, engines, monkeypatch):
    """Обзор плана 2+4, I-6: длинный текст файла не сохраняется, «Повторить» не предлагается; огромный журнал
    отклоняется по размеру, не тратя время на определение кодировки."""
    from cleaner.ingest import textfiles
    from cleaner.web.routes_chats import can_retry

    user, chat_id = chat
    service = ChatService(repo, max_text_chars=20, engines=engines)
    item = service.add_file(chat_id, user, "big.log", ("строка " * 5).encode("utf-8"))
    stored = repo.item(chat_id, item.id)
    assert (stored.status, stored.original, stored.meta["error"]) == ("failed", "", "текст длиннее 20 знаков")
    assert not can_retry(stored)

    def never(data):
        raise AssertionError("кодировка огромного файла не определяется")

    monkeypatch.setattr(textfiles, "decode", never)
    huge = service.add_file(chat_id, user, "huge.log", b"x" * 81)
    assert repo.item(chat_id, huge.id).meta["error"] == "текст длиннее 20 знаков"


def test_key_error_from_a_layer_fails_the_text_instead_of_leaving_it_running(repo, chat, engines, with_ner):
    """Обзор плана 2+4, m-1: KeyError слоя — не «чат удалён»: элемент не висит «в работе», ошибка в журнале."""
    user, chat_id = chat

    def broken(text, ctx=None):
        raise KeyError("ner")

    engines.ner_layer.detect = broken
    service = ChatService(repo, engines=engines)
    item = service.add_input(chat_id, user, "почта a@x.example")
    assert (item.status, item.meta["error"]) == ("failed", "Внутренняя ошибка очистки: текст не обработан и никуда не передан")
    assert [e.details for e in repo.audit_events("error")] == [{"kind": "KeyError", "stage": "process"}]
    engines.ner_layer = type(engines.ner_layer)()
    done = service.add_input(chat_id, user, "почта b@x.example")
    engines.completer.error = KeyError("guesses")
    service.check_risk(chat_id, user, done.id)
    assert repo.item(chat_id, done.id).risk_status == "failed"


GUESS = '{"guesses": [{"kind": "org", "guess": "Ромашка", "clue": ""}]}'


def test_risk_guesses_are_cleared_when_the_cleaned_text_changes(repo, chat, engines, with_ner):
    """Обзор плана 2+4, m-2: догадки относятся к прежнему очищенному тексту — правка и «Очистить заново»
    их стирают; правка, не изменившая текст, — нет."""
    user, chat_id = chat
    service = ChatService(repo, engines=engines)
    item = service.add_input(chat_id, user, "Проект Заря, отдел Восток")
    engines.completer.answers = [GUESS, GUESS]
    service.check_risk(chat_id, user, item.id)
    service.refresh(chat_id, user)
    assert repo.item_risk(chat_id, item.id)["guesses"][0]["guess"] == "Ромашка"
    service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
    stored = repo.item(chat_id, item.id)
    assert (stored.sanitized, stored.risk_status, repo.item_risk(chat_id, item.id)) == ("Проект <TERM_1>, отдел Восток", "", None)
    service.check_risk(chat_id, user, item.id)
    engines.ner_layer.marks = {"Восток": T.ORG}
    service.retry(chat_id, user, item.id)
    stored = repo.item(chat_id, item.id)
    assert (stored.sanitized, stored.risk_status, repo.item_risk(chat_id, item.id)) == ("Проект <TERM_1>, отдел <ORG_1>", "", None)


def test_guesses_of_a_check_overtaken_by_an_edit_are_not_stored(repo, chat, engines):
    """Обзор плана 2+4, m-2: пока модель думала, текст изменили — её догадки о прежнем тексте не записываются."""
    user, chat_id = chat
    service = ChatService(repo, engines=engines)
    item = service.add_input(chat_id, user, "Проект Заря запущен")

    def edited_meanwhile(sanitized):
        service.mask_value(chat_id, user, item.id, "Заря", T.TERM)
        return []

    engines.risk = lambda: edited_meanwhile
    service.check_risk(chat_id, user, item.id)
    stored = repo.item(chat_id, item.id)
    assert (stored.sanitized, stored.risk_status, repo.item_risk(chat_id, item.id)) == ("Проект <TERM_1> запущен", "", None)
    assert repo.audit_events("risk_check") == []


def test_double_click_queues_the_text_and_the_check_once(repo, chat, engines, monkeypatch):
    """Обзор плана 2+4, m-10: два запроса прочли «готово» раньше, чем любой из них поставил задание в очередь."""
    user, chat_id = chat
    queue = []
    service = ChatService(repo, engines=engines, submit=lambda fn, *args: queue.append(fn))
    item = repo.add_item(chat_id, Item("a" * 32, 0, "input", "Проект Заря", "Проект Заря"))
    monkeypatch.setattr(repo, "item", lambda chat_id_, item_id: item)
    service.check_risk(chat_id, user, item.id)
    with pytest.raises(EditRefused):
        service.check_risk(chat_id, user, item.id)
    service.retry(chat_id, user, item.id)
    with pytest.raises(EditRefused):
        service.retry(chat_id, user, item.id)
    assert queue == [service.run_risk, service.process]


def test_edit_keeps_items_cleaned_before_layers_4_and_5_unmarked(repo, chat):
    """Обзор плана 2+4, m-12: у текста этапа 1 нет отметки о слоях — правка не приписывает ему «слои выключены»."""
    user, chat_id = chat
    state, version = repo.load_state(chat_id)
    repo.commit_chat(chat_id, state, version, [Item("b" * 32, 0, "input", "Проект Заря", "Проект Заря")])
    ChatService(repo).mask_value(chat_id, user, "b" * 32, "Заря", T.TERM)
    stored = repo.item(chat_id, "b" * 32)
    assert (stored.sanitized, stored.meta) == ("Проект <TERM_1>", {})
