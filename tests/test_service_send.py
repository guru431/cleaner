"""Отправка облачной модели и вопрос локальной модели (FR-8, FR-9.4) на уровне службы. Облако подменено."""
import pytest

from cleaner.core.types import EntityType as T
from cleaner.egress import ProviderError, cloud
from cleaner.service import AnswerView, ChatService, SendRefused
from cleaner.storage.repo import Item, Provider

KEY = "sk-test-0123456789abcd"


class FakeCloud:
    """Облако для тестов: запоминает запросы и отдаёт заданные фрагменты; может оборвать поток ошибкой."""

    def __init__(self, *pieces: str, error: Exception | None = None, stop_after: int | None = None, truncated=False):
        self.pieces, self.error, self.stop_after, self.truncated = pieces, error, stop_after, truncated
        self.calls: list[tuple] = []

    def __call__(self, ctx, connection, state, settings, *, cancel=None, outcome=None, transport=None, on_open=None):
        self.calls.append((ctx, connection, state is not None))
        for number, piece in enumerate(self.pieces):
            if cancel is not None and cancel.is_set():
                return
            yield piece
            if self.stop_after == number + 1:
                cancel.set()                     # пользователь нажал «Остановить»
        if self.truncated and outcome is not None:
            outcome["truncated"] = True
        if self.error is not None:
            raise self.error


@pytest.fixture
def chat(repo):
    user = repo.create_user("ivan", "hash", "user")
    return user, repo.create_chat(user, "Чат")


@pytest.fixture
def provider(repo):
    provider_id = repo.add_provider(Provider("", "Облако", "openai", "https://llm.example/v1", "bearer", KEY, ("m-1",), 512))
    return repo.provider(provider_id)


def service_with(repo, fake, **kwargs) -> ChatService:
    return ChatService(repo, cloud_send=fake, **kwargs)


def ready(repo, chat, provider, fake, text="Вопрос: почта a@x.example", **kwargs) -> ChatService:
    user, chat_id = chat
    service = service_with(repo, fake, **kwargs)
    service.add_input(chat_id, user, text)
    service.set_provider(chat_id, provider.id, "m-1")
    return service


def send(service, chat):
    user, chat_id = chat
    return service.send(chat_id, user, service.outgoing(chat_id).outgoing.context.digest())


def answer(repo, chat):
    return [item for item in repo.items(chat[1]) if item.kind == "answer"][-1]


def test_send_records_a_running_answer_and_finishes_it(repo, chat, provider):
    fake = FakeCloud("Ответ: ", "пишите на <EMAIL_1>")
    service = ready(repo, chat, provider, fake)
    item = send(service, chat)
    assert (item.source, item.status) == ("api", "running")
    stored = answer(repo, chat)
    assert (stored.status, stored.original, stored.meta) == ("done", "Ответ: пишите на <EMAIL_1>", {"provider": "Облако", "model": "m-1"})
    [(ctx, connection, checked)] = fake.calls
    assert checked and connection.api_key == KEY and ctx.model == "m-1"
    assert "a@x.example" not in " ".join(ctx.texts()) and ctx.messages[-1].text == "Вопрос: почта <EMAIL_1>"
    assert service.view(chat[1]).items[-1].result.text == "Ответ: пишите на a@x.example"
    assert service.live.get(item.id) is None


def test_audit_has_no_text_or_key(repo, chat, provider):
    service = ready(repo, chat, provider, FakeCloud("Ответ <EMAIL_1>"))
    send(service, chat)
    [sent] = repo.audit_events("cloud_send")
    assert sent.details == {"provider": provider.id, "model": "m-1", "messages": 1, "chars": sent.details["chars"], "excluded": 0}
    everything = repr([event.details for event in repo.audit_events()])
    assert "a@x.example" not in everything and KEY not in everything and "Ответ" not in everything
    assert repo.audit_events("restore")[0].details["restored"] == 1


def test_send_refuses_when_the_digest_differs(repo, chat, provider):
    service = ready(repo, chat, provider, FakeCloud("x"))
    with pytest.raises(SendRefused, match="изменился"):
        service.send(chat[1], chat[0], "0" * 64)
    assert [item.kind for item in repo.items(chat[1])] == ["input"]


def test_send_refuses_without_a_connection_or_while_a_text_is_processing(repo, chat, provider):
    user, chat_id = chat
    service = service_with(repo, FakeCloud("x"))
    service.add_input(chat_id, user, "Вопрос")
    with pytest.raises(SendRefused, match="Выберите подключение"):
        service.outgoing(chat_id)
    service.set_provider(chat_id, provider.id, "m-1")
    repo.add_item(chat_id, Item("q" * 32, 0, "input", "ещё вопрос", None, status="queued"))
    with pytest.raises(SendRefused, match="ещё обрабатывается"):
        service.outgoing(chat_id)
    with pytest.raises(SendRefused):
        service.set_provider(chat_id, provider.id, "нет такой модели")


def test_failed_text_and_local_answers_are_skipped_and_listed(repo, chat, provider):
    user, chat_id = chat
    service = service_with(repo, FakeCloud("x"))
    repo.add_item(chat_id, Item("f" * 32, 0, "input", "не очищенный текст", None, status="failed"))
    repo.add_item(chat_id, Item("l" * 32, 0, "answer", "Иванов Пётр, 10.1.2.5", None, source="local"))
    service.add_input(chat_id, user, "Вопрос")
    service.set_provider(chat_id, provider.id, "m-1")
    preview = service.outgoing(chat_id)
    assert preview.skipped == [(1, "текст не очищен"), (2, "ответ локальной модели: в нём оригиналы")]
    assert [m.text for m in preview.outgoing.context.messages] == ["Вопрос"]


def test_provider_error_keeps_the_received_part_as_partial(repo, chat, provider):
    service = ready(repo, chat, provider, FakeCloud("Начало ", error=ProviderError(status=502)))
    send(service, chat)
    stored = answer(repo, chat)
    assert (stored.status, stored.original, stored.meta["error"]) == ("partial", "Начало ", "сбой на стороне провайдера (код 502)")
    assert repo.audit_events("error")[0].details == {"kind": "ProviderError", "stage": "send", "status": 502}


def test_provider_error_before_any_text_fails_the_answer(repo, chat, provider):
    service = ready(repo, chat, provider, FakeCloud(error=ProviderError(status=401, detail=f"bad key {KEY}")))
    send(service, chat)
    stored = answer(repo, chat)
    assert (stored.status, stored.original) == ("failed", "")
    assert KEY not in repr(stored.meta) and "ключ" in stored.meta["error"]


def test_stop_ends_the_stream_and_marks_the_answer_partial(repo, chat, provider):
    service = ready(repo, chat, provider, FakeCloud("Первая часть. ", "Вторая часть.", stop_after=1))
    send(service, chat)
    stored = answer(repo, chat)
    assert (stored.status, stored.original, stored.meta["error"]) == ("partial", "Первая часть. ", "Остановлено")


def test_stop_reaches_the_live_answer_only_while_it_runs(repo, chat, provider):
    jobs = []
    service = ready(repo, chat, provider, FakeCloud("x"), send_submit=lambda fn, *args: jobs.append((fn, args)))
    item = send(service, chat)
    service.stop(chat[1], item.id)
    assert service.live.get(item.id).cancel.is_set()
    fn, args = jobs[0]
    fn(*args)
    with pytest.raises(KeyError):
        service.stop(chat[1], item.id)


def test_second_send_while_the_answer_runs_is_refused(repo, chat, provider):
    """Обзор этапа 3: двойное нажатие прошло бы проверку отпечатка и отправило оплаченный запрос дважды."""
    jobs = []
    fake = FakeCloud("x")
    service = ready(repo, chat, provider, fake, send_submit=lambda fn, *args: jobs.append((fn, args)))
    shown = service.outgoing(chat[1]).outgoing.context.digest()
    service.send(chat[1], chat[0], shown)
    with pytest.raises(SendRefused, match="ещё идёт"):
        service.send(chat[1], chat[0], shown)
    assert len(jobs) == 1 and len(answers := [i for i in repo.items(chat[1]) if i.kind == "answer"]) == 1
    fn, args = jobs[0]
    fn(*args)
    assert answers[0].id == answer(repo, chat).id and answer(repo, chat).status == "done"


def test_answer_cut_by_a_provider_error_is_left_out_and_the_question_can_go_again(repo, chat, provider):
    """FR-8.9: после обрыва ошибкой провайдера вопрос можно отправить снова — оборванный ответ в запрос не входит."""
    service = ready(repo, chat, provider, FakeCloud("Начало ", error=ProviderError(status=502)))
    send(service, chat)
    assert answer(repo, chat).meta["aborted"] is True
    preview = service.outgoing(chat[1])
    assert preview.skipped == [(2, "ответ оборван ошибкой провайдера")]
    assert [m.role for m in preview.outgoing.context.messages] == ["user"]


@pytest.mark.parametrize("cut", [(), ("Начало ",)], ids=["failed", "aborted"])
def test_cloud_answer_counts_the_replacements_since_the_previous_answer(repo, chat, provider, cut):
    """FR-7.5: замены во входных текстах после предыдущего ответа. Ответ локальной модели — граница, но своего
    счётчика у него нет: модель видела оригиналы. Отказ и ответ, оборванный ошибкой провайдера, — не граница:
    вопрос уходит снова, и в запросе следующего ответа те же замены."""
    user, chat_id = chat
    send(ready(repo, chat, provider, FakeCloud("Ответ <EMAIL_1>"), text="почта a@x.example и b@x.example"), chat)
    service = service_with(repo, FakeCloud(*cut, error=ProviderError(status=502)))
    service.add_input(chat_id, user, "ещё c@x.example")
    repo.add_item(chat_id, Item("l" * 32, 0, "answer", "Локальный ответ", None, source="local"))
    service.add_input(chat_id, user, "и d@x.example")
    send(service, chat)
    send(service_with(repo, FakeCloud("Ответ <EMAIL_4>")), chat)
    answers = [e for e in service.view(chat_id).items if isinstance(e, AnswerView)]
    assert [(e.item.source, e.result.counters.get("in_request")) for e in answers] == [
        ("api", 2), ("local", None), ("api", 1), ("api", 1),
    ]


def test_restore_audit_has_the_replacements_of_the_request(repo, chat, provider):
    """FINDINGS «Restore round of 15.10», (3), FR-11.1: в журнал — счётчики восстановления, и «замен в запросе»
    (FR-7.5) тоже. Число — запроса, ушедшего при отправке: текст, вставленный, пока идёт ответ, в него не входил."""
    user, chat_id = chat
    jobs = []
    service = ready(
        repo, chat, provider, FakeCloud("Ответ <EMAIL_1>"), text="почта a@x.example и b@x.example",
        send_submit=lambda fn, *args: jobs.append((fn, args)),
    )
    send(service, chat)
    service.add_input(chat_id, user, "ещё c@x.example")
    fn, args = jobs[0]
    fn(*args)
    assert repo.audit_events("restore")[0].details == {
        "restored": 1, "altered": 0, "derived": 0, "unknown": 0, "kept": 0, "foreign_links": 0, "in_request": 2,
    }
    assert [e.result.counters["in_request"] for e in service.view(chat_id).items if isinstance(e, AnswerView)] == [2]


def test_answer_longer_than_the_text_limit_is_cut(repo, chat, provider):
    fake = FakeCloud(*(["слово "] * 50))
    service = ready(repo, chat, provider, fake, max_text_chars=60)
    send(service, chat)
    stored = answer(repo, chat)
    assert stored.status == "partial" and len(stored.original) <= 66 and "длиннее 60 знаков" in stored.meta["error"]


def test_service_stop_saves_running_answers_as_partial_with_its_own_reason(repo, chat, provider):
    jobs = []
    service = ready(repo, chat, provider, FakeCloud("Часть. ", "Ещё."), send_submit=lambda fn, *args: jobs.append((fn, args)))
    item = send(service, chat)
    closed = []
    service.live.get(item.id).on_open(lambda: closed.append(True))
    service.live.cancel_all()
    assert closed == [True]
    fn, args = jobs[0]
    fn(*args)
    stored = answer(repo, chat)
    assert stored.status == "failed" and stored.meta["error"].startswith("Служба остановлена")


def test_deleting_a_chat_stops_its_running_answer(repo, chat, provider):
    jobs = []
    service = ready(repo, chat, provider, FakeCloud("x"), send_submit=lambda fn, *args: jobs.append((fn, args)))
    item = send(service, chat)
    service.stop_chat(chat[1])
    assert service.live.get(item.id).cancel.is_set() and service.live.get(item.id).reason == "Чат удалён"


def test_truncated_local_answer_is_partial(repo, chat, engines):
    user, chat_id = chat
    engines.completer.answers = ["Начало длинного ответа"]
    engines.completer.truncated = True
    service = ChatService(repo, engines=engines)
    service.add_input(chat_id, user, "Вопрос")
    item = service.ask_local(chat_id, user)
    stored = repo.item(chat_id, item.id)
    assert (stored.status, stored.meta) == ("partial", {"error": "Ответ обрезан пределом длины"})


def test_truncated_answer_is_partial(repo, chat, provider):
    service = ready(repo, chat, provider, FakeCloud("Длинный ответ", truncated=True))
    send(service, chat)
    assert answer(repo, chat).status == "partial"


def test_leak_at_send_fails_the_answer_and_is_audited(repo, chat, provider):
    """AC-3.4 на уровне службы: проверка утечек модуля выхода в сеть отказала — ответа нет, событие в журнале."""
    service = ready(repo, chat, provider, FakeCloud(error=cloud.LeakDetected(1)))
    send(service, chat)
    stored = answer(repo, chat)
    assert (stored.status, stored.meta["error"]) == ("failed", "В исходящем тексте найден оригинал: запрос не отправлен")
    assert repo.audit_events("leak")[0].details == {"count": 1, "stage": "send"}


def test_instruction_is_cleaned_and_goes_to_the_system_part(repo, chat, provider):
    user, chat_id = chat
    service = ready(repo, chat, provider, FakeCloud("ok"))
    service.add_input(chat_id, user, "Отвечай кратко, копия на a@x.example", source="instruction")
    service.add_input(chat_id, user, "Ещё вопрос")
    context = service.outgoing(chat_id).outgoing.context
    assert context.system.endswith("Отвечай кратко, копия на <EMAIL_1>")
    assert [m.text for m in context.messages] == ["Вопрос: почта <EMAIL_1>\n\nЕщё вопрос"]


def test_three_turns_and_a_rule_before_the_third(repo, chat, provider):
    """AC-3.5 на уровне службы: замены одинаковы на всех ходах, правило перед третьим ходом — во всей истории."""
    user, chat_id = chat
    fake = FakeCloud("Принято, <EMAIL_1>. Проект Ромашка в порядке.")
    service = ready(repo, chat, provider, fake, text="Почта a@x.example, проект Ромашка")
    send(service, chat)
    service.add_input(chat_id, user, "Что с a@x.example?")
    send(service, chat)
    service.mask_value(chat_id, user, repo.items(chat_id)[0].id, "Ромашка", T.TERM)
    service.add_input(chat_id, user, "А с Ромашкой?")
    send(service, chat)
    first, second, third = (call[0] for call in fake.calls)
    assert first.messages[0].text == second.messages[0].text == "Почта <EMAIL_1>, проект Ромашка"
    assert second.messages[2].text == "Что с <EMAIL_1>?"
    assert "Ромашка" not in " ".join(third.texts()) and "<TERM_1>" in third.messages[0].text
    assert "<TERM_1>" in third.messages[1].text            # ответ модели, повторивший значение (FR-8.11)
    assert all("a@x.example" not in " ".join(call[0].texts()) for call in fake.calls)


def test_ask_local_sends_originals_only_to_the_local_model(repo, chat, engines):
    user, chat_id = chat
    engines.completer.answers = ["Локальный ответ про a@x.example"]
    service = ChatService(repo, engines=engines, cloud_send=FakeCloud("не должно вызываться"))
    service.add_input(chat_id, user, "Отвечай кратко", source="instruction")
    service.add_input(chat_id, user, "Вопрос: почта a@x.example")
    item = service.ask_local(chat_id, user)
    [request] = engines.completer.requests
    assert request["messages"] == [
        {"role": "system", "content": "Отвечай кратко"}, {"role": "user", "content": "Вопрос: почта a@x.example"},
    ]
    stored = repo.item(chat_id, item.id)
    assert (stored.source, stored.status, stored.original) == ("local", "done", "Локальный ответ про a@x.example")
    assert service.view(chat_id).items[-1].result.text == "Локальный ответ про a@x.example"
    assert repo.audit_events("local_answer")[0].details == {"messages": 2}


def test_second_local_question_waits_for_the_first_answer(repo, chat, engines, monkeypatch):
    """Аудит 21.10.2026: второй вопрос до начала первого ответа (двойная отправка формы, две вкладки) — та же
    генерация ещё раз в общем пуле из двух потоков. Пока ответ локальной модели в очереди или в работе,
    новый вопрос отклоняется — и тогда, когда вторая вкладка успела записать свой между чтением и записью."""
    user, chat_id = chat
    jobs = []
    service = ChatService(repo, engines=engines, submit=lambda fn, *args: jobs.append((fn, args)))
    repo.add_item(chat_id, Item("q" * 32, 0, "input", "Вопрос", "Вопрос"))
    first = service.ask_local(chat_id, user)
    with pytest.raises(SendRefused, match="ещё идёт"):
        service.ask_local(chat_id, user)
    [(fn, args)] = jobs
    fn(*args)
    assert repo.item(chat_id, first.id).status == "done"
    repo.add_item(chat_id, Item("r" * 32, 0, "input", "Ещё вопрос", "Ещё вопрос"))
    commit = repo.commit_chat

    def other_tab_first(*args, **kwargs):
        monkeypatch.setattr(repo, "commit_chat", commit)
        service.ask_local(chat_id, user)
        return commit(*args, **kwargs)

    monkeypatch.setattr(repo, "commit_chat", other_tab_first)
    with pytest.raises(SendRefused, match="ещё идёт"):
        service.ask_local(chat_id, user)
    assert len(jobs) == 2
    assert [i.status for i in repo.items(chat_id) if i.source == "local"] == ["done", "queued"]
    assert len(repo.audit_events("local_answer")) == 2


def test_local_answer_failure_has_a_reason(repo, chat, engines):
    user, chat_id = chat
    engines.unavailable = "Локальная модель недоступна: нет ключа"
    service = ChatService(repo, engines=engines)
    engines.unavailable = None
    service.add_input(chat_id, user, "Вопрос")
    engines.unavailable = "Локальная модель недоступна: нет ключа"
    item = service.ask_local(chat_id, user)
    stored = repo.item(chat_id, item.id)
    assert (stored.status, stored.meta) == ("failed", {"error": "Локальная модель недоступна: нет ключа"})


def test_local_answer_is_not_restored(repo, chat, provider):
    """Адрес в ответе локальной модели — настоящий: его не принимают за выведенный из подменной подсети."""
    user, chat_id = chat
    service = ready(repo, chat, provider, FakeCloud("x"), text="узел 10.1.2.5")
    fake_ip = repo.items(chat_id)[0].sanitized.split()[-1]
    repo.add_item(chat_id, Item("l" * 32, 0, "answer", f"Проверьте {fake_ip[:-1]}9", None, source="local"))
    assert service.view(chat_id).items[-1].result.text == f"Проверьте {fake_ip[:-1]}9"


def dialogue(repo, chat, provider, fake) -> ChatService:
    """Вопрос, вставленный ответ модели, второй вопрос — элементы 1, 2, 3."""
    service = ready(repo, chat, provider, fake, text="Первый вопрос: почта a@x.example")
    service.add_answer(chat[1], chat[0], "Ответ про <EMAIL_1>")
    service.add_input(chat[1], chat[0], "Второй вопрос")
    return service


def test_excluded_items_leave_the_request_and_change_its_digest(repo, chat, provider):
    """Сокращение контекста: исключённый ответ не уходит, вопросы вокруг склеиваются (раздел 10.1), отпечаток другой,
    и отправка с отпечатком прежнего состава отказывает."""
    user, chat_id = chat
    fake = FakeCloud("x")
    service = dialogue(repo, chat, provider, fake)
    full = service.outgoing(chat_id)
    assert [m.role for m in full.outgoing.context.messages] == ["user", "assistant", "user"]
    assert [(seq, role) for seq, role, _ in full.candidates] == [(1, "user"), (2, "assistant"), (3, "user")]
    short = service.outgoing(chat_id, frozenset({2, 99}))
    assert short.excluded == [2]
    assert [m.text for m in short.outgoing.context.messages] == ["Первый вопрос: почта <EMAIL_1>\n\nВторой вопрос"]
    assert short.outgoing.context.digest() != full.outgoing.context.digest()
    with pytest.raises(SendRefused, match="изменился"):
        service.send(chat_id, user, full.outgoing.context.digest(), frozenset({2}))
    service.send(chat_id, user, short.outgoing.context.digest(), frozenset({2}))
    [(ctx, _, _)] = fake.calls
    assert ctx == short.outgoing.context
    assert repo.audit_events("cloud_send")[0].details["excluded"] == 1


def test_excluding_the_last_question_keeps_the_choice_and_refuses_sending(repo, chat, provider):
    user, chat_id = chat
    service = dialogue(repo, chat, provider, FakeCloud("x"))
    preview = service.outgoing(chat_id, frozenset({3}))
    assert preview.outgoing is None and "Последним в запросе" in preview.refused and preview.excluded == [3]
    with pytest.raises(SendRefused, match="Последним"):
        service.send(chat_id, user, "0" * 64, frozenset({3}))


def test_manual_transfer_is_the_api_request_without_a_connection(repo, chat, provider):
    """Перенос вручную: та же сборка и проверка утечек, без подключения; без новых замен состояние не пишется."""
    user, chat_id = chat
    service = dialogue(repo, chat, provider, FakeCloud("x"))
    version = repo.load_state(chat_id)[1]
    manual = service.manual(chat_id)
    assert manual.provider is None and (manual.outgoing.context.provider_id, manual.outgoing.context.model) == ("", "")
    assert manual.outgoing.context.texts() == service.outgoing(chat_id).outgoing.context.texts()
    assert repo.load_state(chat_id)[1] == version and repo.audit_events("cloud_send") == []


def test_manual_transfer_keeps_the_replacements_it_issues(repo, chat):
    """Словарь пополнен после очистки: сборка выдаёт новую замену, и состояние записывается — иначе метку
    скопированного текста во вставленном ответе было бы нечем восстановить."""
    user, chat_id = chat
    service = service_with(repo, FakeCloud("x"))
    service.add_input(chat_id, user, "клиент Ромашка")
    repo.add_dictionary("always", "Ромашка", T.ORG)
    [message] = service.manual(chat_id).outgoing.context.messages
    assert message.text == "клиент <ORG_1>"
    service.add_answer(chat_id, user, "Ответ для <ORG_1>")
    assert service.view(chat_id).items[-1].result.text == "Ответ для Ромашка"


def test_check_provider_sends_no_chat_data(repo, provider):
    fake = FakeCloud("готово")
    assert service_with(repo, fake).check_provider(provider, "m-1") == "готово"
    [(ctx, connection, checked)] = fake.calls
    assert (ctx.chat_id, ctx.system, checked) == ("", "", False)
