import json
import re
import uuid

from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.storage.repo import Item
from cleaner.web.app import create_app
from cleaner.web.routes_review import _back


def first_item(repo, chat_id: str) -> str:
    return repo.items(chat_id)[0].id


def test_new_text_opens_the_review_with_paired_fragments(ivan, repo):
    chat_id = ivan.chat()
    response = ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = first_item(repo, chat_id)
    assert response.headers["location"] == f"/chats/{chat_id}/items/{item_id}"
    page = ivan.get(response.headers["location"]).text
    entities = re.findall(r'data-entity="([0-9a-f]+)"', page)
    assert len(entities) == 2 and entities[0] == entities[1]          # одна сущность в обеих панелях (FR-6.1)
    assert "a@x.example</mark>" in page and "&lt;EMAIL_1&gt;</mark>" in page
    assert "Почта — 1" in page and 'data-copy="sanitized"' in page
    assert "известных скрываемых оригиналов не найдено" in page


def test_summary_names_what_the_leak_check_skips(ivan, repo):
    """Аудит 21.10.2026: после «Снять замену во всём чате» адрес открыт в очищенном тексте, а зелёный итог проверки
    утверждал, что оригиналов в нём нет. Итог говорит только об известных скрываемых значениях; открытые решением
    пользователя и выполненные слои — отдельными значками."""
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/layers", layer="llm", enabled="no")
    ivan.post(f"/chats/{chat_id}/input", text="почта demo@example.org, копия demo@example.org")
    item_id = first_item(repo, chat_id)
    path = f"/chats/{chat_id}/items/{item_id}"
    page = ivan.get(path).text
    assert "открыто по решению пользователя" not in page and "слои 1–3, 4</span>" in page
    ivan.post(f"/chats/{chat_id}/unmask", item_id=item_id, value="demo@example.org")
    page = ivan.get(path).text
    assert "demo@example.org, копия demo@example.org" in repo.items(chat_id)[0].sanitized
    assert "известных скрываемых оригиналов не найдено" in page and "оригиналов в очищенном тексте нет" not in page
    assert "открыто по решению пользователя — 1</span>" in page


def test_review_marks_a_hidden_blocked_finding_and_a_pasted_blocked_surrogate(ivan, repo):
    """Фрагмент со скрытой в нём находкой «блокировать» и вставленная замена заблокированной сущности подсвечены и
    названы в сообщении о блокировке — по нынешней политике, без повторной очистки."""
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="домен fabrikam.ru")
    ivan.post(f"/chats/{chat_id}/input", text="token=+79161234567abcdef, снова token=+79161234567abcdef и domain-1.example")
    repo.set_policy(T.PHONE, Policy.BLOCK)
    repo.set_policy(T.DOMAIN, Policy.BLOCK)
    item = repo.items(chat_id)[1]
    page = ivan.get(f"/chats/{chat_id}/items/{item.id}").text
    assert "Фрагментов типа с политикой «блокировать» — 3." in page
    assert page.count('class="t-SECRET blocked"') == 2
    assert "Внутри фрагмента найдено значение типа «Телефон»" in page        # карточка «Почему скрыто»
    assert '<mark class="blocked" title="Замена сущности с политикой «блокировать»">domain-1.example</mark>' in page
    repo.set_policy(T.DOMAIN, Policy.MASK)
    assert "Фрагментов типа с политикой «блокировать» — 2." in ivan.get(f"/chats/{chat_id}/items/{item.id}").text


def test_multiline_fragment_with_crlf_is_masked_whole(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Проект\r\nЗаря Восток\r\nзапущен")
    item_id = first_item(repo, chat_id)
    # Выделение браузер отдаёт с LF, а сохранённый оригинал — с CRLF, как его прислала форма.
    response = ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value="Заря Восток\nзапущен", type="TERM")
    assert response.headers["location"] == f"/chats/{chat_id}/items/{item_id}"
    assert repo.items(chat_id)[0].sanitized == "Проект\r\n<TERM_1>"


def test_unmask_and_mask_apply_to_every_text_of_the_chat(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="a@x.example, проект Заря")
    ivan.post(f"/chats/{chat_id}/input", text="снова a@x.example и Заря")
    first = first_item(repo, chat_id)
    ivan.post(f"/chats/{chat_id}/unmask", item_id=first, value="a@x.example")
    ivan.post(f"/chats/{chat_id}/mask", item_id=first, value="Заря", type="TERM")
    assert [i.sanitized for i in repo.items(chat_id)] == [
        "a@x.example, проект <TERM_1>", "снова a@x.example и <TERM_1>",
    ]


def test_entity_table_merges_and_changes_the_restore_value(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Иванов, Ivanov, a@x.example")
    item_id = first_item(repo, chat_id)
    for value in ("Иванов", "Ivanov"):
        ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value=value, type="PERSON")
    state, _ = repo.load_state(chat_id)
    first, _ = sorted((e for e in state.entities.values() if e.type is T.PERSON), key=lambda e: e.number)
    email = next(e for e in state.entities.values() if e.type is T.EMAIL)
    table = ivan.get(f"/chats/{chat_id}/entities").text
    assert "&lt;PERSON_2&gt;" in table and "Ivanov" in table
    assert '<datalist id="peers-PERSON"><option value="&lt;PERSON_1&gt;">' in table
    assert f'name="keep" value="{first.id}"' in table and 'list="peers-PERSON"' in table
    # Присоединяемая — по её замене; неизвестная замена и замена другого типа — понятный отказ.
    for surrogate, refusal in (("<PERSON_9>", "такой замены в таблице чата нет"), ("<EMAIL_1>", "одного типа")):
        response = ivan.post(f"/chats/{chat_id}/entities/merge", keep=first.id, surrogate=surrogate)
        assert response.status_code == 400 and refusal in response.text, surrogate
    ivan.post(f"/chats/{chat_id}/entities/merge", keep=first.id, surrogate=" <PERSON_2> ")
    ivan.post(f"/chats/{chat_id}/entities/{first.id}/restore-value", value="Иванов И. И.")
    ivan.post(f"/chats/{chat_id}/entities/{email.id}/unmask")
    assert repo.items(chat_id)[0].sanitized == "<PERSON_1>, <PERSON_1>, a@x.example"
    ivan.post(f"/chats/{chat_id}/answer", answer="Ответ для <PERSON_1>")
    assert "Иванов И. И.</mark>" in ivan.get(f"/chats/{chat_id}").text          # FR-7.10


def test_retype_and_refused_edits(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Проект Заря")
    item_id = first_item(repo, chat_id)
    ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value="Заря", type="TERM")
    [entity] = repo.load_state(chat_id)[0].entities.values()
    ivan.post(f"/chats/{chat_id}/entities/{entity.id}/retype", type="ORG")
    assert repo.items(chat_id)[0].sanitized == "Проект <ORG_1>"
    refused = ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value="нет такого", type="TERM")
    assert refused.status_code == 400 and "такого фрагмента в тексте нет" in refused.text
    assert ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value="Заря", type="NOPE").status_code == 400
    assert ivan.post(f"/chats/{chat_id}/entities/missing/retype", type="ORG").status_code == 404


def test_retyping_a_host_part_keeps_the_full_name(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="узел srv01.contoso.ru и srv01")
    host = next(e for e in repo.load_state(chat_id)[0].entities.values() if e.key == "srv01")
    ivan.post(f"/chats/{chat_id}/entities/{host.id}/retype", type="TERM")
    assert repo.items(chat_id)[0].sanitized == "узел <TERM_1>.domain-1.example и <TERM_1>"
    ivan.post(f"/chats/{chat_id}/answer", answer="Перезагрузите <TERM_1>.domain-1.example")
    assert "srv01.contoso.ru" in ivan.get(f"/chats/{chat_id}").text


def test_admin_adds_a_value_to_the_dictionary_from_the_review(boss, ivan, repo):
    chat_id = boss.chat()
    boss.post(f"/chats/{chat_id}/input", text="клиент Ромашка")
    item_id = first_item(repo, chat_id)
    response = boss.post(f"/chats/{chat_id}/dictionary", item_id=item_id, value="Ромашка", list="always", type="ORG")
    assert response.headers["location"] == f"/chats/{chat_id}/items/{item_id}"
    assert [(r.list, r.value) for r in repo.dictionary()] == [("always", "Ромашка")]
    assert repo.items(chat_id)[0].sanitized == "клиент <ORG_1>"
    own = ivan.chat()
    assert ivan.post(f"/chats/{own}/dictionary", value="x", list="never").status_code == 403


def test_value_masked_later_is_flagged_where_it_was_open(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Проект Заря запущен")
    item_id = first_item(repo, chat_id)
    ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value="Заря", type="TERM")
    assert "содержал открытым значение" in ivan.get(f"/chats/{chat_id}/items/{item_id}").text      # FR-6.8


def test_answers_have_no_review_screen(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/answer", answer="ответ")
    assert ivan.get(f"/chats/{chat_id}/items/{first_item(repo, chat_id)}").status_code == 404


def test_reviewed_text_is_saved_as_a_gold_example(ivan, repo):
    """FR-6.10: текст и итоговая разметка — с правками пользователя."""
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Пишет a@x.example про a@x.example и Заря")
    item_id = first_item(repo, chat_id)
    ivan.post(f"/chats/{chat_id}/mask", item_id=item_id, value="Заря", type="TERM")
    assert "Сохранить как эталон" in ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert ivan.post(f"/chats/{chat_id}/items/{item_id}/gold").status_code == 303
    [row] = repo.gold()
    assert row.text == "Пишет a@x.example про a@x.example и Заря"
    assert [(s["type"], s["entity"], s["origin"]) for s in row.spans] == [
        ("EMAIL", 0, "detector"), ("EMAIL", 0, "detector"), ("TERM", 1, "manual"),
    ]
    assert [e.details for e in repo.audit_events("gold_added")] == [{"spans": 3}]


def test_residual_risk_guesses_are_shown_and_stored_encrypted(ivan, repo, engines, tmp_path):
    """FR-9.3: догадки — подсказка на экране проверки; верная догадка — оригинал, поэтому зашифрована."""
    engines.completer.answers = [json.dumps({"guesses": [{"kind": "org", "guess": "Ромашка Rk17", "clue": ""}]}, ensure_ascii=False)]
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = first_item(repo, chat_id)
    assert ivan.post(f"/chats/{chat_id}/items/{item_id}/risk").status_code == 303
    page = ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert "организация: «Ромашка Rk17»" in page
    assert [e.details for e in repo.audit_events("risk_check")] == [{"guesses": 1}]
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))
    assert "Rk17".encode("utf-8") not in raw


def test_check_interrupted_by_a_restart_says_so_and_can_be_run_again(ivan, repo, clock, engines, jobs):
    """Обзор плана 2+4, m-2: прерванная перезапуском проверка — не «локальная модель недоступна»."""
    engines.completer.answers = [json.dumps({"guesses": []})]
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = first_item(repo, chat_id)
    job = repo.queue_risk(chat_id, item_id, ("",))
    repo.set_item_risk_status(chat_id, item_id, job, "running", ("queued",))
    create_app(repo, clock, secure_cookies=False, engines=engines, jobs=jobs)          # перезапуск службы
    page = ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert "Проверка прервана перезапуском службы" in page and "недоступна" not in page
    assert f"/items/{item_id}/risk" in page
    ivan.post(f"/chats/{chat_id}/items/{item_id}/risk")
    assert repo.item(chat_id, item_id).risk_status == "done"


def test_text_cleaned_before_layers_4_and_5_is_not_reported_as_cleaned_without_them(ivan, repo):
    """Обзор плана 2+4, m-12: у текста этапа 1 слоёв 4 и 5 не было — «слой выключен» о нём неправда."""
    chat_id = ivan.chat()
    state, version = repo.load_state(chat_id)
    old = Item(uuid.uuid4().hex, 0, "input", "Проект Заря запущен", "Проект Заря запущен")     # meta {} — как после миграции
    repo.commit_chat(chat_id, state, version, [old])
    assert "не выполнялся" not in ivan.get(f"/chats/{chat_id}/items/{old.id}").text
    ivan.post(f"/chats/{chat_id}/mask", item_id=old.id, value="Заря", type="TERM")
    page = ivan.get(f"/chats/{chat_id}/items/{old.id}").text
    assert "&lt;TERM_1&gt;" in page and "не выполнялся" not in page


def test_hidden_sheets_left_out_of_the_text_are_reported(ivan, repo):
    """Находка «Small gaps…»: в meta — только число скрытых листов, имена листов — данные пользователя."""
    chat_id = ivan.chat()
    state, version = repo.load_state(chat_id)
    book = Item(uuid.uuid4().hex, 0, "input", "Сотрудник", "Сотрудник", source="file",
                meta={"kind": "xlsx", "hidden_sheets": 2, "layers": ["ner", "llm"]})
    plain = Item(uuid.uuid4().hex, 0, "input", "Сотрудник", "Сотрудник", source="file",
                 meta={"kind": "xlsx", "layers": ["ner", "llm"]})
    repo.commit_chat(chat_id, state, version, [book, plain])
    notice = "Скрытые листы книги (2) не извлечены: их содержимое в очищенный текст не попало"
    assert notice in ivan.get(f"/chats/{chat_id}/items/{book.id}").text
    assert "Скрытые листы" not in ivan.get(f"/chats/{chat_id}/items/{plain.id}").text


def test_partial_extraction_is_shown_in_the_feed_and_on_the_review(ivan, repo):
    """Идея аудита 2026-10-21: «извлечено частично» со страницами — в заголовке элемента ленты и в сводке проверки;
    о встроенных изображениях документа — предупреждение. В meta — только номера и числа."""
    chat_id = ivan.chat()
    state, version = repo.load_state(chat_id)
    layers = ["ner", "llm"]
    scan = Item(uuid.uuid4().hex, 0, "input", "Сотрудник", "Сотрудник", source="file", meta={
        "kind": "pdf", "pages": 7, "ocr_pages": [1, 2, 3, 4], "unread_pages": [2], "doubtful_pages": [5],
        "failed_pages": [7], "layers": layers,
    })
    deck = Item(uuid.uuid4().hex, 0, "input", "Сотрудник", "Сотрудник", source="file",
                meta={"kind": "pptx", "images": 3, "layers": layers})
    repo.commit_chat(chat_id, state, version, [scan, deck])
    feed = ivan.get(f"/chats/{chat_id}").text
    assert feed.count("извлечено частично") == 1 and "извлечено частично: страницы 2, 5, 7" in feed
    review = ivan.get(f"/chats/{chat_id}/items/{scan.id}").text
    assert "PDF, страниц — 7: распознаванием — 1–4; из слоя текста файла — 5, 6; не распознаны — 7." in review
    assert "Извлечено частично. На страницах 2 распознавание не нашло текста" in review
    assert "Извлечено частично. Страницы 7 распознать не удалось: их содержимое в очищенный текст не попало" in review
    assert "Извлечено частично. На страницах 5 изображение занимает большую часть страницы" in review
    review = ivan.get(f"/chats/{chat_id}/items/{deck.id}").text
    assert "Встроенных изображений в документе — 3: текст на них не распознаётся" in review
    assert "Извлечено частично" not in review and "PDF, страниц" not in review


def test_failed_residual_risk_check_says_so(ivan, repo, engines):
    engines.completer.answers = ["не JSON"]
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = first_item(repo, chat_id)
    ivan.post(f"/chats/{chat_id}/items/{item_id}/risk")
    assert "Проверка не выполнена" in ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert [e.details for e in repo.audit_events("error")] == [{"kind": "DetectorError", "stage": "risk"}]


def entity_table(browser_, count: int) -> str:
    chat_id = browser_.chat()
    browser_.post(f"/chats/{chat_id}/input", text=" ".join(f"u{n}@x.example" for n in range(count)))
    return chat_id


def test_entity_table_grows_linearly_and_pages_on_the_server(ivan):
    """Аудит 21.10.2026, P2: у каждой строки был список всех сущностей того же типа — 500 сущностей давали 250 000
    <option> и 12 МБ HTML. Теперь кандидаты — один список на тип, а строк на странице не больше ENTITIES_PAGE."""
    chats = entity_table(ivan, 200), entity_table(ivan, 400)
    small, large = (ivan.get(f"/chats/{chat_id}/entities").text for chat_id in chats)
    options = [page.count("<option") for page in (small, large)]
    assert options[1] - options[0] <= 210                   # +200 сущностей — +200 кандидатов, а не квадрат
    assert len(large) < 400_000 and len(large) - len(small) < 25_000     # страница — постоянная, кандидаты — линейно
    assert large.count("<tr>") == 1 + 100 and "Показаны 1–100 из 400" in large and "страница 1 из 4" in large
    last = ivan.get(f"/chats/{chats[0]}/entities", page="99").text      # номер за пределами — последняя страница
    assert "Показаны 101–200 из 200" in last and 'rel="prev"' in last and 'rel="next"' not in last


def test_entity_table_filter_by_type_stays_after_an_edit(ivan):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="a@x.example b@x.example srv01.contoso.ru")
    table = ivan.get(f"/chats/{chat_id}/entities", type="EMAIL").text
    assert "Показаны 1–2 из 2" in table and "&lt;EMAIL_2&gt;" in table and "host-1" not in table
    assert '<input type="hidden" name="back" value="type=EMAIL">' in table
    assert ivan.get(f"/chats/{chat_id}/entities", type="NOPE").status_code == 400
    # Адрес возврата собирает сервер: из поля back — только известный код типа и число.
    assert _back("c1", {"back": "type=EMAIL&page=2"}) == "/chats/c1/entities?type=EMAIL&page=2"
    assert _back("c1", {"back": "type=<x>&page=//evil.example"}) == "/chats/c1/entities"
