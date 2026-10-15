import json
import re
import uuid

from cleaner.core.types import EntityType as T
from cleaner.storage.repo import Item
from cleaner.web.app import create_app


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
    assert "оригиналов в очищенном тексте нет" in page


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
    first, second = sorted((e for e in state.entities.values() if e.type is T.PERSON), key=lambda e: e.number)
    email = next(e for e in state.entities.values() if e.type is T.EMAIL)
    table = ivan.get(f"/chats/{chat_id}/entities").text
    assert "&lt;PERSON_2&gt;" in table and "Ivanov" in table
    ivan.post(f"/chats/{chat_id}/entities/merge", keep=first.id, drop=second.id)
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
    repo.set_item_risk_status(chat_id, item_id, "running", ("",))
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


def test_failed_residual_risk_check_says_so(ivan, repo, engines):
    engines.completer.answers = ["не JSON"]
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = first_item(repo, chat_id)
    ivan.post(f"/chats/{chat_id}/items/{item_id}/risk")
    assert "Проверка не выполнена" in ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert [e.details for e in repo.audit_events("error")] == [{"kind": "DetectorError", "stage": "risk"}]
