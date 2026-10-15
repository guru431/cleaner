import re
import uuid

from cleaner import service
from cleaner.core.pipeline import SanitizeResult
from cleaner.core.types import EntityType as T
from cleaner.storage.repo import Item
from cleaner.web.app import create_app
from cleaner.web.jobs import INTERRUPTED


def test_new_chat_gets_a_dated_title_and_the_list_is_searchable(ivan):
    chat_id = ivan.chat(title="")
    assert "Чат от 14.10.2026 09:00" in ivan.get(f"/chats/{chat_id}").text
    ivan.chat("Сервер почты")
    found = ivan.get("/chats", q="ПОЧТЫ").text
    assert "Сервер почты" in found and "Чат от" not in found


def test_input_is_shown_cleaned_and_downloadable(ivan):
    chat_id = ivan.chat()
    assert ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example").status_code == 303
    page = ivan.get(f"/chats/{chat_id}").text
    assert "&lt;EMAIL_1&gt;" in page and "a@x.example" not in page
    item_id = re.search(r'id="item-([0-9a-f]+)"', page).group(1)
    download = ivan.get(f"/chats/{chat_id}/items/{item_id}/download")
    assert download.text == "почта <EMAIL_1>"
    assert download.headers["content-disposition"].startswith("attachment")


def test_answer_is_restored_with_the_view_as_received(ivan):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    ivan.post(f"/chats/{chat_id}/answer", answer="Напишите на <EMAIL_1> и <PERSON_7>")
    page = ivan.get(f"/chats/{chat_id}").text
    assert 'class="r-restored"' in page and "a@x.example</mark>" in page
    assert 'class="r-unknown"' in page
    assert "Напишите на &lt;EMAIL_1&gt; и &lt;PERSON_7&gt;" in page      # вид «как получено» (FR-7.11)


def test_answer_shows_the_replacements_of_the_texts_since_the_previous_answer(ivan):
    """FR-7.5: счётчик ответа — замены в его запросе, а не вся таблица замен чата (у второго ответа в ней 3)."""
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example и b@x.example")
    ivan.post(f"/chats/{chat_id}/answer", answer="Ответ <EMAIL_1>")
    ivan.post(f"/chats/{chat_id}/input", text="ещё c@x.example")
    ivan.post(f"/chats/{chat_id}/answer", answer="Ответ <EMAIL_3>")
    page = ivan.get(f"/chats/{chat_id}").text
    assert re.findall(r"Замен в текстах после прошлого ответа: (\d+), восстановлено: (\d+)", page) == [
        ("2", "1"), ("1", "1"),
    ]


def test_markup_in_title_text_and_answer_is_shown_as_text(ivan):
    chat_id = ivan.chat("<img src=x onerror=alert(1)>")
    ivan.post(f"/chats/{chat_id}/input", text="<script>alert(1)</script> a@x.example")
    ivan.post(
        f"/chats/{chat_id}/answer",
        answer='<img src="https://evil.example.org/p.png"> [ссылка](https://evil.example.org/?q=<EMAIL_1>)',
    )
    page = ivan.get(f"/chats/{chat_id}").text
    assert "<script>alert" not in page and "<img" not in page and 'href="https://evil' not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "a@x.example" not in page            # метка в посторонней ссылке не восстановлена (FR-7.8)


def test_empty_and_oversized_input_are_refused(ivan, repo):
    chat_id = ivan.chat()
    for text in ("", "   \r\n  "):
        assert ivan.post(f"/chats/{chat_id}/input", text=text).status_code == 400
    response = ivan.post(f"/chats/{chat_id}/input", text="x" * 500_001)
    assert response.status_code == 413 and "500000" in response.text
    assert repo.items(chat_id) == []


def test_rename_and_delete_with_confirmation(ivan):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/rename", title="Новое имя")
    assert "Новое имя" in ivan.get("/chats").text
    assert ivan.post(f"/chats/{chat_id}/delete").status_code == 400
    assert ivan.post(f"/chats/{chat_id}/delete", confirm="yes").headers["location"] == "/chats"
    assert ivan.get(f"/chats/{chat_id}").status_code == 404


def test_copy_and_download_are_blocked_while_a_leak_is_found(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="клиент Ромашка")
    repo.add_dictionary("always", "Ромашка", T.ORG)
    item_id = repo.items(chat_id)[0].id
    page = ivan.get(f"/chats/{chat_id}").text
    assert "data-copy" not in page and "Выдача заблокирована" in page       # SEC-2
    assert ivan.get(f"/chats/{chat_id}/items/{item_id}/download").status_code == 409


def test_largest_allowed_text_is_accepted(ivan, repo, monkeypatch):
    """FR-2.1, финальный обзор 1В: 500 000 знаков, даже четырёхбайтных, принимаются целиком — без отказа
    библиотеки форм (Starlette по умолчанию ограничивает поле одним мегабайтом). Очистка подменена:
    здесь проверяется приём формы, скорость очистки длинного текста — тесты NFR-4."""
    monkeypatch.setattr(service, "sanitize", lambda state, text, settings: SanitizeResult(text, []))
    chat_id = ivan.chat()
    response = ivan.post(f"/chats/{chat_id}/input", text="😀" * 500_000)
    assert response.status_code == 303, response.text[:200]
    assert len(repo.items(chat_id)[0].original) == 500_000


def test_status_of_a_text_is_served_as_json_without_its_content(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    response = ivan.get(f"/chats/{chat_id}/items/{item_id}/status")
    assert response.json() == {"status": "done", "risk": "", "progress": ""}
    assert "a@x.example" not in response.text
    assert ivan.get(f"/chats/{chat_id}/items/{'0' * 32}/status").status_code == 404


def test_text_in_progress_is_polled_and_not_shown(ivan, repo):
    chat_id = ivan.chat()
    item = repo.add_item(chat_id, Item(uuid.uuid4().hex, 0, "input", "почта a@x.example", None, status="queued"))
    poll = f'data-poll="/chats/{chat_id}/items/{item.id}/status"'
    for path in (f"/chats/{chat_id}", f"/chats/{chat_id}/items/{item.id}"):
        page = ivan.get(path).text
        assert poll in page and "a@x.example" not in page, path
    assert ivan.get(f"/chats/{chat_id}/items/{item.id}/download").status_code == 409


def test_text_left_running_fails_at_start_and_can_be_run_again(ivan, repo, clock, engines, jobs):
    """Обзор плана 2+4, пункт 1 (NFR-6)."""
    chat_id = ivan.chat()
    item = repo.add_item(chat_id, Item(uuid.uuid4().hex, 0, "input", "почта a@x.example", None, status="running"))
    create_app(repo, clock, secure_cookies=False, engines=engines, jobs=jobs)          # перезапуск службы
    stored = repo.item(chat_id, item.id)
    assert (stored.status, stored.meta["error"]) == ("failed", INTERRUPTED)
    assert [e.details for e in repo.audit_events("jobs_interrupted")] == [{"count": 1}]
    page = ivan.get(f"/chats/{chat_id}").text
    assert INTERRUPTED in page and f"/items/{item.id}/retry" in page
    ivan.post(f"/chats/{chat_id}/items/{item.id}/retry")
    assert repo.item(chat_id, item.id).sanitized == "почта <EMAIL_1>"
    assert ivan.post(f"/chats/{chat_id}/items/{'0' * 32}/retry").status_code == 404


def test_chat_deleted_while_the_wal_is_held_is_gone_and_the_error_is_logged(ivan, repo, wal_reader):
    """Обзор 1В: журнал WAL не усечён — администратор видит это в журнале событий, удаление всё равно состоялось."""
    chat_id = ivan.chat()
    response = ivan.post(f"/chats/{chat_id}/delete", confirm="yes")
    assert response.headers["location"] == "/chats"
    assert ivan.get(f"/chats/{chat_id}").status_code == 404
    assert [e.details for e in repo.audit_events("error")] == [{"kind": "CheckpointBusy", "stage": "delete"}]
    assert len(repo.audit_events("chat_deleted")) == 1


def flat(html: str) -> str:
    return " ".join(html.split())


def test_layer_is_switched_off_for_a_chat_shown_on_the_review_and_logged(ivan, repo):
    """FR-3.8: отключение — явным действием, видно на экране проверки, записано в журнал."""
    chat_id = ivan.chat()
    assert "Слой 4 — модели распознавания имён: включён" in flat(ivan.get(f"/chats/{chat_id}").text)
    ivan.post(f"/chats/{chat_id}/layers", layer="ner", enabled="no")
    assert "Слой 4 — модели распознавания имён: выключен" in flat(ivan.get(f"/chats/{chat_id}").text)
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    page = flat(ivan.get(f"/chats/{chat_id}/items/{item_id}").text)
    assert "Слой 4 — модели распознавания имён для этого текста не выполнялся" in page
    assert [e.details for e in repo.audit_events("layer_changed")] == [{"layer": "ner", "enabled": False}]
    assert ivan.post(f"/chats/{chat_id}/layers", layer="rules", enabled="no").status_code == 400
