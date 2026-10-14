import re

from cleaner.core.types import EntityType as T


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
