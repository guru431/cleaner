import json
import logging

OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32 + "EncryptedPackage".encode("utf-16-le")
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def files_bytes(tmp_path) -> bytes:
    return b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())


def test_text_file_is_decoded_cleaned_and_its_name_is_kept_nowhere(ivan, repo, tmp_path, caplog):
    """FR-2.4, FR-2.7: имени файла нет ни в базе, ни в журнале, ни в логах; сам файл нигде не записан."""
    caplog.set_level(logging.DEBUG)
    chat_id = ivan.chat()
    response = ivan.upload(f"/chats/{chat_id}/upload", "Договор Петрова Zq83.txt", "почта a@x.example".encode("cp1251"))
    [item] = repo.items(chat_id)
    assert response.headers["location"] == f"/chats/{chat_id}/items/{item.id}"
    assert (item.source, item.status, item.sanitized, item.meta["kind"]) == ("file", "done", "почта <EMAIL_1>", "text")
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = files_bytes(tmp_path)
    journal = json.dumps([(a.event, a.details) for a in repo.audit_events(limit=100)], ensure_ascii=False)
    for value in ("Zq83", "Петрова", "a@x.example"):
        assert value.encode("utf-8") not in raw and value.encode("cp1251") not in raw, value
        assert value not in journal and value not in caplog.text, value
    assert [e.details["source"] for e in repo.audit_events("sanitize")] == ["file"]


def test_scan_is_recognised_and_marked_on_the_review(ivan, repo):
    """FR-2.5, FR-6.7."""
    chat_id = ivan.chat()
    ivan.upload(f"/chats/{chat_id}/upload", "scan.png", PNG)
    [item] = repo.items(chat_id)
    assert (item.sanitized, item.meta["ocr_pages"]) == ("Скан: почта <EMAIL_1>", [1])
    assert "получен распознаванием изображения" in ivan.get(f"/chats/{chat_id}/items/{item.id}").text
    page = ivan.get(f"/chats/{chat_id}").text
    assert '<span class="title">Файл 1</span>' in page and f'href="/chats/{chat_id}/items/{item.id}"' in page


def test_password_protected_file_fails_with_a_reason_and_no_retry(ivan, repo):
    """AC-2.4 в быстром наборе; повторять нечего — файл не хранится."""
    chat_id = ivan.chat()
    ivan.upload(f"/chats/{chat_id}/upload", "secret.docx", OLE)
    [item] = repo.items(chat_id)
    assert (item.status, item.meta["error"]) == ("failed", "Файл защищён паролем: снимите защиту и загрузите его снова")
    page = ivan.get(f"/chats/{chat_id}").text
    assert "Файл защищён паролем" in page and f"/items/{item.id}/retry" not in page


def test_oversized_and_empty_uploads_are_refused(ivan, repo, app):
    app.state.max_file_bytes = 1024
    chat_id = ivan.chat()
    assert ivan.upload(f"/chats/{chat_id}/upload", "big.txt", b"x" * 2048).status_code == 413
    assert ivan.client.post(f"/chats/{chat_id}/upload", data={"csrf": ivan.csrf}).status_code == 400
    assert repo.items(chat_id) == []


def test_file_above_the_form_body_limit_but_within_max_file_mb_is_accepted(ivan, repo):
    """Предел тела запроса (8 МиБ, план 1В) не урезает предел файла: max_file_mb по умолчанию — 50 МБ (FR-2.2)."""
    chat_id = ivan.chat()
    response = ivan.upload(f"/chats/{chat_id}/upload", "big.png", PNG + b"\x00" * (9 * 1024 * 1024))
    assert response.status_code == 303
    [item] = repo.items(chat_id)
    assert (item.status, item.meta["kind"]) == ("done", "image")


def test_upload_needs_the_form_token_and_an_own_chat(browser, ivan, repo):
    chat_id = ivan.chat()
    forged = ivan.client.post(f"/chats/{chat_id}/upload", data={"csrf": "x"}, files={"file": ("a.txt", b"x")})
    assert forged.status_code == 403
    boris = browser()
    boris.user("boris")
    boris.login("boris")
    assert boris.upload(f"/chats/{chat_id}/upload", "a.txt", b"x").status_code == 404
    assert repo.items(chat_id) == []
