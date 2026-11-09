"""Идея «Видимый отпечаток установленного кода»: sha256 исходников пакета и дата самого нового файла."""
import os
from datetime import datetime, timezone

from cleaner import version


def _tree(root, newline=b"\n"):
    (root / "web").mkdir(parents=True)
    (root / "__pycache__").mkdir()
    (root / "a.py").write_bytes(b"x = 1" + newline)
    (root / "web" / "page.html").write_bytes(b"<p>" + newline)
    (root / "__pycache__" / "a.cpython-312.pyc").write_bytes(b"\0compiled")
    stamp = datetime(2026, 11, 9, 12, tzinfo=timezone.utc).timestamp()
    for path in (root / "a.py", root / "web" / "page.html"):
        os.utime(path, (stamp, stamp))
    return root


def test_fingerprint_covers_every_source_file_and_ignores_bytecode_and_line_endings(tmp_path):
    first = version.fingerprint(_tree(tmp_path / "lf"))
    assert first.date == "2026-11-09" and len(first.digest) == 64 and first.short == first.digest[:12]
    assert version.fingerprint(_tree(tmp_path / "crlf", b"\r\n")).digest == first.digest     # Windows и Linux
    (tmp_path / "lf" / "__pycache__" / "a.cpython-312.pyc").write_bytes(b"other")
    assert version.fingerprint(tmp_path / "lf").digest == first.digest
    (tmp_path / "lf" / "web" / "page.html").write_bytes(b"<p>changed\n")
    assert version.fingerprint(tmp_path / "lf").digest != first.digest


def test_footer_shows_the_code_fingerprint_to_signed_in_users(ivan, browser):
    build = version.current()
    page = ivan.get("/chats").text
    assert f"Код {build.short} от {build.date}" in page
    assert 'href="/account/password"' in page and 'href="/account/sessions"' in page
    assert build.short not in browser().get("/login").text                  # без входа версию не видно
