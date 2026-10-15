"""Страницы интерфейса: шаблоны без встроенных стилей и скриптов (SEC-9), иконки на месте, страницы открываются."""
import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parent.parent / "cleaner" / "web"
TEMPLATES = sorted((WEB / "templates").glob("*.html"))
# Под CSP `default-src 'self'` такие места молча не работают: стиль не применяется, обработчик не вызывается.
INLINE = {
    "атрибут style": re.compile(r"\sstyle\s*=", re.I),
    "элемент style": re.compile(r"<style\b", re.I),
    "обработчик on…": re.compile(r"\son[a-z]+\s*=", re.I),
    "встроенный скрипт": re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.I),
}


def inline(text: str) -> list[str]:
    return [name for name, pattern in INLINE.items() if pattern.search(text)]


def test_inline_markup_is_recognised():
    samples = ['<p style="x">', "<style>p{}</style>", '<a onclick="x()">', "<script>alert(1)</script>"]
    assert [inline(sample) for sample in samples] == [[name] for name in INLINE]
    assert inline('<script src="/static/app.js" defer></script><option value="1">') == []


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda path: path.name)
def test_template_has_no_inline_styles_or_scripts(template):
    assert inline(template.read_text(encoding="utf-8")) == []


def test_every_icon_used_in_the_templates_is_in_the_sprite(browser):
    sprite = browser().get("/static/icons.svg")
    assert sprite.headers["content-type"].startswith("image/svg+xml")
    symbols = set(re.findall(r'<symbol id="([a-z]+)"', sprite.text))
    references = re.compile(r'icon\("([a-z]+)"\)|icons\.svg#([a-z]+)')              # макрос и прямой <use>
    used = {"".join(match) for path in TEMPLATES for match in references.findall(path.read_text(encoding="utf-8"))}
    assert used and used <= symbols, used - symbols


def test_chat_pages_open_with_chats_current(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    for path in ("/chats", f"/chats/{chat_id}", f"/chats/{chat_id}/items/{item_id}", f"/chats/{chat_id}/entities"):
        response = ivan.get(path)
        assert response.status_code == 200, path
        assert re.findall(r'<a href="([^"]+)" class="on"', response.text) == ["/chats"], path


def test_layer_switch_states_its_layer_and_state(ivan):
    chat_id = ivan.chat()
    page = ivan.get(f"/chats/{chat_id}").text
    assert 'aria-pressed="true" title="Слой 4 — модели распознавания имён: включён"' in page
    ivan.post(f"/chats/{chat_id}/layers", layer="ner", enabled="no")
    assert 'aria-pressed="false" title="Слой 4 — модели распознавания имён: выключен"' in ivan.get(f"/chats/{chat_id}").text
