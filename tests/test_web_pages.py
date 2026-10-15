"""Страницы интерфейса: шаблоны без встроенных стилей и скриптов (SEC-9), иконки на месте, страницы открываются."""
import re
from pathlib import Path

import pytest

from cleaner.core.types import EntityType as T

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


def css_block(css: str, pattern: str) -> dict[str, str]:
    body = re.search(pattern + r"\s*\{([^{}]*)\}", css).group(1)
    pairs = (declaration.split(":", 1) for declaration in body.split(";") if declaration.strip())
    return {name.strip(): " ".join(value.split()) for name, value in pairs}


def test_dark_palette_is_the_same_by_the_system_and_by_the_switch():
    """Тёмный набор записан дважды (спецификация вида, раздел 3): по системе и по кнопке темы. Правка одной копии
    без другой дала бы две разные тёмные темы — и ни один другой тест этого не заметил бы."""
    css = (WEB / "static" / "app.css").read_text(encoding="utf-8")
    system = css_block(css, r'@media \(prefers-color-scheme: dark\)\s*\{\s*:root:not\(\[data-theme="light"\]\)')
    assert system["--bg"] == "#0d1117" and system == css_block(css, r':root\[data-theme="dark"\]')


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


def review_page(browser_, repo) -> str:
    chat_id = browser_.chat()
    browser_.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    return browser_.get(f"/chats/{chat_id}/items/{repo.items(chat_id)[0].id}").text


def test_review_keeps_the_multiline_mask_field_and_every_tab(ivan, boss, repo):
    """Выделение через перевод строки приходит в поле целиком только в textarea; вкладки — все в разметке,
    «Замены» выбраны без JS и без запомненного выбора."""
    page = review_page(ivan, repo)
    assert '<textarea id="mask-value" name="value"' in page
    assert re.findall(r'data-tab="([a-z]+)"', page) == ["fragments", "risk", "gold"]
    assert "data-tabs data-tabs-remember" in page
    assert 'class="tab-panel on" role="tabpanel" data-tab-panel="fragments"' in page
    assert re.findall(r'data-tab="([a-z]+)"', review_page(boss, repo)) == ["fragments", "risk", "dictionary", "gold"]


def test_risk_poll_stays_in_the_page_while_its_tab_is_not_selected(ivan, repo):
    """Скрытая вкладка прячется только стилем: опрос проверки риска в ней работает, и по её концу страница
    перезагружается, какая бы вкладка ни была выбрана."""
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    repo.set_item_risk_status(chat_id, item_id, "running", ("",))
    page = ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert 'class="tab-panel" role="tabpanel" data-tab-panel="risk"' in page
    assert f'data-poll="/chats/{chat_id}/items/{item_id}/status" data-poll-field="risk"' in page


def test_review_of_a_blocked_text_offers_no_copy(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="клиент Ромашка")
    repo.add_dictionary("always", "Ромашка", T.ORG)
    page = ivan.get(f"/chats/{chat_id}/items/{repo.items(chat_id)[0].id}").text
    assert "data-copy" not in page and "/download" not in page and "Выдача заблокирована" in page


SETTINGS = [
    "/settings/providers", "/settings/local-llm", "/settings/policies", "/settings/dictionary", "/settings/patterns",
    "/settings/builtin", "/settings/gold", "/settings/users", "/settings/audit",
]


def current(page: str) -> list[str]:
    return re.findall(r'<a href="([^"]+)" class="current"', page)


def test_every_settings_page_opens_with_its_menu_item_current(boss):
    index = boss.get("/settings")
    assert index.status_code == 200 and current(index.text) == []
    assert all(f'href="{path}"' in index.text for path in SETTINGS)          # карточки девяти разделов
    for path in SETTINGS:
        response = boss.get(path)
        assert response.status_code == 200, path
        assert current(response.text) == [path], path
        assert re.findall(r'<a href="([^"]+)" class="on"', response.text) == ["/settings"], path
    preview = boss.post("/settings/dictionary/import", csv="a\r\nb\r\n", column="a", delimiter="comma", list="never", action="preview")
    assert preview.status_code == 200 and current(preview.text) == ["/settings/dictionary"]
