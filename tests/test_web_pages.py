"""Страницы интерфейса: шаблоны без встроенных стилей и скриптов (SEC-9), иконки на месте, страницы открываются."""
import re
from pathlib import Path
from xml.etree import ElementTree

import pytest

from cleaner.core.types import EntityType as T
from cleaner.storage.repo import Provider

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


def theme_modes(page: str) -> list[str]:
    group = re.search(r'<div class="segmented theme-set" role="group" aria-label="Тема">(.*?)</div>', page, re.S).group(1)
    return re.findall(r'data-theme-set="([a-z]+)" aria-pressed="false"[^>]*>.*?</svg>([^<]+)</button>', group, re.S)


def test_theme_is_three_buttons_on_login_and_in_the_view_menu(browser, ivan):
    """Аудит 21.10.2026: после первого переключения вернуть «как в системе» было нельзя, а на входе темы не было вовсе.
    Аудит 09.11.2026: кнопка по кругу при светлой системе первым нажатием видимо ничего не меняла, и в шапке стояли
    три кнопки оформления подряд — теперь три сегмента в меню «Вид», выбранный виден сразу (aria-pressed)."""
    modes = [("system", "Система"), ("light", "Светлая"), ("dark", "Тёмная")]
    assert theme_modes(browser().get("/login").text) == modes
    page = ivan.get("/chats").text
    assert theme_modes(re.search(r'<details class="menu view-menu">(.*?)</details>', page, re.S).group(1)) == modes
    assert "data-theme-toggle" not in page
    css = (WEB / "static" / "app.css").read_text(encoding="utf-8")
    assert "html:not(.js) .theme-set" in css                # без JS выбирать нечем
    assert 'button.setAttribute("aria-pressed", String(button.dataset.themeSet === current))' in (
        WEB / "static" / "app.js").read_text(encoding="utf-8")


def test_browser_storage_keeps_only_the_theme_and_the_tab():
    """Хранилища браузера — только оформление и выбор вкладки (раздел 6 спецификации вида): ни текстов форм, ни данных
    чатов. Запись — только по ключам темы, вида рабочего места, синхронной прокрутки проверки и вкладки."""
    script = (WEB / "static" / "app.js").read_text(encoding="utf-8")
    keys = re.findall(r"(?:local|session)Storage\.setItem\(([^,]+),", script)
    assert sorted(set(keys)) == ['"cleaner-sync-scroll"', '"cleaner-theme"', '"cleaner-view"', "key"]
    assert 'const key = `tab:${window.location.pathname}`' in script
    assert 'localStorage.setItem("cleaner-view", marks.join(" "))' in script     # только имена отметок вида


def view_marks() -> list[str]:
    """Отметки, которые theme.js ставит из localStorage до отрисовки, — только из своего списка."""
    script = (WEB / "static" / "theme.js").read_text(encoding="utf-8")
    return re.findall(r'"([a-z-]+)"', re.search(r"const marks = \[([^\]]*)\]", script).group(1))


def test_every_view_mark_has_its_switch_its_style_and_survives_a_reload(boss):
    """Идея аудита 21.10.2026: меню «Вид» в шапке. Отметка, которой нет в списке theme.js, работала бы до перезагрузки
    и пропадала после; отметка без правила в app.css ничего бы не меняла."""
    page = boss.get("/chats").text
    menu = re.search(r'<details class="menu view-menu">(.*?)</details>', page, re.S).group(1)
    assert re.findall(r'data-view-toggle="([a-z-]+)" aria-pressed="false"', menu) == view_marks()
    css = (WEB / "static" / "app.css").read_text(encoding="utf-8")
    assert all(f":root.view-{mark}" in css for mark in view_marks())
    assert "html:not(.js) .view-menu" in css                    # без JS переключать нечем — меню не показывается


def test_chat_list_and_composer_fold_in_place(ivan):
    """Свёрнутые список чатов и редактор разворачиваются на месте, не только из меню «Вид»."""
    page = ivan.get(f"/chats/{ivan.chat()}").text
    folds = re.findall(r'data-view-fold="([a-z-]+)" aria-expanded="true"', page)
    assert folds == ["side-folded", "composer-folded"] and set(folds) <= set(view_marks())
    # Кнопка свёртки редактора — не в tablist: там только вкладки.
    assert "data-view-fold" not in re.search(r'<div class="tab-list" role="tablist">(.*?)</div>', page, re.S).group(1)


def test_check_buttons_name_what_they_check():
    """Идея аудита 21.10.2026: «Проверить» без объекта — на подключениях, локальной модели и шаблонах — не говорит,
    что будет проверено."""
    bare = [path.name for path in TEMPLATES if re.search(r">\s*Проверить\s*<", path.read_text(encoding="utf-8"))]
    assert bare == []


def test_every_icon_used_in_the_templates_is_in_the_sprite(browser):
    sprite = browser().get("/static/icons.svg")
    assert sprite.headers["content-type"].startswith("image/svg+xml")
    symbols = set(re.findall(r'<symbol id="([a-z]+)"', sprite.text))
    references = re.compile(r'icon\("([a-z]+)"\)|icons\.svg#([a-z]+)')              # макрос и прямой <use>
    used = {"".join(match) for path in TEMPLATES for match in references.findall(path.read_text(encoding="utf-8"))}
    assert used and used <= symbols, used - symbols


def test_pages_name_their_icon(browser):
    """Без <link rel="icon"> браузер сам запрашивает /favicon.ico, а такого адреса нет: каждая вкладка писала в
    консоль 404. Значок — файлом из static (CSP), с заголовками безопасности, как остальные."""
    b = browser()
    href = re.search(r'<link rel="icon" href="([^"]+)"', b.get("/login").text).group(1)
    icon = b.get(href)
    assert href.startswith("/static/") and icon.status_code == 200
    assert icon.headers["content-type"].startswith("image/svg+xml")
    assert icon.headers["content-security-policy"].startswith("default-src 'self'")
    ElementTree.fromstring(icon.content)            # испорченный XML браузер молча не рисует: «--» в комментарии


def test_chat_pages_open_with_chats_current(ivan, repo):
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    paths = ("/chats", f"/chats/{chat_id}", f"/chats/{chat_id}/items/{item_id}", f"/chats/{chat_id}/entities", f"/chats/{chat_id}/manual")
    for path in paths:
        response = ivan.get(path)
        assert response.status_code == 200, path
        assert re.findall(r'<a href="([^"]+)" class="on"', response.text) == ["/chats"], path


LONG_TITLE = "Согласование договора поставки серверного оборудования для филиала «Север» на четвёртый квартал"


def test_a_cut_chat_title_is_whole_in_its_tooltip(ivan, repo):
    """Длинное название обрезается многоточием в шапке чата, в списке чатов и в «хлебных крошках»; целиком оно —
    в подсказке, а не только в поле переименования."""
    chat_id = ivan.chat(LONG_TITLE)
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    provider = repo.add_provider(Provider("", "Облако", "openai", "https://llm.example/v1", "bearer", "sk-test-0123", ("m-1",), 512))
    ivan.post(f"/chats/{chat_id}/provider", choice=f"{provider}|m-1")
    page = ivan.get(f"/chats/{chat_id}").text
    assert f'<h1 title="{LONG_TITLE}">{LONG_TITLE}</h1>' in page
    assert f'<span class="name" title="{LONG_TITLE}">{LONG_TITLE}</span>' in page
    for path in (f"/chats/{chat_id}/items/{item_id}", f"/chats/{chat_id}/entities", f"/chats/{chat_id}/send", f"/chats/{chat_id}/manual"):
        assert f'<a href="/chats/{chat_id}" title="{LONG_TITLE}">{LONG_TITLE}</a>' in ivan.get(path).text, path


def test_chat_composer_tab_is_remembered(ivan):
    """Аудит 21.10.2026: перезагрузка по концу задания возвращала редактор на «Текст», даже если писали ответ вручную."""
    page = ivan.get(f"/chats/{ivan.chat()}").text
    assert re.search(r'<div class="tabs" data-tabs data-tabs-remember>\s*<div class="tab-list" role="tablist">\s*'
                     r'<button type="button" role="tab" data-tab="text"', page)


def test_layer_switch_states_its_layer_and_state(ivan):
    """На кнопке — что слой даёт, номер слоя и состояние — в подсказке (идея аудита 21.10.2026)."""
    chat_id = ivan.chat()
    page = ivan.get(f"/chats/{chat_id}").text
    assert 'aria-pressed="true" title="Слой 4 — модели распознавания имён: включён"' in page
    labels = re.findall(r'<button class="toggle"[^>]*><span class="switch"></span>([^<]+)</button>', page)
    assert labels == ["Имена и организации", "Допроверка локальной моделью"]
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
    job = repo.queue_risk(chat_id, item_id, ("",))
    repo.set_item_risk_status(chat_id, item_id, job, "running", ("queued",))
    page = ivan.get(f"/chats/{chat_id}/items/{item_id}").text
    assert 'class="tab-panel" role="tabpanel" data-tab-panel="risk"' in page
    assert f'data-poll="/chats/{chat_id}/items/{item_id}/status" data-poll-field="risk"' in page


def risk_tab(page: str) -> str:
    return re.search(r'data-tab="risk" aria-selected="false">(.*?)</button>', page).group(1)


def test_risk_check_state_is_on_its_tab_label(ivan, repo):
    """Идущая, не выполненная и прерванная проверка видна на ярлыке вкладки — и когда выбрана другая вкладка, и когда
    браузер не даёт sessionStorage (выбор не переживает перенаправление). Готовая и не запускавшаяся — без отметки."""
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    item_id = repo.items(chat_id)[0].id
    path = f"/chats/{chat_id}/items/{item_id}"
    assert risk_tab(ivan.get(path).text) == "Остаточный риск"
    job = repo.queue_risk(chat_id, item_id, ("",))
    labels = {"queued": risk_tab(ivan.get(path).text)}
    for status, current in (("running", "queued"), ("failed", "running"), ("interrupted", "failed")):
        repo.set_item_risk_status(chat_id, item_id, job, status, (current,))
        labels[status] = risk_tab(ivan.get(path).text)
    assert labels == {
        "queued": 'Остаточный риск <span class="badge">идёт проверка</span>',
        "running": 'Остаточный риск <span class="badge">идёт проверка</span>',
        "failed": 'Остаточный риск <span class="badge bad">ошибка проверки</span>',
        "interrupted": 'Остаточный риск <span class="badge bad">проверка прервана</span>',
    }
    repo.set_item_risk_status(chat_id, item_id, job, "running", ("interrupted",))
    repo.set_item_risk(chat_id, item_id, job, repo.item(chat_id, item_id).sanitized, {"guesses": []})
    assert risk_tab(ivan.get(path).text) == "Остаточный риск"


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


def test_settings_are_grouped_by_task_in_the_menu_and_on_the_cards(boss):
    """Идея аудита 21.10.2026: группы по задачам вместо общей «Качество и доступ»; меню и карточки — из одного списка,
    у каждой карточки одна строка «что получите». С 09.11.2026 она — в подсказке, на карточке — состояние раздела."""
    groups = ["Модели и подключения", "Правила очистки", "Качество", "Доступ и аудит"]
    index = boss.get("/settings").text
    menu = re.search(r'<aside class="side side-nav"[^>]*>(.*?)</aside>', index, re.S).group(1)
    assert re.findall(r"<h2>([^<]+)</h2>", menu) == groups
    cards = index[index.index("</aside>"):]
    assert re.findall(r"<h2>([^<]+)</h2>", cards) == groups + ["Служба"]
    lines = re.findall(r'<a class="card" href="([^"]+)" title="([^"]+)"><strong>[^<]+</strong><span class="badge (?:good|warn|bad)">', cards)
    assert [href for href, _ in lines] == SETTINGS and all(line.strip() for _, line in lines)
    assert "внутренними суффиксами доменов" in dict(lines)["/settings/builtin"]


def test_layer_defaults_are_named_by_what_they_give(boss):
    page = boss.get("/settings/local-llm").text
    assert re.findall(r'name="(ner|llm)" value="yes"[^>]*> ([^<]+) <span class="hint">([^<]+)</span>', page) == [
        ("ner", "Имена и организации", "слой 4 — модели распознавания имён"),
        ("llm", "Допроверка локальной моделью", "слой 5 — локальная модель"),
    ]
