"""Каркас интерфейса (аудит интерфейса 09.11.2026): шапка, меню пользователя, подвал, страница ошибки, список чатов,
главная настроек и блок «Служба»."""
import hashlib
import re
from concurrent.futures import Executor, Future

from cleaner.web.jobs import Jobs


class Held(Executor):
    """Пул, который ничего не запускает: задания стоят в очереди, пока тест их не снимет."""

    def submit(self, fn, /, *args, **kwargs):
        return Future()


def top(page: str) -> str:
    return re.search(r'<header class="top">(.*?)</header>', page, re.S).group(1)


def sections(page: str) -> list[tuple[str, str]]:
    nav = re.search(r'<nav class="sections"[^>]*>(.*?)</nav>', page, re.S).group(1)
    return re.findall(r'<a href="([^"]+)"[^>]*>([^<]+)</a>', nav)


def test_top_bar_has_three_sections_and_the_mode_switch_only_in_the_sidebar(ivan, boss):
    """Режим разговоров выбирался дважды и назывался по-разному («Чаты» / «Агенты» в шапке и «Все / Консультации /
    Агенты» в боковой панели); «Мои задания» — раздел верхнего уровня, почти всегда пустой."""
    page = ivan.get("/chats").text
    assert sections(page) == [("/chats", "Разговоры"), ("/keys", "Ключи")]
    assert sections(boss.get("/chats").text) == [("/chats", "Разговоры"), ("/keys", "Ключи"), ("/settings", "Настройки")]
    assert "kind=" not in top(page) and "Мои задания" not in top(page) and 'href="/jobs"' not in top(page)
    assert re.findall(r'<nav class="chat-kinds"[^>]*>.*?</nav>', page, re.S)
    assert re.findall(r'>(Все|Консультации|Агенты)</a>', page) == ["Все", "Консультации", "Агенты"]


def test_jobs_counter_shows_only_while_my_jobs_wait(ivan, app, repo, clock):
    pool = Jobs(Held(), budget=app.state.jobs.budget, now=clock.now)
    app.state.job_pools += (pool,)
    chat = ivan.chat()
    user = repo.user_by_login("ivan").id
    pool.submit_reserved(lambda: None, (), pool.budget.reserve(user), user=user, chat=chat, item="", kind="text")
    try:
        counter = re.search(r'<a class="jobs-count" href="/jobs"[^>]*>Задания <span class="count">(\d+)</span></a>',
                            top(ivan.get(f"/chats/{chat}").text))
        assert counter and counter.group(1) == "1"
    finally:
        [job] = pool.owned(user)
        pool.cancel(job["id"], user)
    assert "jobs-count" not in ivan.get("/chats").text


def test_user_menu_holds_own_pages_and_logout_and_the_footer_only_the_code(ivan):
    page = ivan.get("/chats").text
    menu = re.search(r'<details class="menu user-menu">(.*?)</details>', top(page), re.S).group(1)
    assert re.search(r"<summary[^>]*>.*ivan.*</summary>", menu, re.S)
    assert re.findall(r'<a href="([^"]+)">([^<]+)</a>', menu) == [
        ("/keys", "Мои ключи"), ("/account/password", "Сменить пароль"), ("/account/sessions", "Мои сессии"),
    ]
    assert re.search(r'<form method="post" action="/logout"><input type="hidden" name="csrf" value="[^"]+"><button>Выйти</button></form>', menu)
    footer = re.search(r"<footer[^>]*>(.*?)</footer>", page, re.S).group(1)
    assert "Код " in footer and "<a " not in footer                 # ссылки на свои страницы — в меню пользователя
    assert ivan.post("/logout").headers["location"] == "/login"


def test_error_page_keeps_the_top_bar_and_leads_back(ivan, browser):
    """Аудит 09.11.2026: ошибка рендерилась без вошедшего — пропадали меню, тема и «Выйти», а выход был один —
    «К списку чатов», даже если ошибка случилась на странице чата."""
    chat = ivan.chat()
    missing = ivan.get(f"/chats/{chat}/items/нет-такого")
    assert missing.status_code == 404 and "Ошибка 404" in missing.text
    assert sections(missing.text)[0] == ("/chats", "Разговоры") and "user-menu" in missing.text
    assert f'<a href="/chats/{chat}">Вернуться в чат</a> · <a href="/chats">К списку чатов</a>' in missing.text
    unknown = ivan.get("/chats/нет-такого-чата")                   # чужой и несуществующий чат — назад некуда
    assert unknown.status_code == 404 and "Вернуться" not in unknown.text and "user-menu" in unknown.text
    refused = ivan.get("/settings/users")                          # раздел администратора — назад в него нельзя
    assert refused.status_code == 403 and "Вернуться" not in refused.text and "user-menu" in refused.text
    empty = ivan.post(f"/chats/{chat}/input", text="  ")                # ошибка формы — назад в тот же чат
    assert empty.status_code == 400 and f'<a href="/chats/{chat}">Вернуться в чат</a>' in empty.text
    anonymous = browser().get("/нет-такой-страницы")
    assert anonymous.status_code == 404 and '<header class="top">' not in anonymous.text


def test_agents_mode_offers_a_key_instead_of_a_new_consultation(ivan):
    """Аудит 09.11.2026: в разделе «Агенты» пустое состояние звало «создать новый», а «Новый» создавал консультацию."""
    agents = ivan.get("/chats", kind="agent").text
    assert 'action="/chats"' not in agents.replace('action="/chats" class="search"', "")
    assert 'data-view-fold="side-folded"' in agents                # свёртка списка остаётся
    assert '<a class="btn primary" href="/keys">Выпустить ключ для агента</a>' in agents
    assert "Агент через подключение" in agents
    chats = ivan.get("/chats", kind="chat").text
    assert re.search(r'<form method="post" action="/chats" class="side-new">', chats)
    assert "Новая консультация" in chats and "Выпустить ключ" not in chats


def chat_items(page: str) -> list[str]:
    """Пункты списка чатов по порядку: заголовок группы — словом, чат — «название: значок состояния»."""
    listed = re.search(r'<ul class="chat-list">(.*?)</ul>', page, re.S).group(1)
    items = []
    for item in re.findall(r"<li[^>]*>.*?</li>", listed, re.S):
        group = re.fullmatch(r'<li class="group">([^<]+)</li>', item)
        name = re.search(r'<span class="name" title="([^"]+)">', item)
        state = re.search(r'<small class="chat-state">.*?<span class="badge[^"]*"[^>]*>(?:<svg.*?</svg>)?([^<]+)</span>', item, re.S)
        items.append(group.group(1) if group else f"{name.group(1)}: {state.group(1) if state else ''}")
    return items


def test_chat_list_shows_what_needs_action_and_groups_by_day(ivan, repo, clock):
    """Идея аудита 09.11.2026: чтобы найти чат с непроверенным текстом, приходилось открывать каждый."""
    ivan.chat("Прошлая неделя")
    clock.advance(days=6)
    ivan.login("ivan")                                              # прежняя сессия за неделю истекла
    yesterday = ivan.chat("Вчерашняя")
    ivan.post(f"/chats/{yesterday}/input", text="почта a@x.example")
    clock.advance(days=1)
    ivan.login("ivan")
    today = ivan.chat("Сегодняшняя")
    ivan.post(f"/chats/{today}/input", text="почта b@x.example")
    item = repo.items(today)[0]
    ivan.post(f"/chats/{today}/items/{item.id}/reviewed", digest=hashlib.sha256(item.sanitized.encode()).hexdigest())
    # «Проверено» и «блокировку» список не утверждает: их решают проверка утечек и нынешние политики.
    assert chat_items(ivan.get("/chats").text) == [
        "Сегодня", "Сегодняшняя: ", "Вчера", "Вчерашняя: требуется проверка", "Раньше", "Прошлая неделя: ",
    ]
    needed = ivan.get("/chats", kind="all", need="1").text
    assert chat_items(needed) == ["Вчера", "Вчерашняя: требуется проверка"]
    assert 'href="/chats?kind=all" aria-current="page"' in needed and 'name="need" value="1"' in needed
    assert "Ничего не требует действия" in ivan.get("/chats", kind="chat", need="1", q="нет такого").text


def card(page: str, href: str) -> tuple[str, str, str]:
    return re.search(rf'<a class="card" href="{href}" title="[^"]+"><strong>[^<]+</strong>'
                     rf'<span class="badge (good|warn|bad)">(?:<svg.*?</svg>)?([^<]+)</span><span class="sub">([^<]*)</span></a>',
                     page, re.S).groups()


def test_settings_home_shows_section_states_and_the_gold_reminder(boss, repo):
    """Идея аудита 09.11.2026: /settings повторял меню девятью карточками и не показывал ни одного состояния.
    Идея «Сбор собственного эталона»: счётчик «эталон — N из 200» и пустые классы — напоминание (warn)."""
    page = boss.get("/settings").text
    assert card(page, "/settings/gold")[:2] == ("warn", "эталон — 0 из 200")
    assert card(page, "/settings/gold")[2].startswith("пустых классов — 8: ")
    assert card(page, "/settings/providers")[:2] == ("warn", "включённых нет")
    assert card(page, "/settings/local-llm")[:2] == ("good", "ключ шлюза задан")
    assert card(page, "/settings/users") == ("good", "пользователей — 1", "администраторов — 1, отключено — 0")
    repo.add_dictionary("always", "Ромашка")
    repo.audit("error", kind="CheckpointBusy", stage="delete")
    page = boss.get("/settings").text
    assert card(page, "/settings/dictionary") == ("good", "записей — 1", "скрывать — 1, не скрывать — 0")
    assert card(page, "/settings/audit")[0] == "warn" and card(page, "/settings/audit")[2] == "ошибок за сутки — 1"
    assert "не прошла за 30 дней — 1" in page


def test_service_block_shows_queues_with_deadlines_and_is_polled_by_the_admin_only(boss, ivan, app, repo, clock):
    pool = Jobs(Held(), budget=app.state.jobs.budget, now=clock.now)
    app.state.job_pools += (pool,)
    user = repo.user_by_login("ivan").id
    pool.submit_reserved(lambda: None, (), pool.budget.reserve(user), user=user, chat=ivan.chat(), item="", kind="text")
    try:
        page = boss.get("/settings").text
        assert '<section class="panel service" data-refresh="/settings/service">' in page
        clock.advance(seconds=100)
        block = boss.get("/settings/service")
        assert block.status_code == 200 and "<html" not in block.text
        text = " ".join(re.sub(r"<[^>]+>", " ", block.text).split())
        assert "Входной бюджет заданий — 1 из 64" in text
        assert "Другие задания в очереди — 1 в работе — 0; ждёт с 14.10.2026 09:00; истечёт через 200 с" in text
        assert "Шлюз агентов запросов — 0 из 8 отказов 429 с запуска службы — 0" in text
        assert "Распознавание сканов служба ocr-ru доступность — не проверялось" in text
        assert ivan.get("/settings/service").status_code == 403
        assert "ivan" not in block.text and "Консультация" not in block.text      # ни владельцев, ни чатов
    finally:
        [job] = pool.owned(user)
        pool.cancel(job["id"], user)
