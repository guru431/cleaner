import re
from pathlib import Path
from types import SimpleNamespace

import regex

from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.engines import LocalSettings, local_settings
from cleaner.eval import runner
from cleaner.local_llm import LocalLLMError
from cleaner.web.routes_settings import EVENTS


def test_settings_are_for_admins_only(ivan):
    for path in (
        "/settings", "/settings/policies", "/settings/dictionary", "/settings/patterns",
        "/settings/builtin", "/settings/users", "/settings/audit",
    ):
        assert ivan.get(path).status_code == 403, path
    assert ivan.post("/settings/policies", **{"policy-CARD": "block"}).status_code == 403


def test_policies_are_saved_and_logged(boss, repo):
    boss.post("/settings/policies", **{"policy-CARD": "block", "policy-SECRET": "hide"})
    assert repo.policies()[T.CARD] is Policy.BLOCK
    assert [e.details for e in repo.audit_events("policy_changed")] == [{"type": "CARD", "policy": "block"}]
    assert boss.post("/settings/policies", **{"policy-CARD": "всегда"}).status_code == 400
    assert repo.policies()[T.CARD] is Policy.BLOCK


def test_dictionary_entries_are_added_shown_escaped_and_deleted(boss, repo):
    boss.post(
        "/settings/dictionary", list="always", value="<b>Ромашка</b>", type="ORG",
        aliases="Romashka\nРомашка-М", comment="клиент",
    )
    [row] = repo.dictionary()
    assert (row.type, row.value, row.aliases, row.comment) == (T.ORG, "<b>Ромашка</b>", ("Romashka", "Ромашка-М"), "клиент")
    assert "&lt;b&gt;Ромашка&lt;/b&gt;" in boss.get("/settings/dictionary").text
    boss.post(f"/settings/dictionary/{row.id}/delete")
    assert repo.dictionary() == []
    assert [e.details for e in repo.audit_events("dictionary_changed")] == [
        {"action": "delete", "list": "always"}, {"action": "add", "list": "always"},
    ]
    assert boss.post("/settings/dictionary", list="always", value="Без типа").status_code == 400


def test_value_already_in_the_same_list_is_refused(boss, repo):
    """Самопроверка плана 1Б: повтор значения в том же списке — отказ, а не вторая строка (как при импорте CSV)."""
    boss.post("/settings/dictionary", list="always", value="Ромашка", type="ORG")
    duplicate = boss.post("/settings/dictionary", list="always", value=" ромашка ", type="PERSON")
    assert duplicate.status_code == 400 and "уже есть" in duplicate.text
    assert boss.post("/settings/dictionary", list="never", value="Ромашка").status_code == 303
    chat_id = boss.chat()
    assert boss.post(f"/chats/{chat_id}/dictionary", value="РОМАШКА", list="never").status_code == 400
    assert sorted((r.list, r.value) for r in repo.dictionary()) == [("always", "Ромашка"), ("never", "Ромашка")]
    assert len(repo.audit_events("dictionary_changed")) == 2


def test_deleting_an_unknown_pattern_is_not_found_and_not_logged(boss, repo):
    """Самопроверка плана 1Б: удаление несуществующего шаблона — 404, как у словаря, без записи в журнал."""
    pattern_id = repo.add_pattern("Инвентарный", r"INV-\d{6}", T.TERM)
    assert boss.post(f"/settings/patterns/{'0' * 32}/delete").status_code == 404
    assert boss.post(f"/settings/patterns/{pattern_id}/delete").status_code == 303
    assert boss.post(f"/settings/patterns/{pattern_id}/delete").status_code == 404
    assert repo.patterns() == []
    assert [e.details for e in repo.audit_events("pattern_changed")] == [{"action": "delete"}]


def test_csv_import_shows_a_preview_before_writing(boss, repo):
    repo.add_dictionary("never", "known.example")
    csv_text = "﻿Name;DNSHostName\r\nsrv1;srv1.corp.example\r\nsrv2;known.example\r\nsrv3;srv1.corp.example\r\n"
    fields = {"csv": csv_text, "delimiter": "semicolon", "list": "never"}
    preview = boss.post("/settings/dictionary/import", column="DNSHostName", action="preview", **fields)
    assert preview.status_code == 200 and "новых для списка: 1" in preview.text
    assert len(repo.dictionary()) == 1                                       # предпросмотр ничего не пишет
    boss.post("/settings/dictionary/import", column="DNSHostName", action="save", **fields)
    assert sorted(r.value for r in repo.dictionary()) == ["known.example", "srv1.corp.example"]
    assert [e.details for e in repo.audit_events("dictionary_import")] == [{"list": "never", "count": 1}]
    assert boss.post("/settings/dictionary/import", column="Нет", action="save", **fields).status_code == 400


def test_dictionary_is_paged_filtered_and_searched_without_values_in_the_address(boss, repo):
    """FINDINGS «Интерфейс: словарь выводится целиком, без поиска и страниц»: страницы по 100 строк, отбор по списку и
    типу — кодами в адресе, поиск по значению и вариантам — формой POST, без учёта регистра и «ё»."""
    repo.add_dictionary_many("always", [f"srv{n:03d}.corp.example" for n in range(230)], T.HOST)
    repo.add_dictionary("always", "Ромашка", T.ORG, ("Romashka", "Ёлка-М"))
    repo.add_dictionary("never", "intranet.example")
    rows = lambda response: re.findall(r'<td class="mono">([^<]+)</td><td class="nowrap">', response.text)
    first = boss.get("/settings/dictionary")
    assert len(rows(first)) == 100 and "Показаны 1–100 из 232" in first.text and "?page=2" in first.text
    pages = [rows(boss.get("/settings/dictionary", page=str(number))) for number in (1, 2, 3)]
    assert [len(shown) for shown in pages] == [100, 100, 32] and pages[2][-1] == "intranet.example"    # «никогда» — последним
    assert len({value for shown in pages for value in shown}) == 232
    assert rows(boss.get("/settings/dictionary", type="ORG")) == ["Ромашка"]
    assert rows(boss.get("/settings/dictionary", list="never")) == ["intranet.example"]
    assert boss.get("/settings/dictionary", page="99").status_code == 200
    assert boss.get("/settings/dictionary", list="все").status_code == 400
    assert boss.get("/settings/dictionary", type="НЕТ").status_code == 400
    found = boss.post("/settings/dictionary/search", q="елка", list="", type="")
    assert found.status_code == 200 and rows(found) == ["Ромашка"]
    assert sorted(rows(boss.post("/settings/dictionary/search", q="SRV12", list="always", type="HOST"))) == [
        f"srv{n:03d}.corp.example" for n in range(120, 130)
    ]
    assert len(rows(boss.post("/settings/dictionary/search", q="srv", list="always", type="HOST", page="3"))) == 30
    plain = boss.post("/settings/dictionary/search", q=" ", list="always", type="ORG", page="2")
    assert plain.status_code == 303 and plain.headers["location"] == "/settings/dictionary?list=always&type=ORG&page=2"


def test_dictionary_entry_in_all_cases_shows_its_forms_and_is_kept_by_apply(boss, repo):
    """IDEAS «Словарь: падежные формы для людей, организаций и терминов»: отметка «искать во всех падежах» хранится у
    записи, «Оценить добавление» показывает формы, после применения они — варианты записи в настройках ядра. У типа без
    падежей отметка не хранится."""
    from cleaner import settings_impact

    page = boss.get("/settings/dictionary").text
    assert 'name="inflect"' in page and "падеж" in page
    shown = boss.post("/settings/dictionary", list="always", value="Проект Полярис", type="TERM", inflect="1", action="impact")
    assert shown.status_code == 200 and "Проекту Полярис" in shown.text and repo.dictionary() == []
    receipt = re.search(r'name="receipt" value="([^"]+)"', shown.text).group(1)
    settings_impact.apply(repo, repo.user_by_login("boss").id, receipt)
    [row] = repo.dictionary()
    assert row.inflect and row.aliases == ()
    [entry] = repo.settings().always
    assert "Проекту Полярис" in entry.aliases and "во всех падежах" in boss.get("/settings/dictionary").text
    boss.post("/settings/dictionary", list="always", value="srv01.corp.example", type="HOST", inflect="1")
    assert sorted((r.value, r.inflect) for r in repo.dictionary()) == [("srv01.corp.example", False), ("Проект Полярис", True)]


def test_pattern_is_tried_on_a_sample_before_saving(boss, repo, monkeypatch):
    fields = {"name": "Инвентарный", "regex": r"INV-\d{6}", "type": "TERM"}
    tried = boss.post("/settings/patterns", sample="INV-123456 и INV-12", action="test", **fields)
    assert "Совпадений: 1" in tried.text and repo.patterns() == []
    boss.post("/settings/patterns", sample="INV-123456", action="save", **fields)
    assert [p.regex for p in repo.patterns()] == [r"INV-\d{6}"]
    for bad in ("(", r"\d*"):                                        # не разбирается; находит пустую строку
        response = boss.post("/settings/patterns", name="Плохой", regex=bad, type="TERM", sample="1", action="save")
        assert response.status_code == 400, bad

    compiled = regex.compile("(a+)+$")

    class TooSlow:
        match = compiled.match

        def finditer(self, *args, **kwargs):
            raise TimeoutError

    monkeypatch.setattr(regex, "compile", lambda expression: TooSlow())
    slow = boss.post("/settings/patterns", name="Медленный", regex="(a+)+$", type="TERM", sample="a" * 30 + "b", action="save")
    assert slow.status_code == 400 and "долго" in slow.text
    assert len(repo.patterns()) == 1


def test_builtin_lists_are_shown_and_extended_through_the_never_list(boss, repo):
    page = boss.get("/settings/builtin").text
    assert "microsoft.com" in page and "administrator" in page
    response = boss.post("/settings/dictionary", list="never", value="intranet.example", back="builtin")
    assert response.headers["location"] == "/settings/builtin"
    assert repo.settings().never == frozenset({"intranet.example"})


def test_internal_suffixes_are_shown_extended_and_reduced(boss, repo):
    """IDEAS P3 «список суффиксов на странице встроенных списков»: встроенные видны, свои добавляются и удаляются и действуют
    на распознавание сразу."""
    from cleaner.core.entities import hostmap
    from cleaner.web.routes_settings import apply_suffixes

    page = boss.get("/settings/builtin").text
    assert "localdomain" in page and "loc" in page
    try:
        assert boss.post("/settings/builtin/suffixes", value=".LCL").headers["location"] == "/settings/builtin"
        assert hostmap.has_known_suffix("srv01.romashka.lcl")
        assert "lcl" in boss.get("/settings/builtin").text
        for value in ("lcl", "loc", "ru", "a b", ""):
            assert boss.post("/settings/builtin/suffixes", value=value).status_code == 400, value
        apply_suffixes(repo)            # перезапуск службы: дополнение берётся из базы
        assert hostmap.extra_suffixes == ("lcl",)
        assert [e.details for e in repo.audit_events("settings_changed")][-1] == {"section": "internal_suffixes", "action": "add"}
        boss.post("/settings/builtin/suffixes/lcl/delete")
        assert not hostmap.has_known_suffix("srv01.romashka.lcl")
        assert boss.post("/settings/builtin/suffixes/lcl/delete").status_code == 404
    finally:
        hostmap.set_extra_suffixes(())


def test_users_are_created_given_new_passwords_and_disabled(boss, browser, repo):
    boss.post("/settings/users", login="petr", password="длинный-пароль-1", role="user")
    petr = repo.user_by_login("petr")
    other = browser()
    assert other.login("petr", "длинный-пароль-1").status_code == 303
    boss.post(f"/settings/users/{petr.id}/password", password="другой-пароль-22")
    assert other.get("/").headers["location"] == "/login"                    # смена пароля закрывает сессии
    boss.post(f"/settings/users/{petr.id}/disable", disabled="yes")
    assert other.login("petr", "другой-пароль-22").status_code == 401
    assert boss.post("/settings/users", login="short", password="коротко", role="user").status_code == 400
    assert boss.post("/settings/users", login="petr", password="длинный-пароль-1", role="user").status_code == 400
    me = repo.user_by_login("boss")
    assert boss.post(f"/settings/users/{me.id}/disable", disabled="yes").status_code == 400
    assert {"user_created", "password_changed", "user_disabled"} <= {e.event for e in repo.audit_events()}


def test_disabled_account_is_deleted_with_all_its_chats(boss, browser, repo, app):
    """Идея «Удаление учётной записи вместе с её чатами»: только отключённая запись, с подтверждением логином; чаты —
    через ChatService.delete_chat (ключи чатов стёрты, журнал WAL усечён), в журнал — событие без данных."""
    other = browser()
    petr = other.user("petr")
    other.login("petr")
    chats = [other.chat("Первый"), other.chat("Второй")]
    assert boss.post(f"/settings/users/{petr}/delete", confirm="petr").status_code == 400      # ещё включён
    boss.post(f"/settings/users/{petr}/disable", disabled="yes")
    assert boss.post(f"/settings/users/{petr}/delete", confirm="ivan").status_code == 400      # не тот логин
    assert repo.user(petr) is not None and all(repo.chat(chat) for chat in chats)
    assert "Удалить вместе с чатами" in boss.get("/settings/users").text
    deleted = []
    app.state.service.stop_chat = deleted.append              # путь ChatService.delete_chat, а не каскад схемы
    assert boss.post(f"/settings/users/{petr}/delete", confirm="petr").status_code == 303
    assert sorted(deleted) == sorted(chats)
    assert repo.user(petr) is None and repo.chat_ids(petr) == [] and not any(repo.chat(chat) for chat in chats)
    assert repo.conn.execute("SELECT COUNT(*) FROM chats WHERE user_id = ?", (petr,)).fetchone()[0] == 0
    [event] = repo.audit_events("user_deleted")
    assert (event.user_id, event.details) == (repo.user_by_login("boss").id, {"target": petr, "chats": 2})
    assert len(repo.audit_events("chat_deleted")) == 2
    assert boss.post(f"/settings/users/{petr}/delete", confirm="petr").status_code == 404


def test_deleted_account_takes_the_gold_examples_of_its_chats(boss, browser, repo):
    """Находка «Удаление чата «безвозвратно»…»: удаление учётной записи удаляет чаты тем же путём, что и кнопка, —
    с примерами эталона из них. Пример, который владелец сам оставил в наборе при удалении чата, остаётся: он уже
    передан в общий набор, и удаляет его администратор на странице «Эталонный набор»."""
    other = browser()
    petr = other.user("petr")
    other.login("petr")
    for title in ("Оставленный", "Текущий"):
        chat_id = other.chat(title)
        other.post(f"/chats/{chat_id}/input", text="почта a@x.example")
        other.post(f"/chats/{chat_id}/items/{repo.items(chat_id)[0].id}/gold", purpose="tuning", source=title)
    left = next(chat for chat in repo.chat_ids(petr) if repo.chat(chat).title == "Оставленный")
    other.post(f"/chats/{left}/delete", confirm="yes", gold_shown="yes")
    boss.post(f"/settings/users/{petr}/disable", disabled="yes")
    assert boss.post(f"/settings/users/{petr}/delete", confirm="petr").status_code == 303
    assert [row.metadata["source"] for row in repo.gold()] == ["Оставленный"]
    assert [e.details for e in repo.audit_events("chat_deleted")] == [{"via": "user_deleted", "gold": 1}, {"gold_kept": 1}]


def test_every_password_form_names_whose_password_it_is(boss):
    """Форма нового пароля без поля логина: менеджер паролей браузера записал бы новый пароль пользователя к учётной
    записи вошедшего администратора. Логин строки — скрытым полем без name: на сервер он не уходит."""
    boss.post("/settings/users", login="petr", password="длинный-пароль-1", role="user")
    page = boss.get("/settings/users").text
    for login in ("boss", "petr"):
        assert f'<input hidden autocomplete="username" value="{login}">' in page
    assert '<input name="login" autocomplete="username" required>' in page


def test_audit_is_filtered_by_event_user_and_day(browser, repo, clock):
    ivan = repo.create_user("ivan", "hash", "user")
    repo.audit("restore", ivan, restored=2)                                   # 14.10
    clock.advance(days=1)
    admin = browser()
    admin.user("boss", "admin")
    admin.login("boss")                                                       # 15.10

    def events(**params: str) -> list[str]:
        return re.findall(r'<td class="event">([^<]+)</td>', admin.get("/settings/audit", **params).text)

    assert events() == ["login", "restore"]
    assert events(event="restore") == ["restore"]
    assert events(user=ivan) == ["restore"]
    assert events(since="2026-10-15") == ["login"]
    assert events(until="2026-10-14") == ["restore"]
    assert admin.get("/settings/audit", since="вчера").status_code == 400


def test_audit_is_exported_as_csv_with_the_current_filter(browser, repo, clock):
    """Идея «Выгрузка журнала в CSV за период»: тот же отбор, что на странице, без предела в 500 строк; ячейки,
    которые таблица сочла бы формулой, обезврежены; сама выгрузка — событие журнала."""
    import csv
    import io

    ivan = repo.create_user("=HYPERLINK(\"x\")", "hash", "user")
    for _ in range(501):
        repo.audit("restore", ivan, restored=2)                               # 14.10
    repo.audit("leak", ivan, note="@SUM(1)")
    clock.advance(days=1)
    admin = browser()
    admin.user("boss", "admin")
    admin.login("boss")                                                       # 15.10
    response = admin.get("/settings/audit/export", user=ivan, until="2026-10-14")
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert rows[0] == ["time_utc", "login", "user_id", "chat_id", "event", "details"]
    assert len(rows) == 1 + 502 and {row[4] for row in rows[1:]} == {"restore", "leak"}
    assert rows[1][1] == "'=HYPERLINK(\"x\")" and rows[1][5] == '{"note": "@SUM(1)"}'
    assert all(not cell.startswith(("=", "+", "-", "@", "\t", "\r")) for row in rows for cell in row)
    [event] = repo.audit_events("audit_export")
    assert event.details == {"rows": 502, "filter": {"event": "", "user": ivan, "since": "", "until": "2026-10-14"}}
    assert browser().get("/settings/audit/export").status_code == 303                 # без входа — на страницу входа


def test_audit_filter_lists_every_event_the_service_writes():
    """Ревью 2026-10-21: событие «reviewed» в фильтр журнала не попало. Сверка с исходниками: каждое имя события в
    repo.audit("…") есть в списке фильтра."""
    root = Path(__file__).resolve().parents[1] / "cleaner"
    written = {
        name for path in root.rglob("*.py")
        for name in re.findall(r'\.audit\(\s*"(\w+)"(?:\s+if\s+\w+\s+else\s+"(\w+)")?', path.read_text(encoding="utf-8"))
        for name in name if name
    }
    assert "reviewed" in written and written <= set(EVENTS)


def test_local_model_settings_are_saved_and_a_public_address_is_refused(boss, repo):
    boss.post(
        "/settings/local-llm", url="http://10.20.0.10:30000/v1", model="qwen-27b-fast", trusted="", schema="prompt",
        ocr_model=" tencent/HunyuanOCR ",
    )
    assert local_settings(repo) == LocalSettings(
        "http://10.20.0.10:30000/v1", "qwen-27b-fast", frozenset(), False, "tencent/HunyuanOCR",
    )
    response = boss.post("/settings/local-llm", url="http://8.8.8.8:30000/v1", model="x", trusted="")
    assert response.status_code == 400 and "не петлевой" in response.text
    assert local_settings(repo).url == "http://10.20.0.10:30000/v1"
    assert [e.details for e in repo.audit_events("settings_changed")] == [{"section": "local_llm"}]


def test_local_model_check_reports_the_outcome(boss, engines):
    assert "Локальная модель ответила" in boss.post("/settings/local-llm/check").text
    engines.completer.error = LocalLLMError("unavailable", "локальная модель недоступна")
    assert "Проверка не прошла: локальная модель недоступна" in boss.post("/settings/local-llm/check").text


def test_local_model_settings_are_for_admins_only(ivan):
    assert ivan.get("/settings/local-llm").status_code == 403
    assert ivan.post("/settings/local-llm", url="http://127.0.0.1:30000/v1", model="m").status_code == 403


def test_gold_list_shows_counts_but_no_text_and_only_to_admins(boss, ivan, repo):
    user = repo.user_by_login("ivan").id
    gold_id = repo.add_gold(user, "секрет Gg44 текст", [{"start": 0, "end": 6, "type": "TERM", "entity": 0, "origin": "manual"}])
    page = boss.get("/settings/gold").text
    assert "TERM — 1" in page and "ivan" in page and "Gg44" not in page
    assert ivan.get("/settings/gold").status_code == 403
    boss.post(f"/settings/gold/{gold_id}/delete")
    assert repo.gold() == []
    assert boss.post(f"/settings/gold/{gold_id}/delete").status_code == 404
    assert len(repo.audit_events("gold_deleted")) == 1


GOLD_SPANS = [
    {"start": 7, "end": 13, "type": "PERSON", "entity": 0, "origin": "detector"},
    {"start": 21, "end": 32, "type": "EMAIL", "entity": 1, "origin": "detector"},
]


def test_gold_measure_runs_in_the_background_and_fills_the_passport(boss, ivan, repo, engines):
    """Идея аудита 21.10.2026: паспорт качества — без текстов, с единицей подсчёта, знаменателями и сравнением слоёв."""
    repo.add_gold(None, "звонил Петров, почта a@x.example", GOLD_SPANS)
    page = boss.get("/settings/gold").text
    assert "Замеров собственного набора ещё не было" in page and "Измерить собственный набор" in page
    assert ivan.post("/settings/gold/measure").status_code == 403
    assert ivan.get("/settings/gold/measure/status").status_code == 403
    engines.ner_layer.marks["Петров"] = T.PERSON
    assert boss.post("/settings/gold/measure").status_code == 303
    assert boss.get("/settings/gold/measure/status").json() == {"status": "done"}
    page = boss.get("/settings/gold").text
    assert "Петров" not in page and "a@x" not in page
    assert "Слои 1-3" in page and "Слои 1-4" in page and "Слои 1-5" not in page            # слой 5 выключен по умолчанию
    fio = re.search(r"<td>ФИО</td><td class=\"num\">1</td>(.*?)</tr>", page).group(1)
    from cleaner.eval.runner import confidence
    assert re.findall(r'<td class="num mono">([^<]+)</td>', fio) == [confidence(0, 1), confidence(1, 1)]
    assert "Единица подсчёта: сущности разметки экрана проверки" in page and "QA-6 не проверена" in page
    assert "data-poll" not in page
    [event] = repo.audit_events("eval_run")
    assert event.details == {
        "dataset": "gold", "layers": ["1-3", "1-4"], "outcome": "done", "examples": 1, "drops": 0, "unchecked": 2,
    }
    repo.add_gold(None, "ещё пример", [])
    assert "набор изменился после замера" in boss.get("/settings/gold").text


def test_second_press_while_measuring_does_not_start_another(boss, repo, app):
    from cleaner.queueing import Budget

    repo.add_gold(None, "звонил Петров, почта a@x.example", GOLD_SPANS)
    repo.set_layer_defaults({"ner": False, "llm": True})
    calls = []
    app.state.measures = SimpleNamespace(
        budget=Budget(), submit_reserved=lambda fn, args, reservation, **options: calls.append((fn, *args)),
    )  # задание ещё в очереди
    boss.post("/settings/gold/measure")
    boss.post("/settings/gold/measure")
    assert len(calls) == 1 and calls[0][-1] == ["1-3", "1-4", "1-5"]                      # слой 5 включён по умолчанию
    page = boss.get("/settings/gold").text
    assert 'data-poll="/settings/gold/measure/status"' in page and "disabled" in page
    assert boss.get("/settings/gold/measure/status").json() == {"status": "queued"}


def test_gold_measure_failure_is_shown_and_an_empty_set_is_marked(boss, repo, engines):
    page = boss.get("/settings/gold").text
    assert "Собственный набор пуст: полнота по QA-1 не измерена" in page and "Измерить собственный набор" not in page
    assert boss.post("/settings/gold/measure").status_code == 400
    repo.add_gold(None, "звонил Петров, почта a@x.example", GOLD_SPANS)
    engines.unavailable = "модели слоя 4 не загружены"
    boss.post("/settings/gold/measure")
    assert "Замер не выполнен: модели слоя 4 не загружены" in boss.get("/settings/gold").text
    assert [e.details["outcome"] for e in repo.audit_events("eval_run")] == ["failed"]


def test_open_set_passport_is_shown_apart_from_the_own_set(boss, repo):
    record = runner.example_from("почта a@x.example", [{"start": 6, "end": 17, "type": "EMAIL", "entity": 0}])
    source = {"name": "hivetrace", "source": "hivetrace/pii-bench", "revision": "0123456789abcdef", "pinned": False,
              "sha256": "f" * 64, "converter": 2, "examples": 1}
    runner.measure(repo, "open:hivetrace", [record], ["1-3"], None, None, runner.UNIT_OPEN, source)
    page = boss.get("/settings/gold").text
    assert "Открытый набор «hivetrace»" in page and "не выполнение QA-1" in page
    assert "hivetrace/pii-bench @ 0123456789ab, ревизия на момент загрузки" in page
    assert "Единица подсчёта: сущности после преобразования открытого набора" in page
    assert "Собственный набор пуст" in page


def test_admin_sets_the_layer_defaults(boss, repo, ivan):
    boss.post("/settings/layers", llm="yes")
    assert repo.layer_defaults() == {"ner": False, "llm": True}
    boss.post("/settings/layers", ner="yes")
    assert repo.layer_defaults() == {"ner": True, "llm": False}
    assert [e.details for e in repo.audit_events("settings_changed")] == [
        {"section": "layers", "ner": True, "llm": False}, {"section": "layers", "ner": False, "llm": True},
    ]
    assert ivan.post("/settings/layers", ner="yes").status_code == 403
