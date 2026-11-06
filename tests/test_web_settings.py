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
