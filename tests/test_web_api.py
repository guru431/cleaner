"""JSON-API для программ (FR-13, план 5А): ключ доступа, ошибки JSON, чаты, очистка, восстановление, правки."""
from concurrent.futures import Executor, Future

import pytest

from cleaner.core.types import EntityType as T
from cleaner.core.types import Policy
from cleaner.storage.repo import Repository
from cleaner.web.jobs import Jobs

TEXT = "Пишите i.ivanov@contoso.ru, проект Заря-Восток"


def chat(api, **body) -> str:
    response = api.post("/api/v1/chats", json=body)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def clean(api, chat_id: str, text: str = TEXT, **body):
    return api.post(f"/api/v1/chats/{chat_id}/texts", json={"text": text, **body})


def test_no_key_is_401_json(api):
    program = api()
    response = program.client.get("/api/v1/chats")
    assert response.status_code == 401
    assert response.json() == {"error": {"code": 401, "message": "Нужен действующий ключ доступа"}}


def test_session_cookie_does_not_open_the_api(ivan):
    response = ivan.get("/api/v1/chats")
    assert response.status_code == 401 and response.json()["error"]["code"] == 401


def test_key_in_either_header_with_spaces_works(api):
    program = api()
    assert program.client.get("/api/v1/chats", headers={"X-Cleaner-Key": f"  {program.key} "}).status_code == 200
    assert program.client.get("/api/v1/chats", headers={"Authorization": f"Bearer {program.key}"}).status_code == 200


def test_malformed_keys_are_401_not_500(api):
    client = api().client
    for headers in (
        {"X-Cleaner-Key": "ck_"}, {"Authorization": "Bearer"}, {"X-Cleaner-Key": "x" * 5000},
        {"Authorization": "Basic aXZhbjpwYXJvbA=="},
    ):
        response = client.get("/api/v1/chats", headers=headers)
        assert response.status_code == 401, headers
        assert response.json()["error"]["code"] == 401


def test_wrong_keys_are_throttled_by_address(api, repo, clock):
    program = api()
    wrong = {"X-Cleaner-Key": "ck_" + "Z" * 43}
    for _ in range(5):
        assert program.client.get("/api/v1/chats", headers=wrong).status_code == 401
    refused = program.client.get("/api/v1/chats", headers=wrong)
    assert refused.status_code == 429 and refused.headers["retry-after"] == "1"
    assert refused.json()["error"]["code"] == 429
    assert program.get("/api/v1/chats").status_code == 429          # пауза проверяется раньше ключа
    clock.advance(seconds=1)
    assert program.get("/api/v1/chats").status_code == 200
    assert len(repo.audit_events("api_auth_failed")) == 5


def test_revoked_key_and_disabled_owner_are_refused(api, repo):
    revoked, owner = api("ivan"), api("petr")
    assert repo.disable_api_key(revoked.key_id)
    assert revoked.get("/api/v1/chats").status_code == 401
    assert owner.get("/api/v1/chats").status_code == 200
    repo.set_disabled(owner.user_id, True)
    assert owner.get("/api/v1/chats").status_code == 401


def test_chats_are_created_listed_and_deleted_by_their_owner_only(api, repo: Repository):
    ivan, petr = api("ivan"), api("petr")
    chat_id = chat(ivan, title="Отчёт")
    assert [(c["id"], c["title"]) for c in ivan.get("/api/v1/chats").json()] == [(chat_id, "Отчёт")]
    assert set(ivan.get("/api/v1/chats").json()[0]) == {"id", "title", "updated_at"}
    assert petr.get("/api/v1/chats").json() == []
    assert petr.delete(f"/api/v1/chats/{chat_id}").status_code == 404
    assert ivan.delete(f"/api/v1/chats/{chat_id}").status_code == 204
    assert ivan.get("/api/v1/chats").json() == []
    assert [e.details for e in repo.audit_events("chat_created")] == [{"via": "api"}]
    assert [e.details for e in repo.audit_events("chat_deleted")] == [{"via": "api"}]


def test_created_chat_gets_default_title_layers_and_label_style(api, app, repo):
    program = api()
    chat_id = chat(program, label_style="square", layers={"ner": False})
    assert app.state.service.layers(chat_id)["ner"] is False
    assert repo.load_state(chat_id)[0].label_style == "square"
    assert repo.chat(chat_id).title == "API 14.10.2026 09:00"


def test_api_errors_are_json_without_request_values(api):
    program = api()
    responses = [
        program.post("/api/v1/chats", content=b"{", headers={"Content-Type": "application/json"}),
        program.post("/api/v1/chats", json={"title": 12345, "label_style": "Заря-Восток"}),
        program.get("/api/v1/nope"),
    ]
    assert [r.status_code for r in responses] == [422, 422, 404]
    for response in responses:
        assert response.headers["content-type"].startswith("application/json")
        assert "Заря-Восток" not in response.text and "12345" not in response.text
        assert response.json()["error"]["code"] == response.status_code


# --- очистка текста и файла (задача 3) -----------------------------------------------------


def test_text_is_cleaned_with_replacements_in_original_positions(api):
    program = api()
    response = clean(program, chat(program))
    assert response.status_code == 200, response.text
    result = response.json()
    assert (result["status"], result["deliverable"], result["leaks"], result["blocked"]) == ("done", True, 0, 0)
    assert "i.ivanov@contoso.ru" not in result["sanitized"] and "<EMAIL_1>" in result["sanitized"]
    assert result["replacements"]
    for replacement in result["replacements"]:
        assert TEXT[replacement["start"]:replacement["end"]] and replacement["replacement"] in result["sanitized"]
    [email] = [r for r in result["replacements"] if r["type"] == "EMAIL"]
    assert (TEXT[email["start"]:email["end"]], email["replacement"]) == ("i.ivanov@contoso.ru", "<EMAIL_1>")
    assert set(result) == {"item_id", "status", "deliverable", "sanitized", "replacements", "notices", "leaks", "blocked"}


class Deferred(Executor):
    """Исполнитель, который копит задания до run_all(): текст остаётся в очереди, пока тест не отпустит его."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def submit(self, fn, /, *args, **kwargs):
        self.calls.append((fn, args, kwargs))
        return Future()

    def run_all(self) -> None:
        calls, self.calls = self.calls, []
        for fn, args, kwargs in calls:
            fn(*args, **kwargs)


class TestSlowJobs:
    @pytest.fixture
    def deferred(self) -> Deferred:
        return Deferred()

    @pytest.fixture
    def jobs(self, deferred) -> Jobs:
        return Jobs(deferred)

    def test_slow_text_returns_202_and_is_polled(self, api, deferred):
        program = api()
        chat_id = chat(program)
        response = clean(program, chat_id, wait=0)
        assert response.status_code == 202 and response.json()["status"] == "queued"
        item_id = response.json()["item_id"]
        assert set(response.json()) == {"item_id", "status"}
        polled = program.get(f"/api/v1/chats/{chat_id}/items/{item_id}")
        assert (polled.status_code, polled.json()) == (200, {"item_id": item_id, "status": "queued"})
        deferred.run_all()
        done = program.get(f"/api/v1/chats/{chat_id}/items/{item_id}").json()
        assert done["status"] == "done" and "<EMAIL_1>" in done["sanitized"]

    def test_deleted_chat_while_queued_is_404(self, api, deferred, repo):
        program = api()
        chat_id = chat(program)
        item_id = clean(program, chat_id, wait=0).json()["item_id"]
        assert program.delete(f"/api/v1/chats/{chat_id}").status_code == 204
        response = program.get(f"/api/v1/chats/{chat_id}/items/{item_id}")
        assert response.status_code == 404 and response.json()["error"]["code"] == 404
        deferred.run_all()
        assert repo.audit_events("error") == []


def test_blocked_text_is_not_delivered(api, repo):
    repo.set_policy(T.EMAIL, Policy.BLOCK)
    program = api()
    result = clean(program, chat(program)).json()
    assert (result["status"], result["deliverable"]) == ("done", False)
    assert "sanitized" not in result and result["blocked"] >= 1


def test_failed_text_reports_the_reason(api, engines):
    engines.unavailable = "модели не загружены"
    program = api()
    result = clean(program, chat(program, layers={"ner": True})).json()
    assert result["status"] == "failed" and "модели не загружены" in result["error"]
    assert "sanitized" not in result


def test_text_limits_are_json_errors(api):
    program = api()
    chat_id = chat(program)
    responses = [clean(program, chat_id, ""), clean(program, chat_id, "   "), clean(program, chat_id, "я" * 500_001)]
    assert [r.status_code for r in responses] == [422, 422, 413]
    for response in responses:
        assert response.json()["error"]["code"] == response.status_code
    assert responses[0].json()["error"]["message"] == "Пустой текст"


def test_strings_that_are_not_utf_8_are_422_not_500(api, repo):
    """Ревью 5А: «\\ud800» — допустимый JSON, но не текст: строка без пары не кодируется в UTF-8 для шифрования."""
    program = api()
    chat_id = chat(program)
    item_id = clean(program, chat_id).json()["item_id"]
    for path, body in (
        ("/api/v1/chats", '{"title": "Отчёт \\ud800"}'),
        (f"/api/v1/chats/{chat_id}/texts", '{"text": "abc \\ud800 def"}'),
        (f"/api/v1/chats/{chat_id}/restore", '{"text": "Ответ \\udfff"}'),
        (f"/api/v1/chats/{chat_id}/rules", f'{{"action": "mask", "value": "x\\ud800", "type": "TERM", "item_id": "{item_id}"}}'),
    ):
        response = program.post(path, content=body.encode("utf-8"), headers={"Content-Type": "application/json"})
        assert (response.status_code, response.json()["error"]["code"]) == (422, 422), path
    assert repo.audit_events("error") == []


def test_wait_out_of_range_is_422(api):
    program = api()
    chat_id = chat(program)
    assert [clean(program, chat_id, wait=w).status_code for w in (-1, 61)] == [422, 422]


def test_items_of_other_chats_and_users_are_404(api, app):
    ivan, petr = api("ivan"), api("petr")
    first, second = chat(ivan), chat(ivan)
    item_id = clean(ivan, first).json()["item_id"]
    answer = app.state.service.add_answer(first, ivan.user_id, "Ответ: <EMAIL_1>")
    assert ivan.get(f"/api/v1/chats/{first}/items/{item_id}").status_code == 200
    for program, path in (
        (ivan, f"/api/v1/chats/{second}/items/{item_id}"),
        (petr, f"/api/v1/chats/{first}/items/{item_id}"),
        (ivan, f"/api/v1/chats/{first}/items/{answer.id}"),
        (ivan, f"/api/v1/chats/{first}/items/нет"),
    ):
        response = program.get(path)
        assert response.status_code == 404, path
        assert response.json()["error"]["code"] == 404
    assert clean(petr, first).status_code == 404


def test_file_is_queued_and_its_result_polled(api):
    program = api()
    chat_id = chat(program)
    response = program.post(f"/api/v1/chats/{chat_id}/files", files={"file": ("note.txt", "Почта doc@x.example".encode())})
    assert response.status_code == 202, response.text
    result = program.get(f"/api/v1/chats/{chat_id}/items/{response.json()['item_id']}").json()
    assert result["status"] == "done" and "doc@x.example" not in result["sanitized"]


def test_file_over_the_limit_is_413(api, app):
    app.state.max_file_bytes = 1024
    program = api()
    response = program.post(f"/api/v1/chats/{chat(program)}/files", files={"file": ("big.txt", b"x" * 2048)})
    assert response.status_code == 413 and response.json()["error"]["code"] == 413


def test_program_text_is_labelled_in_the_feed(ivan, api):
    program = api("ivan")
    chat_id = chat(program)
    clean(program, chat_id)
    assert "Текст из программы" in ivan.get(f"/chats/{chat_id}").text


# --- восстановление, таблица соответствий, правки (задача 4) ---------------------------------


def test_restore_returns_originals_and_unknown_labels(api, repo):
    program = api()
    chat_id = chat(program)
    clean(program, chat_id)
    response = program.post(f"/api/v1/chats/{chat_id}/restore", json={"text": "Ответ: <EMAIL_1>, а также <PERSON_99>"})
    assert response.status_code == 200, response.text
    result = response.json()
    assert "i.ivanov@contoso.ru" in result["restored"] and result["unknown"] == ["<PERSON_99>"]
    assert (result["counters"]["restored"], result["counters"]["unknown"]) == (1, 1)
    assert [(i.id, i.kind) for i in repo.items(chat_id)][-1] == (result["item_id"], "answer")


def test_restore_limits_are_json_errors(api):
    program = api()
    chat_id = chat(program)
    responses = [
        program.post(f"/api/v1/chats/{chat_id}/restore", json={"text": " "}),
        program.post(f"/api/v1/chats/{chat_id}/restore", json={"text": "я" * 500_001}),
    ]
    assert [(r.status_code, r.json()["error"]["code"]) for r in responses] == [(422, 422), (413, 413)]


def test_entities_list_replacements_originals_and_counts(api):
    program = api()
    chat_id = chat(program)
    clean(program, chat_id, "Пишите i.ivanov@contoso.ru, копия — i.ivanov@contoso.ru")
    entities = program.get(f"/api/v1/chats/{chat_id}/entities").json()
    [email] = [e for e in entities if e["type"] == "EMAIL"]
    assert "<EMAIL_1>" in email["replacements"] and email["original"] == "i.ivanov@contoso.ru" and email["count"] == 2
    assert set(email) == {"id", "type", "replacements", "original", "forms", "count"}


def test_mask_and_unmask_change_the_texts(api):
    program = api()
    chat_id = chat(program)
    item_id = clean(program, chat_id).json()["item_id"]
    rules = f"/api/v1/chats/{chat_id}/rules"
    masked = program.post(rules, json={"action": "mask", "value": "Заря-Восток", "type": "TERM", "item_id": item_id})
    assert masked.json() == {"changed": 1}
    assert "<TERM_1>" in program.get(f"/api/v1/chats/{chat_id}/items/{item_id}").json()["sanitized"]
    assert program.post(rules, json={"action": "unmask", "value": "i.ivanov@contoso.ru"}).json() == {"changed": 1}
    assert "i.ivanov@contoso.ru" in program.get(f"/api/v1/chats/{chat_id}/items/{item_id}").json()["sanitized"]


def test_bad_rules_are_422(api):
    program = api()
    chat_id, other = chat(program), chat(program)
    item_id = clean(program, chat_id).json()["item_id"]
    foreign = clean(program, other).json()["item_id"]
    rules = f"/api/v1/chats/{chat_id}/rules"
    for body in (
        {"action": "mask", "value": "Лето-Сириус", "type": "TERM", "item_id": item_id},
        {"action": "mask", "value": "Заря-Восток", "type": "NOPE", "item_id": item_id},
        {"action": "mask", "value": "Заря-Восток", "type": "TERM"},
        {"action": "mask", "value": " ", "type": "TERM", "item_id": item_id},
        {"action": "unmask", "value": ""},
        {"action": "hide", "value": "Заря-Восток"},
    ):
        response = program.post(rules, json=body)
        assert (response.status_code, response.json()["error"]["code"]) == (422, 422), body
        assert "Лето-Сириус" not in response.text
    refused = program.post(rules, json={"action": "mask", "value": "Заря-Восток", "type": "TERM", "item_id": foreign})
    assert refused.status_code == 422 and refused.json()["error"]["message"] == "выделите фрагмент текста"
