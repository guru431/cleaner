"""JSON-API для программ (FR-13, план 5А): ключ доступа, ошибки JSON, чаты, очистка, восстановление, правки."""
from cleaner.storage.repo import Repository


def chat(api, **body) -> str:
    response = api.post("/api/v1/chats", json=body)
    assert response.status_code == 201, response.text
    return response.json()["id"]


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
