"""Приёмка плана 5А на петле: AC-5.8 (спецификация 2026-10-28, раздел 21) — программа очищает и восстанавливает
текст через /api/v1, отозванный ключ — 401, ключ нигде не хранится и не пишется открыто."""
import logging
import re

from scripts import api_smoke


def test_smoke_reports_a_non_json_http_error(monkeypatch):
    import io
    import urllib.error

    class Opener:
        def open(self, *args, **kwargs):
            raise urllib.error.HTTPError("https://cleaner.example", 502, "Bad gateway", {}, io.BytesIO(b"<html>failure</html>"))

    monkeypatch.setattr(api_smoke.urllib.request, "build_opener", lambda *args: Opener())
    assert api_smoke.http_call("https://cleaner.example", "ck_fictional", None)("GET", "/api/v1/chats", None) == (502, {})
from tests.test_acceptance_core import CONTROL, TEXT

KEY = re.compile(r"ck_[A-Za-z0-9_-]{43}")


def through(client, key: str) -> api_smoke.Call:
    """call скрипта поверх клиента тестов: тот же сценарий, что против живого экземпляра."""
    def call(method: str, path: str, body: dict | None) -> tuple[int, object]:
        response = client.request(method, path, json=body, headers={"X-Cleaner-Key": key})
        return response.status_code, (response.json() if response.content else {})
    return call


def test_ac_5_8_program_cleans_and_restores_through_the_api(api, repo, capsys):
    program = api()
    assert api_smoke.run(through(program.client, program.key)) == []
    assert repo.chats(program.user_id) == []                    # сценарий убирает за собой свой чат
    assert repo.disable_api_key(program.key_id)
    assert api_smoke.run(through(program.client, program.key), expect_revoked=True) == []
    assert api_smoke.run(through(program.client, program.key)) != []
    printed = capsys.readouterr().out
    assert all(value not in printed for value in api_smoke.CONTROL) and program.key not in printed


def test_ac_5_8_control_text_of_stage_1_is_fully_replaced(api):
    program = api()
    chat_id = program.post("/api/v1/chats", json={}).json()["id"]
    result = program.post(f"/api/v1/chats/{chat_id}/texts", json={"text": TEXT}).json()
    assert result["deliverable"]
    sanitized = result["sanitized"].lower()
    assert [value for value in CONTROL if value.lower() in sanitized] == []


def test_ac_5_8_key_is_never_stored_or_logged_in_clear(ivan, repo, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    issued = ivan.post("/keys", name="Сборка отчётов")
    key = KEY.search(ivan.get(issued.headers["location"]).text).group(0)
    headers = {"X-Cleaner-Key": key}
    chat_id = ivan.client.post("/api/v1/chats", json={"title": "AC-5.8"}, headers=headers).json()["id"]
    ivan.client.post(f"/api/v1/chats/{chat_id}/texts", json={"text": "Почта a@x.example"}, headers=headers)
    ivan.client.get(f"/api/v1/chats/{chat_id}/entities", headers=headers)
    ivan.client.get("/api/v1/chats", headers={"Authorization": f"Bearer {key}"})
    for wrong in (key[:-1], key + "x", key.upper()):
        assert ivan.client.get("/api/v1/chats", headers={"X-Cleaner-Key": wrong}).status_code == 401
    ivan.client.post("/api/v1/chats", content=b"{", headers={**headers, "Content-Type": "application/json"})
    ivan.client.delete(f"/api/v1/chats/{chat_id}", headers=headers)
    page = ivan.get("/keys").text
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = b"".join(path.read_bytes() for path in tmp_path.glob("cleaner.db*"))
    journal = repr([(event.event, event.details) for event in repo.audit_events(limit=1000)])
    secret = key[3:]                         # без приставки: ни ключ, ни его тело
    for where in (page, caplog.text, journal):
        assert secret not in where
    assert secret.encode("ascii") not in raw and secret.encode("utf-16-le") not in raw
    assert f"…{key[-4:]}" in page
