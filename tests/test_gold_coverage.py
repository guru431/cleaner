"""Сохранение coverage остаётся явным действием владельца; тексты не выходят в паспорт."""
def test_gold_review_metadata_is_validated_and_private(ivan, boss, repo):
    chat = ivan.chat()
    ivan.post(f"/chats/{chat}/input", text="почта audit.person@contoso.ru")
    item = repo.items(chat)[0]
    path = f"/chats/{chat}/items/{item.id}/gold"
    assert repo.gold() == []
    assert ivan.post(path, scenario="unsupported").status_code == 400
    assert repo.gold() == []
    assert ivan.post(path, scenario="config", repeated="yes", false_positives="yes").status_code == 303
    [row] = repo.gold()
    assert row.metadata == {"scenario": "config", "checks": ["false_positives", "repeated"]}
    assert row.text == item.original
    raw = repo.conn.execute("SELECT metadata_enc FROM gold").fetchone()[0]
    assert b"config" not in raw and b"false_positives" not in raw
    shown = boss.get("/settings/gold").text
    assert "audit.person@contoso.ru" not in shown
    assert "Конфигурация" in shown
    assert ivan.get("/settings/gold").status_code == 403


def test_full_queue_does_not_leave_a_measurement_permanently_queued(boss, repo, app, monkeypatch):
    from cleaner.queueing import QueueFull

    repo.add_gold(None, "пример", [])

    def full(*args, **kwargs):
        raise QueueFull()

    monkeypatch.setattr(app.state.measures, "submit_reserved", full)
    response = boss.post("/settings/gold/measure")
    assert response.status_code == 503 and response.headers["Retry-After"] == "5"
    assert boss.get("/settings/gold/measure/status").json() == {"status": "failed"}
