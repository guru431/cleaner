"""Регрессии допуска очереди, очистки RAM multipart и отмены без хранения исходных файлов."""
import asyncio
import io
from concurrent.futures import Executor, Future
from types import SimpleNamespace

import pytest
from starlette.datastructures import Headers

from cleaner.queueing import Budget, QueueFull
from cleaner.service import ChatService
from cleaner.web import deps
from cleaner.web.app import BodyLimit
from cleaner.web.jobs import CANCELLED, EXPIRED, Jobs


class Deferred(Executor):
    def __init__(self):
        self.tasks = []

    def submit(self, fn, /, *args, **kwargs):
        future = Future()
        self.tasks.append((future, fn, args))
        return future

    def run(self):
        future, fn, args = self.tasks.pop(0)
        if future.set_running_or_notify_cancel():
            future.set_result(fn(*args))


def test_budget_checks_both_users_and_shared_capacity_and_releases():
    budget = Budget(jobs=2, bytes_=20, user_jobs=1, user_bytes=15)
    first = budget.reserve("a", 8)
    with pytest.raises(QueueFull) as personal:
        budget.reserve("a", 1)
    assert personal.value.status == 429
    second = budget.reserve("b", 10)
    with pytest.raises(QueueFull) as shared:
        budget.reserve("c", 3)
    assert shared.value.status == 503
    first.release()
    first.release()
    second.release()
    assert budget.usage() == (0, 0)


def test_request_body_admission_refuses_before_receive(app):
    app.state.jobs.budget.max_bytes = 1
    scope = {"type": "http", "method": "POST", "path": "/api/v1/chats", "app": app, "headers": []}
    sent = []

    async def refuse(*args):
        pytest.fail("overloaded body was consumed or routed")

    async def send(message):
        sent.append(message)

    asyncio.run(BodyLimit(refuse)(scope, refuse, send))
    assert sent[0]["status"] == 503
    assert (b"retry-after", b"5") in sent[0]["headers"]
    assert app.state.jobs.budget.usage() == (0, 0)


def test_upload_admission_refuses_before_streaming_raw_bytes(app):
    app.state.jobs.budget.user_jobs = 0

    async def stream():
        pytest.fail("file body consumed without admission")
        yield b""

    request = SimpleNamespace(app=app, headers=Headers({"content-type": "multipart/form-data; boundary=b"}), stream=stream)
    with pytest.raises(QueueFull):
        asyncio.run(deps._read_upload(request, None, "owner"))


def test_admission_precedes_database_write_and_cancel_frees_raw_arguments(repo, clock, engines):
    user = repo.create_user("owner", "hash", "user")
    chat = repo.create_chat(user, "Чат")
    executor = Deferred()
    budget = Budget(user_jobs=1)
    jobs = Jobs(executor, budget=budget)
    service = ChatService(repo, engines=engines, file_submit=jobs.submit, budget=budget)
    item = service.add_file(chat, user, "report.txt", b"private synthetic bytes")
    with pytest.raises(QueueFull):
        service.add_file(chat, user, "extra.txt", b"extra")
    assert len(repo.items(chat)) == 1
    task = next(iter(jobs._tasks.values()))
    assert task.args[3] == b"private synthetic bytes"
    assert jobs.cancel(task.id, "other") is None
    assert jobs.cancel(task.id, user)
    assert task.args == () and task.fn is None
    assert budget.usage() == (0, 0)
    stored = repo.item(chat, item.id)
    assert stored.status == "failed" and stored.meta["error"] == CANCELLED
    executor.run()
    assert repo.item(chat, item.id).original == ""


def test_deadline_cancels_queued_and_failure_returns_its_budget(repo, engines, monkeypatch):
    timers = []

    class Timer:
        def __init__(self, delay, fn, args):
            timers.append(lambda: fn(*args))

        def start(self):
            pass

        def cancel(self):
            pass

    monkeypatch.setattr("cleaner.web.jobs.threading.Timer", Timer)
    user = repo.create_user("owner", "hash", "user")
    chat = repo.create_chat(user, "Чат")
    executor = Deferred()
    jobs = Jobs(executor)
    service = ChatService(repo, engines=engines, file_submit=jobs.submit, budget=jobs.budget)
    first = service.add_file(chat, user, "report.txt", b"a")
    timers[0]()
    assert repo.item(chat, first.id).meta["error"] == EXPIRED
    assert jobs.budget.usage() == (0, 0)
    second = service.add_file(chat, user, "report.bin", b"\x00\x01\xff")
    executor.run()  # cancelled first
    executor.run()  # unsupported second
    assert repo.item(chat, second.id).status == "failed"
    assert jobs.budget.usage() == (0, 0)


def test_chat_deletion_cancels_queued_work_and_releases_budget(repo, engines):
    user = repo.create_user("owner", "hash", "user")
    chat = repo.create_chat(user, "Чат")
    executor = Deferred()
    jobs = Jobs(executor)
    service = ChatService(repo, engines=engines, file_submit=jobs.submit, budget=jobs.budget)
    service.add_file(chat, user, "report.txt", b"sample")
    service.delete_chat(chat, user)
    assert jobs.budget.usage() == (0, 0)
    assert jobs.owned(user) == []
    executor.run()
    assert repo.chat(chat) is None


@pytest.mark.parametrize(("personal", "status"), [(True, 429), (False, 503)])
def test_api_overload_is_retryable_without_queued_item(api, app, repo, personal, status):
    program = api()
    chat = program.post("/api/v1/chats", json={}).json()["id"]
    budget = app.state.jobs.budget
    if personal:
        budget.user_jobs = 1
        ticket = budget.reserve(program.user_id)
    else:
        budget.max_jobs = 1
        ticket = budget.reserve("other")
    try:
        refused = program.post(f"/api/v1/chats/{chat}/texts", json={"text": "test", "wait": 0})
        assert refused.status_code == status and refused.headers["retry-after"] == "5"
        assert repo.items(chat) == []
        restored = program.post(f"/api/v1/chats/{chat}/restore", json={"text": "test"})
        assert restored.status_code == status and repo.items(chat) == []
    finally:
        ticket.release()


def test_personal_queue_hides_other_users_and_cancellation_needs_csrf(ivan, browser, app, repo):
    executor = Deferred()
    pool = Jobs(executor, budget=app.state.jobs.budget)
    app.state.job_pools += (pool,)
    app.state.service.file_submit = pool.submit
    chat = ivan.chat()
    ivan.upload(f"/chats/{chat}/upload", "report.txt", b"a")
    [job] = ivan.get("/jobs/status").json()["jobs"]
    assert job["cancellable"] and job["position"] == 1
    assert "Извлечение файла" in ivan.get("/jobs").text
    other = browser()
    other.user("other")
    other.login("other")
    assert other.get("/jobs/status").json() == {"jobs": []}
    assert other.post(f"/jobs/{job['id']}/cancel").status_code == 404
    assert ivan.client.post(f"/jobs/{job['id']}/cancel", data={"csrf": "bad"}).status_code == 403
    assert ivan.post(f"/jobs/{job['id']}/cancel").status_code == 303
    assert repo.items(chat)[0].status == "failed"
    assert ivan.get("/jobs/status").json() == {"jobs": []}
    assert pool.budget.usage() == (0, 0)


@pytest.mark.parametrize("csrf", ["correct", "bad"])
def test_large_multipart_never_rolls_to_disk_and_closes_every_file(ivan, app, monkeypatch, csrf):
    observed = []
    original = deps.MemoryMultipart.on_headers_finished

    def track(parser):
        original(parser)
        if parser._current_part.file:
            observed.append(parser._current_part.file.file)

    monkeypatch.setattr(deps.MemoryMultipart, "on_headers_finished", track)
    chat = ivan.chat()
    response = ivan.client.post(f"/chats/{chat}/upload", data={"csrf": ivan.csrf if csrf == "correct" else "bad"},
                                files=[("file", ("scan.png", b"\x89PNG\r\n\x1a\n" + b"x" * (2**20 + 1))),
                                       ("file", ("a.txt", b"text"))])
    assert response.status_code == (303 if csrf == "correct" else 403)
    assert len(observed) == 2 and all(isinstance(f, io.BytesIO) and f.closed for f in observed)
    assert app.state.jobs.budget.usage() == (0, 0)


def test_multipart_cancellation_closes_unfinished_buffer_and_releases_budget(app, monkeypatch):
    observed = []
    original = deps.MemoryMultipart.on_headers_finished

    def track(parser):
        original(parser)
        if parser._current_part.file:
            observed.append(parser._current_part.file.file)

    monkeypatch.setattr(deps.MemoryMultipart, "on_headers_finished", track)

    async def stream():
        yield b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="report.txt"\r\n\r\nbody'
        raise asyncio.CancelledError()

    request = SimpleNamespace(app=app, headers=Headers({"content-type": "multipart/form-data; boundary=boundary"}), stream=stream)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(deps._read_upload(request, None, "owner"))
    assert observed and all(f.closed for f in observed)
    assert app.state.jobs.budget.usage() == (0, 0)


def test_batch_has_independent_results_consistent_labels_and_rejects_whole_oversize(ivan, repo, app):
    chat = ivan.chat()
    result = ivan.client.post(f"/chats/{chat}/upload", data={"csrf": ivan.csrf}, files=[
        ("file", ("one.txt", b"email a@example.test")),
        ("file", ("broken.bin", b"\x00\xff\x01")),
        ("file", ("two.txt", b"email a@example.test")),
    ])
    assert result.status_code == 303 and result.headers["location"] == f"/chats/{chat}"
    one, broken, two = repo.items(chat)
    assert one.status == two.status == "done" and broken.status == "failed"
    assert one.sanitized == two.sanitized == "email <EMAIL_1>"
    before = len(repo.items(chat))
    app.state.max_file_bytes = 100
    refused = ivan.client.post(f"/chats/{chat}/upload", data={"csrf": ivan.csrf}, files=[
        ("file", ("one.txt", b"x" * 60)), ("file", ("two.txt", b"x" * 60)),
    ])
    assert refused.status_code == 413 and len(repo.items(chat)) == before
    assert app.state.jobs.budget.usage() == (0, 0)
