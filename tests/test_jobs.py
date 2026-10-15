import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from cleaner.storage.repo import Item
from cleaner.web.app import create_app
from cleaner.web.jobs import INTERRUPTED, Jobs


def blocking_job():
    """Задание, которое идёт, пока тест его не отпустит."""
    started, release, seen = threading.Event(), threading.Event(), []

    def job():
        started.set()
        release.wait(5)
        seen.append("done")

    return job, started, release, seen


def test_shutdown_waits_for_a_running_job():
    """Обзор плана 2+4, m-8: соединение с базой закрывается после заданий, а не под ними."""
    jobs = Jobs(ThreadPoolExecutor(max_workers=1), stop_wait=5)
    job, started, release, seen = blocking_job()
    jobs.submit(job)
    assert started.wait(5)
    release.set()
    assert jobs.shutdown() == 0 and seen == ["done"]


def test_shutdown_drops_queued_jobs_refuses_new_ones_and_counts_the_unfinished():
    executor = ThreadPoolExecutor(max_workers=1)
    jobs = Jobs(executor, stop_wait=0)
    job, started, release, seen = blocking_job()
    jobs.submit(job)
    jobs.submit(seen.append, "из очереди")
    assert started.wait(5)
    assert jobs.shutdown() == 1                      # не дождались: одно задание ещё идёт
    with pytest.raises(RuntimeError):
        jobs.submit(seen.append, "после остановки")
    release.set()
    executor.shutdown(wait=True)
    assert seen == ["done"]


def test_service_stop_marks_unfinished_texts_interrupted_while_the_database_is_open(repo, clock, engines):
    """Обзор плана 2+4, m-8: отказ «прервано» ставит остановка службы, а не случайная ошибка записи в закрытую базу."""
    executor = ThreadPoolExecutor(max_workers=1)
    jobs = Jobs(executor, stop_wait=0)
    user = repo.create_user("ivan", "hash", "user")
    chat_id = repo.create_chat(user, "Чат")
    job, started, release, seen = blocking_job()
    with TestClient(create_app(repo, clock, secure_cookies=False, engines=engines, jobs=jobs)):
        item = repo.add_item(chat_id, Item(uuid.uuid4().hex, 0, "input", "почта a@x.example", None, status="running"))
        jobs.submit(job)                                        # задание этого текста ещё идёт
        assert started.wait(5)
    stored = repo.item(chat_id, item.id)
    assert (stored.status, stored.meta["error"]) == ("failed", INTERRUPTED)
    assert [e.details for e in repo.audit_events("jobs_interrupted")] == [{"count": 1}]
    release.set()
    executor.shutdown(wait=True)


def test_jobs_run_in_a_background_pool():
    jobs = Jobs()
    seen = []
    done = threading.Event()

    def job(value):
        seen.append((value, threading.current_thread().name))
        done.set()

    jobs.submit(job, "x")
    assert done.wait(5)
    jobs.shutdown()
    assert seen[0][0] == "x" and seen[0][1].startswith("cleaner-job")


def test_unexpected_failure_is_logged_by_kind_without_its_text(jobs, caplog):
    caplog.set_level(logging.ERROR)

    def broken(text):
        raise ValueError(f"не разобрано: {text}")

    jobs.submit(broken, "Zx9-канарейка")
    assert "ValueError" in caplog.text and "Zx9" not in caplog.text
