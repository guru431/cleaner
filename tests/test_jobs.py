import logging
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from cleaner.ingest.extract import ExtractError
from cleaner.storage.repo import Item
from cleaner.web.app import FILE_WORKERS, create_app
from cleaner.web.jobs import FILE_INTERRUPTED, INTERRUPTED, WORKERS, Jobs, shutdown

# Предел ожидания заданий в настоящих пулах — страховка от зависания, а не замер: под нагрузкой машины очистка в потоке
# шла дольше секунды, и тест падал по TimeoutError без ошибки в коде (аудит 21.10.2026).
GUARD = 10


def blocking_job():
    """Задание, которое идёт, пока тест его не отпустит."""
    started, release, seen = threading.Event(), threading.Event(), []

    def job():
        started.set()
        release.wait(5)
        seen.append("done")

    return job, started, release, seen


class Pool(ThreadPoolExecutor):
    """Настоящий пул, который помнит свои задания: тест ждёт их результат, а не опрашивает базу."""

    def __init__(self, workers: int):
        super().__init__(max_workers=workers)
        self.futures: list[Future] = []

    def submit(self, fn, /, *args, **kwargs):
        future = super().submit(fn, *args, **kwargs)
        self.futures.append(future)
        return future


@pytest.fixture
def chat(repo):
    user = repo.create_user("ivan", "hash", "user")
    return user, repo.create_chat(user, "Чат")


def test_pasted_text_is_cleaned_while_scans_hold_every_file_thread(repo, clock, engines, chat):
    """Находка «Scanned PDFs hold the two-thread job pool for every user»: сканы заняли все потоки разбора
    файлов, а вставленный абзац очищается сразу, не дожидаясь их."""
    user, chat_id = chat
    reading = {f"скан-{n}.pdf": threading.Event() for n in range(FILE_WORKERS)}
    release = threading.Event()

    class StuckScan:
        def extract(self, filename, data, progress, ocr_all=False):
            reading[filename].set()
            release.wait(5)                     # отпускает тест; пять секунд — только страховка
            raise ExtractError("распознавание остановлено тестом")

    engines.extractor = StuckScan
    shared, files = Pool(WORKERS), Pool(FILE_WORKERS)
    service = create_app(repo, clock, secure_cookies=False, engines=engines, jobs=Jobs(shared), files=Jobs(files)).state.service
    try:
        for name in reading:
            service.add_file(chat_id, user, name, b"%PDF-1.7")
        assert all(event.wait(GUARD) for event in reading.values())        # все потоки разбора файлов заняты
        text = service.add_input(chat_id, user, "почта a@x.example")
        shared.futures[0].result(timeout=GUARD)
        assert repo.item(chat_id, text.id).sanitized == "почта <EMAIL_1>"
    finally:
        release.set()
        shared.shutdown(wait=True)
        files.shutdown(wait=True)


def test_only_file_extraction_goes_to_the_file_pool(repo, clock, engines, chat):
    """Свой пул — только у разбора файла: повтор файла (текст уже извлечён), проверка риска и вопрос локальной
    модели остаются в общем."""
    user, chat_id = chat
    shared, files = Pool(WORKERS), Pool(FILE_WORKERS)
    service = create_app(repo, clock, secure_cookies=False, engines=engines, jobs=Jobs(shared), files=Jobs(files)).state.service
    try:
        letter = service.add_file(chat_id, user, "letter.eml", b"From: a@x.example\n\nbody")
        files.futures[0].result(timeout=GUARD)
        text = service.add_input(chat_id, user, "почта b@x.example")
        shared.futures[0].result(timeout=GUARD)
        service.retry(chat_id, user, letter.id)
        shared.futures[1].result(timeout=GUARD)
        service.check_risk(chat_id, user, text.id)
        shared.futures[2].result(timeout=GUARD)
        service.ask_local(chat_id, user)
        shared.futures[3].result(timeout=GUARD)
        assert (len(files.futures), len(shared.futures)) == (1, 4)
        assert [repo.item(chat_id, i.id).sanitized for i in (letter, text)] == ["Документ: почта <EMAIL_1>", "почта <EMAIL_2>"]
    finally:
        shared.shutdown(wait=True)
        files.shutdown(wait=True)


def test_service_stop_shuts_the_file_pool_down(repo, clock, engines, jobs):
    files = Jobs(ThreadPoolExecutor(max_workers=1), stop_wait=0)
    with TestClient(create_app(repo, clock, secure_cookies=False, engines=engines, jobs=jobs, files=files)):
        pass
    with pytest.raises(RuntimeError):
        files.submit(print)


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


class Stoppable(ThreadPoolExecutor):
    """Пул из одного потока, который сообщает, что его остановили."""

    def __init__(self):
        super().__init__(max_workers=1)
        self.stopped = threading.Event()

    def shutdown(self, wait=True, *, cancel_futures=False):
        super().shutdown(wait=wait, cancel_futures=cancel_futures)
        self.stopped.set()


def test_service_stop_closes_every_pool_before_waiting_for_any():
    """Пулы ждались по очереди: пока шло ожидание общего пула, пул файлов брал из очереди следующий скан,
    а худшая остановка росла на 30 с с каждым пулом."""
    shared, files = Stoppable(), Stoppable()
    running, scan, release, seen = blocking_job()
    other, scan_started, scan_release, _ = blocking_job()
    pools = [Jobs(shared, stop_wait=5), Jobs(files, stop_wait=5)]
    pools[0].submit(running)
    pools[1].submit(other)
    pools[1].submit(seen.append, "следующий скан")
    assert scan.wait(5) and scan_started.wait(5)
    stopping = threading.Thread(target=shutdown, args=pools)
    stopping.start()
    try:
        assert files.stopped.wait(GUARD)                 # общий пул ещё занят, а пул файлов уже закрыт
    finally:
        scan_release.set()
        release.set()
        stopping.join(5)
    assert seen == ["done"]


def test_service_stop_marks_unfinished_texts_interrupted_while_the_database_is_open(repo, clock, engines):
    """Обзор плана 2+4, m-8: отказ «прервано» ставит остановка службы, а не случайная ошибка записи в закрытую базу."""
    executor = ThreadPoolExecutor(max_workers=1)
    jobs = Jobs(executor, stop_wait=0)
    user = repo.create_user("ivan", "hash", "user")
    chat_id = repo.create_chat(user, "Чат")
    job, started, release, seen = blocking_job()
    app = create_app(repo, clock, secure_cookies=False, engines=engines, jobs=jobs)
    assert app.state.unfinished_jobs == 0
    with TestClient(app):
        item = repo.add_item(chat_id, Item(uuid.uuid4().hex, 0, "input", "почта a@x.example", None, status="running"))
        jobs.submit(job)                                        # задание этого текста ещё идёт
        assert started.wait(5)
    stored = repo.item(chat_id, item.id)
    assert (stored.status, stored.meta["error"]) == ("failed", INTERRUPTED)
    assert [e.details for e in repo.audit_events("jobs_interrupted")] == [{"count": 1}]
    assert app.state.unfinished_jobs == 1            # по нему serve выходит, не дожидаясь потока задания (__main__)
    release.set()
    executor.shutdown(wait=True)


def test_service_stop_asks_for_the_file_again_when_its_text_was_not_extracted(repo, clock, engines):
    """Файл не хранится: разбор, прерванный остановкой (идущий и снятый с очереди), — «загрузите файл ещё раз», а не
    «запустите её ещё раз», которого нельзя сделать."""
    files = Jobs(ThreadPoolExecutor(max_workers=1), stop_wait=0)
    user = repo.create_user("ivan", "hash", "user")
    chat_id = repo.create_chat(user, "Чат")
    reading, release = threading.Event(), threading.Event()

    class StuckScan:
        def extract(self, filename, data, progress, ocr_all=False):
            reading.set()
            release.wait(5)
            raise ExtractError("распознавание остановлено тестом")

    engines.extractor = StuckScan
    app = create_app(repo, clock, secure_cookies=False, engines=engines, files=files)
    try:
        with TestClient(app):
            running = app.state.service.add_file(chat_id, user, "скан-1.pdf", b"%PDF-1.7")
            queued = app.state.service.add_file(chat_id, user, "скан-2.pdf", b"%PDF-1.7")
            assert reading.wait(GUARD)
        assert [repo.item(chat_id, i.id).meta["error"] for i in (running, queued)] == [FILE_INTERRUPTED] * 2
        assert "загрузите файл ещё раз" in FILE_INTERRUPTED
    finally:
        release.set()
        files._executor.shutdown(wait=True)


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
