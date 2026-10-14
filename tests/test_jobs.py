import logging
import threading

from cleaner.web.jobs import Jobs


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
