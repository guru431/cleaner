"""Failure contracts reproduced from the November 15 review; synthetic inputs only."""
import urllib.error

import pytest

from cleaner.core.detect.base import DetectorError
from cleaner.ingest.extract import ExtractError, Extractor
from cleaner.storage.repo import Provider
from scripts.checks import ocr_check


def test_orphan_pruning_deletes_every_chat_even_when_checkpoint_is_busy(repo, monkeypatch):
    from cleaner.storage.repo import CheckpointBusy

    user = repo.create_user("owner", "hash", "user")
    chats = [repo.create_chat(user, "synthetic", kind="agent") for _ in range(2)]
    monkeypatch.setattr(repo, "truncate_wal", lambda: "busy")
    with pytest.raises(CheckpointBusy):
        repo.prune_agent("2000-01-01T00:00:00+00:00")
    assert all(repo.chat(chat) is None for chat in chats)


def test_image_ocr_configuration_failure_has_a_user_error(engines):
    def unavailable(*args):
        raise DetectorError("gateway unavailable")

    with pytest.raises(ExtractError, match="Распознавание текста не выполнено"):
        Extractor(engines.documents, unavailable)._page(b"synthetic image", "image/png", 1)


@pytest.mark.parametrize("secret, tail", [("", ""), ("1234", ""), ("12345", "2345")])
def test_provider_tail_never_reveals_a_whole_key(secret, tail):
    assert Provider("", "test", "anthropic", "https://example.test", "bearer", secret, ()).key_tail == tail


def test_ocr_check_recovers_from_transport_errors(monkeypatch):
    attempts, sleeps = [], []

    def unavailable(*args, **kwargs):
        attempts.append(None)
        raise urllib.error.URLError("unavailable")

    monkeypatch.setattr(ocr_check.urllib.request, "urlopen", unavailable)
    monkeypatch.setattr(ocr_check.time, "sleep", sleeps.append)
    assert ocr_check.ocr("https://example.test", "synthetic", b"image") == {"error": "network"}
    assert len(attempts) == 10


def test_ocr_check_missing_key_is_actionable(monkeypatch):
    monkeypatch.delenv("CLEANER_GATEWAY_KEY", raising=False)
    monkeypatch.setattr(ocr_check.sys, "argv", ["ocr_check.py", "https://example.test", "unused", "unused.png"])
    with pytest.raises(SystemExit, match="CLEANER_GATEWAY_KEY не задан"):
        ocr_check.main()


def test_settings_home_reads_the_gold_set_once(boss, repo, monkeypatch):
    calls, gold = [], repo.gold

    def counted():
        calls.append(None)
        return gold()

    monkeypatch.setattr(repo, "gold", counted)
    assert boss.get("/settings").status_code == 200
    assert len(calls) == 1
