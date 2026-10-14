import pytest

from cleaner import models
from cleaner.core.detect.base import DetectorError
from cleaner.engines import Engines, LocalSettings, local_settings, save_local_settings


def test_local_settings_have_defaults_and_round_trip(repo):
    assert local_settings(repo) == LocalSettings()
    wanted = LocalSettings("http://example:30000/v1", "qwen-27b-fast", frozenset({"llm.corp.example"}), False)
    save_local_settings(repo, wanted)
    assert local_settings(repo) == wanted
    with pytest.raises(ValueError):
        save_local_settings(repo, LocalSettings("https://api.example.com/v1", "m"))
    assert local_settings(repo) == wanted


def test_client_needs_the_key_from_the_environment(repo, tmp_path):
    with pytest.raises(DetectorError, match="CLEANER_GATEWAY_KEY"):
        Engines(repo, tmp_path, environ={}).client()
    engines = Engines(repo, tmp_path, environ={"CLEANER_GATEWAY_KEY": "k-test"})
    first = engines.client()
    assert first.config.model == "qwen-27b" and engines.client() is first
    repo.set_setting("local_llm.model", "qwen-27b-fast")
    assert engines.client().config.model == "qwen-27b-fast"


def test_client_refuses_an_address_that_became_public(repo, tmp_path):
    repo.set_setting("local_llm.url", "https://api.example.com/v1")          # мимо формы — например, правкой базы
    with pytest.raises(DetectorError, match="отклонён"):
        Engines(repo, tmp_path, environ={"CLEANER_GATEWAY_KEY": "k"}).client()


def test_status_says_whether_the_key_is_set_but_not_its_value(repo, tmp_path):
    (tmp_path / models.RUBERT_DIR).mkdir()
    status = Engines(repo, tmp_path, environ={"CLEANER_GATEWAY_KEY": "k-secret"}).status()
    assert status["key"] is True and "k-secret" not in repr(status)
    assert status["models"][models.RUBERT_DIR] is True and status["models"][models.GLINER_DIR] is False
