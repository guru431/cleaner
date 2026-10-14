"""Слои 4 и 5, распознавание страниц и разбор документов для службы.

Настройки локальной модели — в таблице settings; ключ шлюза — только из окружения службы
(CLEANER_GATEWAY_KEY в /etc/cleaner/cleaner.env), в базе и файлах репозитория его нет.
"""
from __future__ import annotations

import json
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cleaner import models
from cleaner.core.detect.base import DetectorError
from cleaner.local_llm import LocalLLM, LocalLLMConfig, check_address
from cleaner.storage.repo import Repository

GATEWAY_KEY_ENV = "CLEANER_GATEWAY_KEY"


@dataclass(frozen=True)
class LocalSettings:
    url: str = "http://127.0.0.1:30000/v1"     # шлюз LiteLLM сервера по петле (раздел 11)
    model: str = "qwen-27b"
    trusted: frozenset[str] = frozenset()      # узлы вне частных сетей, которым администратор доверяет явно
    schema: bool = True                        # схема JSON параметром response_format; False — только в тексте запроса


def local_settings(repo: Repository) -> LocalSettings:
    defaults = LocalSettings()
    trusted = repo.setting("local_llm.trusted")
    return LocalSettings(
        url=repo.setting("local_llm.url") or defaults.url,
        model=repo.setting("local_llm.model") or defaults.model,
        trusted=frozenset(json.loads(trusted)) if trusted else frozenset(),
        schema=(repo.setting("local_llm.schema") or "response_format") == "response_format",
    )


def save_local_settings(repo: Repository, settings: LocalSettings) -> None:
    """ValueError, если адрес не петлевой, не частный и не доверенный (SEC-12): тогда ничего не записано."""
    check_address(settings.url, settings.trusted)
    repo.set_setting("local_llm.url", settings.url)
    repo.set_setting("local_llm.model", settings.model)
    repo.set_setting("local_llm.trusted", json.dumps(sorted(settings.trusted)))
    repo.set_setting("local_llm.schema", "response_format" if settings.schema else "prompt")


class Engines:
    def __init__(
        self, repo: Repository, models_dir: Path, environ: Mapping[str, str] = os.environ, transport: object = None,
    ):
        self.repo = repo
        self.models_dir = models_dir
        self.key = environ.get(GATEWAY_KEY_ENV, "")
        self._transport = transport          # только для тестов: httpx.MockTransport
        self._client: LocalLLM | None = None
        self._lock = threading.Lock()

    def status(self) -> dict[str, object]:
        """Для страницы настроек: задан ли ключ (значение не показывается) и какие модели на диске."""
        return {
            "key": bool(self.key),
            "models": {spec.directory: (self.models_dir / spec.directory).is_dir() for spec in models.SPECS},
        }

    def client(self) -> LocalLLM:
        settings = local_settings(self.repo)
        if not self.key:
            raise DetectorError(f"Локальная модель недоступна: в окружении службы не задан ключ шлюза {GATEWAY_KEY_ENV}")
        try:
            check_address(settings.url, settings.trusted)        # и при каждом использовании, а не только в форме
        except ValueError as exc:
            raise DetectorError(f"Адрес локальной модели отклонён: {exc}") from None
        config = LocalLLMConfig(settings.url, settings.model, self.key)
        with self._lock:
            if self._client is None or self._client.config != config:
                self._client = LocalLLM(config, self._transport)
            return self._client

    def ner(self):
        raise DetectorError("Слой 4 недоступен: модели распознавания имён ещё не подключены")

    def llm(self):
        raise DetectorError("Слой 5 недоступен: второй проход локальной модели ещё не подключён")
