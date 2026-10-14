"""Слой 5 с настоящей локальной моделью через шлюз (раздел 5.6). Нужен ключ шлюза в окружении — запуск руками:

  set -a; . data/cleaner.env; set +a
  python -m pytest tests/test_llm_integration.py -m manual
Адрес и модель — из настроек базы разработки (страница «Локальная модель»), тексты — вымышленные.
"""
import os
from pathlib import Path

import pytest

from cleaner.clock import SystemClock
from cleaner.core.pipeline import Layers, sanitize
from cleaner.core.types import ChatState, Settings
from cleaner.engines import GATEWAY_KEY_ENV, Engines
from cleaner.storage import crypto, db
from cleaner.storage.repo import Repository

pytestmark = pytest.mark.manual
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def layer():
    if not os.environ.get(GATEWAY_KEY_ENV):
        pytest.fail(f"нет {GATEWAY_KEY_ENV} в окружении: set -a; . data/cleaner.env; set +a")
    conn = db.connect(ROOT / "data" / "cleaner.db")
    repo = Repository(conn, crypto.master_key_from_env(), SystemClock())
    yield Engines(repo, ROOT / "models").llm()
    conn.close()


@pytest.mark.parametrize(("text", "expected"), [
    ("Для общего ящика на стикере записано: sunflower77, отвечает Сидоров", "Для общего ящика на стикере записано: <SECRET_1>, отвечает <PERSON_1>"),
    ("Сервер host-2 перезагружен, логи смотрел Михайлов, ошибок нет.", "Сервер host-2 перезагружен, логи смотрел <PERSON_1>, ошибок нет."),
    ("Сегодня обсудили бюджет, следующая встреча в четверг.", "Сегодня обсудили бюджет, следующая встреча в четверг."),
])
def test_layer_5_names_values_not_whole_sentences(layer, text, expected):
    """AC-4.1: пароль без ключевого слова и фамилия без имени находит только слой 5 — и только их."""
    result = sanitize(ChatState(chat_id="manual", net_key=bytes(32)), text, Settings(), Layers(llm=layer))
    assert result.sanitized == expected
