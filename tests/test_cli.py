import json
import os

import pytest
import uvicorn
from argon2 import PasswordHasher

from cleaner.__main__ import main
from cleaner.storage import crypto, db
from cleaner.storage.repo import Repository
from cleaner.web import auth


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Каталог установки: cleaner.toml и файл с паролем; быстрый Argon2; ключа в окружении нет."""
    monkeypatch.setattr(auth, "_hasher", PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1))
    monkeypatch.delenv(crypto.MASTER_KEY_ENV, raising=False)
    config = tmp_path / "cleaner.toml"
    config.write_text(f'[paths]\ndata_dir = "{(tmp_path / "data").as_posix()}"\n', encoding="utf-8")
    monkeypatch.setenv("CLEANER_CONFIG", str(config))
    (tmp_path / "secret.txt").write_text("длинный-пароль-1\n", encoding="utf-8")
    return tmp_path


def init(home) -> str:
    """Выполнить init; вернуть главный ключ из записанного файла окружения."""
    args = ["init", "--admin", "boss", "--env-file", str(home / "cleaner.env"), "--password-file", str(home / "secret.txt")]
    assert main(args) == 0
    name, value = (home / "cleaner.env").read_text(encoding="ascii").strip().split("=", 1)
    assert name == crypto.MASTER_KEY_ENV
    return value


def open_repo(path, key: str, clock) -> Repository:
    return Repository(db.connect(path), crypto.master_key_from_env({crypto.MASTER_KEY_ENV: key}), clock)


def test_init_creates_the_database_the_key_and_the_admin(home, clock):
    key = init(home)
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    assert [(u.login, u.role) for u in repo.users()] == [("boss", "admin")]
    repo.conn.close()
    again = ["init", "--admin", "boss", "--env-file", str(home / "other.env"), "--password-file", str(home / "secret.txt")]
    assert main(again) == 1 and not (home / "other.env").exists()


def test_users_key_export_import_and_backup(home, monkeypatch, clock):
    key = init(home)
    secret = str(home / "secret.txt")
    assert main(["user", "add", "ivan", "--password-file", secret]) == 1          # ключа в окружении нет
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, key)
    assert main(["user", "add", "ivan", "--password-file", secret]) == 0
    assert main(["user", "disable", "ivan"]) == 0
    assert main(["user", "passwd", "boss", "--password-file", secret]) == 0
    assert main(["user", "disable", "nobody"]) == 1
    assert main(["key", "export", str(home / "key.bin"), "--passphrase-file", secret]) == 0
    restored = home / "restored.env"
    assert main(["key", "import", str(home / "key.bin"), "--passphrase-file", secret, "--env-file", str(restored)]) == 0
    assert restored.read_text(encoding="ascii") == (home / "cleaner.env").read_text(encoding="ascii")
    assert main(["backup", str(home / "copy.db")]) == 0
    copy = open_repo(home / "copy.db", key, clock)
    assert {(u.login, u.disabled) for u in copy.users()} == {("boss", False), ("ivan", True)}
    copy.conn.close()
    assert main(["backup", str(home / "copy.db")]) == 1                           # существующий файл не трогается


def test_serve_needs_tls_off_loopback_and_runs_without_the_access_log(home, monkeypatch):
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY", "DO_NOT_TRACK", "TOKENIZERS_PARALLELISM"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, init(home))
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))
    config, data = home / "cleaner.toml", f'[paths]\ndata_dir = "{(home / "data").as_posix()}"\n'
    config.write_text('[server]\nhost = "example"\n' + data, encoding="utf-8")
    assert main(["serve"]) == 1 and calls == []
    config.write_text('[server]\nhost = "example"\ntls_cert = "c.pem"\ntls_key = "k.pem"\n' + data, encoding="utf-8")
    assert main(["serve"]) == 0
    [kwargs] = calls
    assert (kwargs["host"], kwargs["ssl_certfile"], kwargs["access_log"]) == ("example", "c.pem", False)
    assert os.environ["HF_HUB_OFFLINE"] == "1" and os.environ["TRANSFORMERS_OFFLINE"] == "1"


def test_models_verify_names_what_is_missing(home, capsys):
    config = home / "cleaner.toml"
    config.write_text(
        f'[paths]\ndata_dir = "{(home / "data").as_posix()}"\nmodels_dir = "{(home / "models").as_posix()}"\n',
        encoding="utf-8",
    )
    assert main(["models", "verify", "--only", "docling"]) == 1
    assert "docling: нет каталога" in capsys.readouterr().out


def test_eval_measures_the_gold_set_and_guards_against_a_drop(home, monkeypatch, capsys, clock):
    """FR-12.5, QA-6."""
    key = init(home)
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, key)
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY", "DO_NOT_TRACK", "TOKENIZERS_PARALLELISM"):
        monkeypatch.setenv(name, "")
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    repo.add_gold(None, "почта a@x.example", [{"start": 6, "end": 17, "type": "EMAIL", "entity": 0, "origin": "detector"}])
    repo.set_setting("eval.baseline", json.dumps({"1-3": {"ФИО": 1.0}}, ensure_ascii=False))
    repo.conn.close()
    assert main(["eval", "--layers", "1-3"]) == 0
    assert "EMAIL | 1.000 (1/1)" in capsys.readouterr().out
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    repo.add_gold(None, "звонил Петров", [{"start": 7, "end": 13, "type": "PERSON", "entity": 0, "origin": "detector"}])
    repo.conn.close()
    assert main(["eval", "--layers", "1-3", "--save-baseline"]) == 1
    out = capsys.readouterr().out
    assert "ПОЛНОТА УПАЛА: слои 1-3, «ФИО»: 1.000 → 0.000" in out and "не сохранён" in out
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    assert json.loads(repo.setting("eval.baseline")) == {"1-3": {"ФИО": 1.0}}
    repo.conn.close()
