import json
import logging
import os
import re
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import uvicorn
from argon2 import PasswordHasher

from cleaner import __main__ as cli
from cleaner.__main__ import main
from cleaner.storage import crypto, db
from cleaner.storage.repo import Provider, Repository
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


def test_init_that_failed_to_create_the_database_leaves_nothing_behind(home, monkeypatch, clock):
    """Ревью 24.10.2026: ключ пишется раньше базы, и сбой её создания оставлял файл ключа — повторный init упирался в
    «файл ключа уже есть». Неудачный init не оставляет ни ключа, ни базы: им нечего защищать."""
    def full_disk(*args):
        raise sqlite3.OperationalError("database or disk is full")

    create_user = Repository.create_user
    monkeypatch.setattr(Repository, "create_user", full_disk)
    args = ["init", "--admin", "boss", "--env-file", str(home / "cleaner.env"), "--password-file", str(home / "secret.txt")]
    assert main(args) == 1
    assert not (home / "cleaner.env").exists() and list((home / "data").iterdir()) == []
    monkeypatch.setattr(Repository, "create_user", create_user)
    key = init(home)
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    assert [u.login for u in repo.users()] == ["boss"]
    repo.conn.close()


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


def test_apikey_add_list_disable(home, monkeypatch, capsys, clock):
    """FR-13.1: ключ выпускается командой для проектов, которые заводятся сценарием; печатается один раз."""
    key = init(home)
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, key)
    capsys.readouterr()
    assert main(["apikey", "add", "boss", "--name", "ci"]) == 0
    issued = capsys.readouterr().out
    assert re.fullmatch(r"ck_[A-Za-z0-9_-]{43}\n", issued)
    issued = issued.strip()
    assert main(["apikey", "list"]) == 0
    listing = capsys.readouterr().out
    [line] = listing.splitlines()
    key_id, login, name, tail, status, upstream = line.split("\t")
    assert (login, name, tail, status, upstream) == ("boss", "ci", f"…{issued[-4:]}", "active", "-")
    assert issued not in listing
    assert main(["apikey", "disable", key_id]) == 0
    assert main(["apikey", "list"]) == 0
    assert capsys.readouterr().out.rstrip("\n").split("\t")[-2] == "disabled"
    assert main(["apikey", "add", "nobody", "--name", "x"]) == 1
    assert main(["apikey", "disable", "нет"]) == 1
    assert main(["apikey", "add", "boss", "--name", " "]) == 1
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    assert [(e.event, e.details) for e in repo.audit_events(limit=2)] == [
        ("key_disabled", {"id": key_id, "by": "cli"}), ("key_created", {"id": key_id, "by": "cli"}),
    ]
    assert issued.encode("ascii") not in b"".join(p.read_bytes() for p in (home / "data").glob("cleaner.db*"))
    repo.conn.close()


def test_apikey_add_gateway_key(home, monkeypatch, capsys, clock):
    """Ключ шлюза агентов командой: подключение и модели проверяются, как в форме страницы «Ключи»."""
    key = init(home)
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, key)
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    anthropic = repo.add_provider(Provider("", "Заглушка", "anthropic", "http://127.0.0.1:9", "x-api-key", "sk-1", ("m-1", "m-2")))
    openai = repo.add_provider(Provider("", "OpenAI", "openai", "https://llm.example/v1", "bearer", "sk-2", ("g-1",)))
    repo.conn.close()
    capsys.readouterr()
    for extra in (["--provider", "нет"], ["--provider", openai], ["--provider", anthropic, "--model", "m-9"]):
        assert main(["apikey", "add", "boss", "--name", "агент", *extra]) == 1, extra
    assert main(["apikey", "add", "boss", "--name", "агент", "--provider", anthropic, "--model", "m-2"]) == 0
    assert re.fullmatch(r"ck_[A-Za-z0-9_-]{43}\n", capsys.readouterr().out)
    assert main(["apikey", "list"]) == 0
    assert capsys.readouterr().out.rstrip("\n").split("\t")[-1] == f"provider:{anthropic}"
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    [stored] = repo.api_keys()
    assert (stored.upstream, stored.models) == (f"provider:{anthropic}", ("m-2",))
    repo.conn.close()


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
    # Обзор плана 2+4, m-7: предупреждения Docling бывают с текстом ячеек документа — в журнал службы они не идут.
    assert all(logging.getLogger(name).level == logging.CRITICAL for name in ("docling", "transformers", "gliner"))


@pytest.fixture
def offline_env(monkeypatch):
    """serve ставит переменные OFFLINE в окружение процесса: после теста — прежние значения."""
    for name in cli.OFFLINE:
        monkeypatch.setenv(name, "")


def test_serve_exits_without_waiting_for_jobs_the_stop_left_running(home, monkeypatch, offline_env):
    """Находка «Small gaps left by the findings batch of 15.10»: когда uvicorn.run возвращается (Ctrl+C), интерпретатор
    при выходе ждал поток пула, пока его задание не кончится, — скан идёт минуты, — а запись задания в закрытую базу
    падала ошибкой. Недождавшиеся задания уже помечены прерванными: процесс выходит сразу, но после закрытия базы."""
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, init(home))
    left, exits = [0], []

    def run(app, **kwargs):
        app.state.unfinished_jobs = left[0]          # столько заданий остановка службы не дождалась (app.lifespan)
        exits.append(app.state.repo.conn)

    def exit_now():
        with pytest.raises(sqlite3.ProgrammingError):
            exits[-1].execute("SELECT 1")            # база уже закрыта
        exits.append("exit")

    monkeypatch.setattr(uvicorn, "run", run)
    monkeypatch.setattr(cli, "_exit_now", exit_now)
    assert main(["serve"]) == 0 and "exit" not in exits      # все дождались: обычный выход
    left[0] = 1
    main(["serve"])
    assert exits[-1] == "exit"


# Служба в отдельном процессе: задание идёт дольше ожидания остановки, сигнал — когда порт уже слушается.
_STUCK_SERVE = """
import signal, socket, sys, threading, time
import cleaner.web.app as web
from cleaner.__main__ import main
from cleaner.web.jobs import Jobs

port, sig, create_app = int(sys.argv[1]), getattr(signal, sys.argv[2]), web.create_app

def stop_when_listening():
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            time.sleep(0.05)
    signal.raise_signal(sig)

def stuck_app(*args, **kwargs):
    app = create_app(*args, jobs=Jobs(stop_wait=0.1), **kwargs)
    app.state.jobs.submit(threading.Event().wait, 60)
    threading.Thread(target=stop_when_listening, daemon=True).start()
    return app

web.create_app = stuck_app
sys.exit(main(["serve"]))
"""


@pytest.mark.integration
@pytest.mark.parametrize("sig", ["SIGTERM", "SIGINT"])
def test_service_process_ends_right_after_the_stop_marks_unfinished_jobs(home, monkeypatch, sig):
    """Находка «Small gaps left by the findings batch of 15.10»: по SIGTERM (systemd) uvicorn после остановки
    повторяет сигнал, и процесс кончается сразу; по SIGINT (Ctrl+C) uvicorn.run возвращается, и процесс жил,
    пока задание не кончится. Около трёх секунд на запуск дочернего процесса — поэтому integration."""
    key = init(home)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = home / "cleaner.toml"
    config.write_text(config.read_text(encoding="utf-8") + f"[server]\nport = {port}\n", encoding="utf-8")
    env = {**os.environ, crypto.MASTER_KEY_ENV: key, "CLEANER_CONFIG": str(config)}
    root = Path(__file__).resolve().parents[1]
    done = subprocess.run(
        [sys.executable, "-c", _STUCK_SERVE, str(port), sig], cwd=root, env=env, capture_output=True, timeout=20,
    )
    assert done.returncode == 0 or sig == "SIGTERM", done.stderr.decode(errors="replace")[-2000:]


def test_models_verify_names_what_is_missing(home, capsys):
    config = home / "cleaner.toml"
    config.write_text(
        f'[paths]\ndata_dir = "{(home / "data").as_posix()}"\nmodels_dir = "{(home / "models").as_posix()}"\n',
        encoding="utf-8",
    )
    assert main(["models", "verify", "--only", "docling"]) == 1
    assert "docling: нет каталога" in capsys.readouterr().out


def test_eval_measures_the_gold_set_and_guards_against_a_drop(home, monkeypatch, capsys, clock, offline_env):
    """FR-12.5, QA-6. Код выхода: 2 — сопоставимого базового замера нет, 1 — полнота упала, 0 — не упала."""
    key = init(home)
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, key)
    database = home / "data" / "cleaner.db"
    repo = open_repo(database, key, clock)
    repo.add_gold(None, "почта a@x.example", [{"start": 6, "end": 17, "type": "EMAIL", "entity": 0, "origin": "detector"}])
    repo.conn.close()
    assert main(["eval", "--layers", "1-3"]) == 2
    out = capsys.readouterr().out
    assert "EMAIL | 1.000 (1/1)" in out and "НЕ ПРОВЕРЕНО: слои 1-3: базового замера нет" in out and "QA-6 не проверена" in out
    assert main(["eval", "--layers", "1-3", "--save-baseline"]) == 2
    assert "Замер сохранён как базовый для слоёв 1-3" in capsys.readouterr().out
    assert main(["eval", "--layers", "1-3"]) == 0
    assert "ни один класс не упал" in capsys.readouterr().out

    repo = open_repo(database, key, clock)
    repo.add_gold(None, "звонил Петров", [{"start": 7, "end": 13, "type": "PERSON", "entity": 0, "origin": "detector"}])
    repo.conn.close()
    assert main(["eval", "--layers", "1-3", "--save-baseline"]) == 2          # набор другой: замена — только явно
    out = capsys.readouterr().out
    assert "снят на другом наборе (примеров было 1, сейчас 2)" in out and "--replace-baseline" in out
    assert main(["eval", "--layers", "1-3", "--replace-baseline"]) == 2
    assert "Замер сохранён как базовый" in capsys.readouterr().out

    repo = open_repo(database, key, clock)
    stored = json.loads(repo.setting("eval.baseline"))
    stored["datasets"]["gold"]["1-3"]["classes"]["ФИО"] = [1, 1]                # прежде имя скрывалось
    repo.set_setting("eval.baseline", json.dumps(stored, ensure_ascii=False))
    repo.conn.close()
    assert main(["eval", "--layers", "1-3", "--save-baseline"]) == 1
    out = capsys.readouterr().out
    assert "ПОЛНОТА УПАЛА: слои 1-3, «ФИО»: 1.000 → 0.000 (1 → 0 из 1)" in out and "не сохранён" in out
    repo = open_repo(database, key, clock)
    assert json.loads(repo.setting("eval.baseline"))["datasets"]["gold"]["1-3"]["classes"]["ФИО"] == [1, 1]
    assert "Петров" not in repo.setting("eval.passport") and "a@x" not in repo.setting("eval.passport")
    repo.conn.close()


def test_eval_of_an_open_set_checks_its_manifest_and_keeps_its_own_baseline(home, monkeypatch, capsys, clock, offline_env):
    """Идея аудита 21.10.2026: снимок сверяется с манифестом, а его базовый замер — отдельно от собственного набора."""
    from cleaner.eval.datasets import write_snapshot

    key = init(home)
    monkeypatch.setenv(crypto.MASTER_KEY_ENV, key)
    record = {"text": "почта a@x.example", "spans": [{"start": 6, "end": 17, "type": "EMAIL", "entity": 0}]}
    path = write_snapshot(home, "set", [record], "org/set", "abc123", True)
    assert main(["eval", "--jsonl", str(path), "--layers", "1-3", "--save-baseline"]) == 2
    out = capsys.readouterr().out
    assert "Набор: open:set; единица подсчёта — сущности после преобразования" in out and "НАБОР:" not in out
    assert "Снимок: org/set @ abc123" in out
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert main(["eval", "--jsonl", str(path), "--layers", "1-3"]) == 0
    assert "НАБОР: файл не совпадает с манифестом" in capsys.readouterr().out
    repo = open_repo(home / "data" / "cleaner.db", key, clock)
    assert set(json.loads(repo.setting("eval.baseline"))["datasets"]) == {"open:set"}
    repo.conn.close()
