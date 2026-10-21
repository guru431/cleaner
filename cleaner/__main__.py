"""Командная строка Cleaner (раздел 15 спецификации)."""
from __future__ import annotations

import argparse
import getpass
import logging
import os
import shutil
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta, timezone
from pathlib import Path

from cleaner import config
from cleaner.clock import SystemClock
from cleaner.config import Config
from cleaner.core.detect.base import DetectorError
from cleaner.storage import crypto, db
from cleaner.storage.repo import Repository
from cleaner.web import auth

CONFIG_ENV = "CLEANER_CONFIG"


def _config(args: argparse.Namespace) -> Config:
    """--config, иначе $CLEANER_CONFIG, иначе настройки по умолчанию (разработка: 127.0.0.1, каталог data)."""
    path = args.config or os.environ.get(CONFIG_ENV)
    return config.load(Path(path)) if path else Config()


def _write_private(path: Path, data: bytes) -> None:
    """Новый файл с правами 0600; существующий не перезаписывается (FileExistsError)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _secret(path: str | None, prompt: str) -> str:
    """Пароль: первая строка файла или ввод с клавиатуры дважды."""
    if path:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        return lines[0] if lines else ""
    first = getpass.getpass(prompt)
    if getpass.getpass("Ещё раз: ") != first:
        raise ValueError("пароли не совпадают")
    return first


@contextmanager
def _repository(cfg: Config, master: bytes | None = None, create: bool = False) -> Iterator[Repository]:
    if not create and not cfg.db_path.exists():
        raise ValueError(f"базы нет: {cfg.db_path}; сначала выполните init")
    conn = db.connect(cfg.db_path)
    try:
        db.migrate(conn)
        yield Repository(conn, master if master is not None else crypto.master_key_from_env(), SystemClock())
    finally:
        conn.close()


# Библиотеки моделей не обращаются в интернет (NFR-2, раздел 2 спецификации); на сервере то же задаёт юнит.
OFFLINE = {
    "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
    "DO_NOT_TRACK": "1", "TOKENIZERS_PARALLELISM": "false",
}


def _offline() -> None:
    """До первого импорта библиотек моделей: они читают переменные при импорте."""
    os.environ.update(OFFLINE)


# Библиотеки разбора и моделей пишут предупреждения с фрагментами документа («Could not extract chart data: …»
# с текстом ячейки), а журнал службы — systemd: их записи ниже CRITICAL не выводятся (SEC-11).
QUIET_LIBRARIES = (
    "docling", "docling_core", "docling_parse", "docling_ibm_models", "transformers", "gliner",
    "huggingface_hub", "pypdfium2", "PIL",
)


def _quiet_libraries() -> None:
    for name in QUIET_LIBRARIES:
        logging.getLogger(name).setLevel(logging.CRITICAL)


def _exit_now() -> None:
    """Выход без ожидания потоков пулов заданий: обычный выход ждёт каждый поток ThreadPoolExecutor, пока его
    задание не кончится. Журнал сбрасывается здесь: atexit при os._exit не выполняется."""
    logging.shutdown()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


def cmd_init(args: argparse.Namespace) -> int:
    cfg, env_file = _config(args), Path(args.env_file)
    if cfg.db_path.exists():
        raise ValueError(f"база уже есть: {cfg.db_path}")
    if env_file.exists():
        raise ValueError(f"файл ключа уже есть: {env_file}")
    password_hash = auth.hash_password(_secret(args.password_file, f"Пароль администратора {args.admin}: "))
    cfg.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = crypto.new_key()
    _write_private(env_file, f"{crypto.key_line(key)}\n".encode("ascii"))     # ключ — раньше базы: потерять его хуже
    with _repository(cfg, key, create=True) as repo:
        user_id = repo.create_user(args.admin, password_hash, "admin")
        repo.audit("user_created", target=user_id, role="admin", by="init")
    print(f"База создана: {cfg.db_path}")
    print(f"Главный ключ записан в {env_file}. Сохраните копию: python -m cleaner key export <файл>")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    _offline()
    _quiet_libraries()
    import uvicorn

    from cleaner.engines import Engines
    from cleaner.web.app import create_app

    cfg = _config(args)
    config.check_transport(cfg)
    with _repository(cfg) as repo:
        app = create_app(
            repo, SystemClock(), secure_cookies=bool(cfg.tls_cert), max_text_chars=cfg.max_text_chars,
            tz=timezone(timedelta(hours=cfg.utc_offset_hours)),
            engines=Engines(repo, cfg.models_dir, max_text_chars=cfg.max_text_chars),
            max_file_mb=cfg.max_file_mb,
        )
        # Журнал доступа выключен: в строке запроса бывает поиск по названиям чатов (SEC-11). Открытый поток ответа
        # облака (события сервера) не держит остановку: через 5 с соединения рвутся, и lifespan сохраняет идущие
        # ответы неполными, а не systemd убивает процесс через 90 с с потерей полученного.
        uvicorn.run(
            app, host=cfg.host, port=cfg.port, ssl_certfile=cfg.tls_cert or None, ssl_keyfile=cfg.tls_key or None,
            access_log=False, server_header=False, proxy_headers=False, timeout_graceful_shutdown=5,
        )
    if app.state.unfinished_jobs:
        # uvicorn.run вернулся (Ctrl+C; по SIGTERM процесс кончается раньше — uvicorn повторяет сигнал), а задания,
        # которых остановка не дождалась, уже помечены прерванными, и база закрыта: их результат записать некуда.
        # Иначе процесс жил бы до конца задания (скан — минуты) с запросами к шлюзу и ошибкой записи в журнале.
        _exit_now()
    return 0


def cmd_user(args: argparse.Namespace) -> int:
    with _repository(_config(args)) as repo:
        if args.action == "add":
            if repo.user_by_login(args.login) is not None:
                raise ValueError(f"пользователь {args.login} уже есть")
            password_hash = auth.hash_password(_secret(args.password_file, f"Пароль {args.login}: "))
            user_id = repo.create_user(args.login, password_hash, args.role)
            repo.audit("user_created", target=user_id, role=args.role, by="cli")
            return 0
        user = repo.user_by_login(args.login)
        if user is None:
            raise ValueError(f"нет пользователя {args.login}")
        if args.action == "disable":
            repo.set_disabled(user.id, True)
            repo.audit("user_disabled", target=user.id, by="cli")
        else:
            repo.set_password(user.id, auth.hash_password(_secret(args.password_file, f"Новый пароль {args.login}: ")))
            repo.audit("password_changed", target=user.id, by="cli")
    return 0


def cmd_key(args: argparse.Namespace) -> int:
    passphrase = _secret(args.passphrase_file, "Пароль файла ключа: ")
    if args.action == "export":
        if len(passphrase) < auth.MIN_PASSWORD:
            raise ValueError(f"пароль файла ключа короче {auth.MIN_PASSWORD} знаков")
        _write_private(Path(args.file), crypto.export_key(crypto.master_key_from_env(), passphrase))
        return 0
    if not args.env_file:
        raise ValueError("для import укажите --env-file")
    key = crypto.import_key(Path(args.file).read_bytes(), passphrase)
    _write_private(Path(args.env_file), f"{crypto.key_line(key)}\n".encode("ascii"))
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    target = Path(args.target)
    with _repository(_config(args)) as repo:
        _write_private(target, b"")         # права 0600 — до того, как в файл попадут данные
        repo.backup(target)
    print(f"Копия: {target}. Главный ключ в копию не входит.")
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    from cleaner import models

    cfg = _config(args)
    specs = [spec for spec in models.SPECS if args.only in (None, spec.directory)]
    if args.action == "download":
        cache = models.prepare_download(cfg.models_dir)
        try:
            for spec in specs:
                print(f"загрузка {spec.directory} ({spec.source} @ {spec.revision()})…")
                print(f"готово: {models.install(cfg.models_dir, spec)}")
        finally:
            shutil.rmtree(cache, ignore_errors=True)
        return 0
    failures = 0
    for spec in specs:
        problems = models.verify(cfg.models_dir, spec)
        print(f"{spec.directory}: {'OK' if not problems else '; '.join(problems)}")
        failures += bool(problems)
    return 1 if failures else 0


def cmd_eval(args: argparse.Namespace) -> int:
    """FR-12.5: полнота и точность по типам на эталонном наборе или наборе JSONL; QA-5 — по слоям, QA-6 — сравнение.

    Код выхода: 1 — полнота упала, 2 — QA-6 не проверена (сопоставимого базового замера нет), 0 — ни один класс не упал."""
    _offline()
    from cleaner.engines import Engines
    from cleaner.eval import datasets, runner

    cfg = _config(args)
    with _repository(cfg) as repo:
        unit, source = runner.UNIT_GOLD, None
        if args.jsonl:
            path = Path(args.jsonl)
            name, source, problems = datasets.check_snapshot(path)
            for problem in problems:
                print(f"НАБОР: {problem}")
            dataset = runner.OPEN_PREFIX + name
            unit = runner.UNIT_OPEN if source and source.get("converter") == datasets.CONVERTER else runner.UNIT_FILE
            examples = runner.jsonl_examples(path)
        else:
            dataset, examples = runner.GOLD, runner.gold_examples(repo)
        if not examples:
            raise ValueError("эталонный набор пуст: примеры сохраняются кнопкой «Сохранить как эталон» на экране проверки")
        done = runner.measure(repo, dataset, examples, args.layers, Engines(repo, cfg.models_dir), cfg.models_dir, unit, source)
        print(f"Набор: {dataset}; единица подсчёта — {unit}")
        if source:
            print(f"Снимок: {source.get('source')} @ {source.get('revision') or '—'}, sha256 {str(source.get('sha256'))[:12]}")
        print(runner.format_results(done.results, done.examples))
        print()
        comparison = done.comparison
        for line in comparison.lines():
            print(line)
        if args.save_baseline or args.replace_baseline:
            if comparison.drops and not args.replace_baseline:
                print("Замер не сохранён как базовый: полнота упала.")
            elif comparison.replace and not args.replace_baseline:
                print(
                    f"Замер не сохранён как базовый: у слоёв {', '.join(comparison.replace)} базовый замер снят на другом "
                    "наборе или в прежнем формате. Принять новый замер — явным решением, ключом --replace-baseline."
                )
            else:
                runner.save_baseline(repo, dataset, done.results, done.fingerprint, done.examples)
                print(
                    f"Замер сохранён как базовый для слоёв {', '.join(done.results)} (QA-6); "
                    "базовые замеры других слоёв не тронуты."
                )
    return 1 if comparison.drops else 2 if comparison.unchecked else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cleaner", description="Очистка данных перед облачными LLM")
    parser.add_argument("--config", help=f"путь к cleaner.toml; по умолчанию ${CONFIG_ENV}")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="создать базу, главный ключ и первого администратора")
    init.add_argument("--admin", required=True, help="логин администратора")
    init.add_argument("--env-file", required=True, help="новый файл для главного ключа (файл окружения службы)")
    init.add_argument("--password-file", help="пароль администратора — первой строкой файла")

    commands.add_parser("serve", help="запустить службу")

    user = commands.add_parser("user", help="учётные записи")
    user.add_argument("action", choices=("add", "disable", "passwd"))
    user.add_argument("login")
    user.add_argument("--role", choices=("admin", "user"), default="user")
    user.add_argument("--password-file", help="пароль — первой строкой файла")

    key = commands.add_parser("key", help="выгрузка и загрузка главного ключа")
    key.add_argument("action", choices=("export", "import"))
    key.add_argument("file", help="файл ключа, защищённый паролем")
    key.add_argument("--passphrase-file", help="пароль файла ключа — первой строкой файла")
    key.add_argument("--env-file", help="для import: новый файл окружения для ключа")

    backup = commands.add_parser("backup", help="копия базы без остановки службы")
    backup.add_argument("target", help="новый файл копии")

    commands.add_parser("verify", help="самопроверка очистки и восстановления на подложенных значениях")

    models = commands.add_parser("models", help="модели слоя 4 и разбора документов: загрузка (нужен интернет) и сверка")
    models.add_argument("action", choices=("download", "verify"))
    models.add_argument("--only", choices=("rubert-base-pii-ner", "gliner-pii-base-v1.0", "docling"))

    evaluate = commands.add_parser("eval", help="измерение качества на эталонном наборе (FR-12.5)")
    evaluate.add_argument("--layers", nargs="+", choices=("1-3", "1-4", "1-5"), default=["1-3", "1-4"])
    evaluate.add_argument("--jsonl", help="вместо эталонного набора — файл JSONL (открытые наборы, QA-4)")
    evaluate.add_argument(
        "--save-baseline", action="store_true",
        help="сохранить замер как базовый для измеренных слоёв, если полнота не упала и набор тот же",
    )
    evaluate.add_argument(
        "--replace-baseline", action="store_true",
        help="сохранить как базовый и при другом наборе или упавшей полноте — явное решение (QA-3, QA-6)",
    )

    args = parser.parse_args(argv)
    if args.command == "verify":
        from cleaner import selfcheck

        return selfcheck.run(print)
    handlers = {
        "init": cmd_init, "serve": cmd_serve, "user": cmd_user, "key": cmd_key, "backup": cmd_backup, "models": cmd_models,
        "eval": cmd_eval,
    }
    try:
        return handlers[args.command](args)
    except (ValueError, OSError, sqlite3.Error, crypto.CryptoError, DetectorError) as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
