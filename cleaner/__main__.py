"""Командная строка Cleaner (раздел 15 спецификации)."""
from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta, timezone
from pathlib import Path

from cleaner import config
from cleaner.clock import SystemClock
from cleaner.config import Config
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
    import uvicorn

    from cleaner.web.app import create_app

    cfg = _config(args)
    config.check_transport(cfg)
    with _repository(cfg) as repo:
        app = create_app(
            repo, SystemClock(), secure_cookies=bool(cfg.tls_cert), max_text_chars=cfg.max_text_chars,
            tz=timezone(timedelta(hours=cfg.utc_offset_hours)),
        )
        # Журнал доступа выключен: в строке запроса бывает поиск по названиям чатов (SEC-11).
        uvicorn.run(
            app, host=cfg.host, port=cfg.port, ssl_certfile=cfg.tls_cert or None, ssl_keyfile=cfg.tls_key or None,
            access_log=False, server_header=False, proxy_headers=False,
        )
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

    args = parser.parse_args(argv)
    if args.command == "verify":
        from cleaner import selfcheck

        return selfcheck.run(print)
    handlers = {"init": cmd_init, "serve": cmd_serve, "user": cmd_user, "key": cmd_key, "backup": cmd_backup}
    try:
        return handlers[args.command](args)
    except (ValueError, OSError, sqlite3.Error, crypto.CryptoError) as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
