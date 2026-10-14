"""Файлы установки на example: договорённости между юнитом, настройками, файлами зависимостей и кодом.

Сами сценарии deploy/ проверяются на сервере (check-cleaner.sh) и в быстрый набор не входят.
"""
import re
from pathlib import Path

import pytest

from cleaner import config

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def test_server_config_loads_and_satisfies_the_tls_rule():
    cfg = config.load(DEPLOY / "cleaner.toml")
    assert (cfg.host, cfg.port, cfg.data_dir.as_posix()) == ("example", 5464, "/var/lib/cleaner")
    assert (cfg.tls_cert, cfg.tls_key) == ("/etc/cleaner/tls/cert.pem", "/etc/cleaner/tls/key.pem")
    assert (cfg.models_dir.as_posix(), cfg.max_file_mb) == ("/opt/cleaner/models", 50)
    config.check_transport(cfg)


def test_unit_declares_what_the_spec_and_the_server_checks_expect():
    """Раздел 15 спецификации и check-egress.sh сервера: учётная запись, файлы, ограничения, запрет исходящих."""
    lines = set((DEPLOY / "cleaner.service").read_text(encoding="utf-8").splitlines())
    for line in (
        "User=cleaner", "Group=cleaner", "WorkingDirectory=/opt/cleaner",
        "EnvironmentFile=/etc/cleaner/cleaner.env", 'Environment="CLEANER_CONFIG=/etc/cleaner/cleaner.toml"',
        'Environment="HOME=/var/lib/cleaner"', "ExecStart=/opt/cleaner/.venv/bin/python -m cleaner serve",
        'Environment="HF_HUB_OFFLINE=1"', 'Environment="TRANSFORMERS_OFFLINE=1"', 'Environment="TOKENIZERS_PARALLELISM=false"',
        "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "NoNewPrivileges=yes", "RestrictSUIDSGID=yes",
        "ReadWritePaths=/var/lib/cleaner", "Restart=always", "After=network-online.target",
        "WantedBy=multi-user.target", "IPAddressDeny=any", "IPAddressAllow=localhost",
        "IPAddressAllow=example/19", "IPAddressAllow=172.16.0.0/12",
    ):
        assert line in lines, line


def _pins(path: Path) -> dict[str, str]:
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if match := re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(\S+)", line):
            pins[re.sub(r"[-_.]+", "-", match.group(1)).lower()] = match.group(2)
    return pins


def test_server_dependencies_pin_the_versions_tested_on_the_dev_machine():
    """SEC-14: на сервере те же версии, что прошли быстрый набор здесь, и у каждой — контрольные суммы."""
    dev = {**_pins(ROOT / "requirements.txt"), **_pins(ROOT / "requirements-dev.txt")}
    for name in ("requirements-linux.txt", "requirements-dev-linux.txt"):
        server = _pins(ROOT / name)
        assert server and {package: dev.get(package) for package in server} == server, name
        blocks = (ROOT / name).read_text(encoding="utf-8").split("==")[1:]
        assert all("--hash=sha256:" in block for block in blocks), name


@pytest.mark.parametrize("script", ["check-cleaner.sh", "install-cleaner.sh"])
def test_scripts_use_the_addresses_and_paths_of_the_unit_and_the_config(script):
    """Установщик и проверка живут отдельно от юнита и настроек: адрес, порт и каталоги у них общие."""
    cfg = config.load(DEPLOY / "cleaner.toml")
    text = (DEPLOY / script).read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n") and "\r" not in text
    lines = text.splitlines()
    for line in (
        f"HOST_IP={cfg.host}", f"PORT={cfg.port}", "CLIENTS=example/19",
        "APP=/opt/cleaner", f"DATA={cfg.data_dir.as_posix()}", "ETC=/etc/cleaner",
    ):
        assert line in lines, line


def test_server_dependencies_take_torch_without_cuda():
    """Сборка torch с PyPI тянет на Linux пакеты NVIDIA; видеокарта сервера занята языковой моделью."""
    text = (ROOT / "requirements-linux.txt").read_text(encoding="utf-8")
    assert "--extra-index-url https://download.pytorch.org/whl/cpu" in text.splitlines()
    pins = _pins(ROOT / "requirements-linux.txt")
    assert pins["torch"].endswith("+cpu")
    assert not [name for name in pins if name.startswith(("nvidia-", "cuda-")) or name == "triton"]
