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
        "ReadWritePaths=/var/lib/cleaner", "Restart=always", "After=network-online.target cleaner-egress.service",
        "Wants=network-online.target cleaner-egress.service", "WantedBy=multi-user.target",
        "ExecStartPre=+/usr/local/sbin/cleaner-egress.sh check",
    ):
        assert line in lines, line
    # Этап 3: выход наружу ограничивает цепочка CLEANER-EGRESS; IPAddressDeny= закрыл бы и порт 443.
    assert not [line for line in lines if line.startswith(("IPAddressDeny", "IPAddressAllow"))]


EGRESS = DEPLOY / "cleaner-egress.sh"
_INTERNAL = re.compile(r'^INTERNAL="(?:\$\{[A-Z_]+:-)?([^}"]*)\}?"$', re.MULTILINE)


def _internal(path: Path) -> set[str]:
    return set(_INTERNAL.search(path.read_text(encoding="utf-8")).group(1).split())


def test_egress_table_allows_internal_nets_and_443_and_rejects_the_rest():
    """Раздел 15 спецификации, SEC-15: своя таблица nftables (ufw её не чистит), заменяется одной транзакцией;
    внутренние сети, затем 443 по IPv4 с записью, остальное — запись и отказ."""
    text = EGRESS.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n") and "\r" not in text
    assert _internal(EGRESS) == {
        "127.0.0.0/8", "example/24", "example/24", "example/19", "example/24", "172.16.0.0/12",
    }
    rules = text[text.index("nft -f - <<EOF"):]
    order = [rules.index(part) for part in (
        "table inet $TABLE\ndelete table inet $TABLE\n", "type filter hook output priority filter; policy accept;",
        "meta skuid $uid jump cleaner", "chain cleaner {", "ip daddr { $nets } return", "ip6 daddr ::1 return",
        'log prefix "cleaner-out: "', "meta nfproto ipv4 tcp dport 443 return", 'log prefix "cleaner-egress: "',
        "meta l4proto tcp reject with tcp reset", "        reject\n",
    )]
    assert order == sorted(order)
    assert "iptables" not in text.replace("iptables-nft", "").split("set -euo pipefail", 1)[1]
    # 15.10.2026: «skuid != … return» не срабатывает у пакетов без сокета пользователя (туннель WireGuard
    # сервера), и они проваливались в отказ. Только положительный отбор по учётной записи.
    assert not [line for line in rules.splitlines() if "skuid !=" in line and not line.strip().startswith("#")]
    # Второй слой для входящих на порт службы — тот же, что у правила ufw и настроек сервера.
    cfg = config.load(DEPLOY / "cleaner.toml")
    assert f"PORT={cfg.port}" in text.splitlines() and "CLIENTS=example/19" in text.splitlines()
    # Профиль хоста переопределяет сети до построения таблицы; сетей клиентов может быть несколько.
    assert text.index('. "$HOST_ENV"') < text.index("nft -f - <<EOF")
    assert "clients=$(tr ' ' ',' <<< \"$CLIENTS\")" in text.splitlines()
    assert "tcp dport $PORT ip saddr != { $clients, 127.0.0.0/8 } drop" in rules
    unit = (DEPLOY / "cleaner-egress.service").read_text(encoding="utf-8").splitlines()
    for line in ("Type=oneshot", "RemainAfterExit=yes", "ExecStart=/usr/local/sbin/cleaner-egress.sh",
                 "After=network-online.target", "Before=cleaner.service", "WantedBy=multi-user.target"):
        assert line in unit, line


def test_egress_internal_nets_match_the_servers_guard():
    """Правило vLLM: все копии списка внутренних сетей меняются вместе. Тест vLLM видит только свой репозиторий."""
    guard = Path("D:/vsc/vLLM/dashboard/deploy/ai-egress-guard.sh")
    if not guard.exists():
        pytest.skip("репозитория vLLM рядом нет (сервер); там сверяет check-cleaner.sh")
    assert _internal(EGRESS) == _internal(guard)


def test_installer_sets_the_egress_chain_before_the_service_restarts():
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    assert 'install -o root -g root -m 0755 "$SRC/deploy/cleaner-egress.sh" "$EGRESS"' in text
    assert text.index("systemctl restart cleaner-egress.service") < text.index("systemctl restart cleaner.service\ncode=")


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


@pytest.mark.parametrize("source, lock", [
    ("requirements.in", "requirements-linux.txt"), ("requirements-dev.in", "requirements-dev-linux.txt"),
])
def test_server_lock_carries_every_top_level_requirement(source, lock):
    """Обзор плана 1В: подмножество версий машины разработки — ещё не полнота. Зависимость, забытая
    в замке сервера, обнаружилась бы только при установке, а то и при первом импорте в службе."""
    names = set()
    for line in (ROOT / source).read_text(encoding="utf-8").splitlines():
        if match := re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line):
            names.add(re.sub(r"[-_.]+", "-", match.group()).lower())
    assert names and names - set(_pins(ROOT / lock)) == set()


@pytest.mark.parametrize("script", ["check-cleaner.sh", "install-cleaner.sh"])
def test_scripts_use_the_addresses_and_paths_of_the_unit_and_the_config(script):
    """Установщик и проверка живут отдельно от юнита и настроек: порт и каталоги у них общие,
    адрес и сети — из профиля хоста."""
    cfg = config.load(DEPLOY / "cleaner.toml")
    text = (DEPLOY / script).read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n") and "\r" not in text
    lines = text.splitlines()
    for line in (f"PORT={cfg.port}", "APP=/opt/cleaner", f"DATA={cfg.data_dir.as_posix()}", "ETC=/etc/cleaner"):
        assert line in lines, line
    if script == "check-cleaner.sh":
        # Значения по умолчанию — example (сервер, где профиль ещё не разложен); host.env их переопределяет.
        s06 = _profile(HOSTS / "example.conf")
        assert f"HOST_IP={s06['HOST_IP']}" in lines and f"CLIENTS={s06['CLIENTS']}" in lines
        assert text.index('. "$HOST_ENV"') < text.index('echo "1. Служба"')
    else:
        assert 'PROFILE="$SRC/deploy/hosts/$HOST_NAME.conf"' in lines
        assert text.index("require_safe_src \"$SRC\"") < text.index('. "$PROFILE"')
        assert 'install -o root -g root -m 0644 "$PROFILE" "$HOST_ENV"' in lines


HOSTS = DEPLOY / "hosts"
_REQUIRED = ("HOST_IP", "CLIENTS", "INTERNAL", "GATEWAY", "CERT_NAME", "SERVER_GUARD", "GATEWAY_KEY_HINT")


def _profile(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key] = value.strip('"')
    return values


def test_host_profiles_are_complete_and_clients_stay_inside_internal_nets():
    """Профиль хоста задаёт адрес, сети и шлюз. Таблица cleaner_egress фильтрует и ответы службы:
    клиент вне внутренних сетей получил бы отказ на свой же запрос — поэтому CLIENTS ⊂ INTERNAL."""
    import ipaddress

    profiles = sorted(HOSTS.glob("*.conf"))
    assert {p.stem for p in profiles} >= {"example", "example"}
    for path in profiles:
        text = path.read_text(encoding="utf-8")
        assert "\r" not in text, path.name
        values = _profile(path)
        assert set(_REQUIRED) <= set(values) and all(values[key] for key in _REQUIRED), path.name
        ipaddress.ip_address(values["HOST_IP"])
        internal = [ipaddress.ip_network(net) for net in values["INTERNAL"].split()]
        assert ipaddress.ip_network("127.0.0.0/8") in internal, path.name
        for net in values["CLIENTS"].split():
            client = ipaddress.ip_network(net)
            assert any(client.subnet_of(inner) for inner in internal), f"{path.name}: {net} вне INTERNAL"
        assert values["SERVER_GUARD"] in ("0", "1"), path.name


def test_s06_profile_matches_the_defaults_of_the_config_and_the_egress_chain():
    """example — сервер, где всё начиналось: значения по умолчанию в настройках и сценариях совпадают с профилем."""
    s06 = _profile(HOSTS / "example.conf")
    cfg = config.load(DEPLOY / "cleaner.toml")
    assert s06["HOST_IP"] == cfg.host
    assert set(s06["INTERNAL"].split()) == _internal(EGRESS)
    assert (s06["GATEWAY"], s06["SERVER_GUARD"]) == ("127.0.0.1:30000", "1")


def test_example_profile_opens_the_home_lan_and_vpn_and_uses_the_local_gateway():
    """Решение владельца 2026-10-15: на example — домашняя сеть и VPN, слой 5 — шлюз llm_routers на этом же хосте."""
    srv = _profile(HOSTS / "example.conf")
    assert (srv["HOST_IP"], srv["CLIENTS"]) == ("example, "192.168.0.0/20 example/20")
    assert (srv["GATEWAY"], srv["SERVER_GUARD"]) == ("127.0.0.1:4000", "0")


def test_installer_renders_the_service_address_from_the_profile():
    """Адрес службы в /etc/cleaner/cleaner.toml берётся из профиля, и установщик проверяет подстановку."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    assert 's|^host = .*|host = \\"${HOST_IP}\\"' in text
    assert 'grep -q "^host = \\"${HOST_IP}\\"" "$CONF"' in text


def test_server_dependencies_take_torch_without_cuda():
    """Сборка torch с PyPI тянет на Linux пакеты NVIDIA; видеокарта сервера занята языковой моделью."""
    text = (ROOT / "requirements-linux.txt").read_text(encoding="utf-8")
    assert "--extra-index-url https://download.pytorch.org/whl/cpu" in text.splitlines()
    pins = _pins(ROOT / "requirements-linux.txt")
    assert pins["torch"].endswith("+cpu")
    assert not [name for name in pins if name.startswith(("nvidia-", "cuda-")) or name == "triton"]


def test_installer_copies_the_database_before_the_new_version_and_rollback_restores_it():
    """Обзор плана 2+4, I-4: новая версия мигрирует схему при старте, а прежний код базу новой версии не откроет.
    Копия снимается до перезапуска службы, откат возвращает её, если схема успела измениться."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    rollback = text[text.index("rollback() {"):text.index("trap 'rollback")]
    assert 'install -o cleaner -g cleaner -m 0600 "$DB_BACKUP" "$DATA/cleaner.db"' in rollback
    assert text.index('DB_BACKUP="$DATA/cleaner.db.bak-$STAMP"') < text.index("systemctl restart cleaner.service\ncode=")
