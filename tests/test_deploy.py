"""Файлы установки: договорённости между юнитом, настройками, файлами зависимостей и кодом.

Исполняемые ветки сценариев проверяются отдельно под Bash с подставными командами системы.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryFile

import pytest

from cleaner import config

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def test_server_config_loads_and_satisfies_the_tls_rule():
    cfg = config.load(DEPLOY / "cleaner.toml")
    assert (cfg.host, cfg.port, cfg.data_dir.as_posix()) == ("127.0.0.1", 5464, "/var/lib/cleaner")
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
    assert _internal(EGRESS) == {"127.0.0.0/8"}
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
    assert f"PORT={cfg.port}" in text.splitlines() and "CLIENTS=127.0.0.0/8" in text.splitlines()
    # Профиль хоста переопределяет сети до построения таблицы; сетей клиентов может быть несколько.
    assert text.index('. "$HOST_ENV"') < text.index("nft -f - <<EOF")
    assert "clients=$(tr ' ' ',' <<< \"$CLIENTS\")" in text.splitlines()
    assert "tcp dport $PORT ip saddr != { $clients, 127.0.0.0/8 } drop" in rules
    unit = (DEPLOY / "cleaner-egress.service").read_text(encoding="utf-8").splitlines()
    for line in ("Type=oneshot", "RemainAfterExit=yes", "ExecStart=/usr/local/sbin/cleaner-egress.sh",
                 "After=network-online.target", "Before=cleaner.service", "WantedBy=multi-user.target"):
        assert line in unit, line


def test_egress_internal_nets_match_the_servers_guard():
    """Локальный профиль и серверный экран должны разрешать одинаковые внутренние сети."""
    guard = os.environ.get("CLEANER_SERVER_GUARD")
    if not guard:
        pytest.skip("CLEANER_SERVER_GUARD не задан; на сервере сверяет check-cleaner.sh")
    profile = Path(os.environ.get("CLEANER_HOST_PROFILE", str(HOSTS / "example.conf")))
    assert set(_profile(profile)["INTERNAL"].split()) == _internal(Path(guard))


def test_installer_sets_the_egress_chain_before_the_service_restarts():
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    assert 'install -o root -g root -m 0755 "$SRC/deploy/cleaner-egress.sh" "$EGRESS"' in text
    assert text.index("systemctl restart cleaner-egress.service") < text.index("systemctl restart cleaner.service\ncode=")


def test_timer_restores_the_egress_table_after_a_ruleset_flush():
    """Идея 12.11.2026: «flush ruleset» из /etc/nftables.conf снимает и таблицу cleaner_egress, а проверяют её только
    при старте службы. Таймер раз в 5 минут сверяет таблицу и при провале ставит её заново; установщик ставит таймер
    вместе с таблицей, check-cleaner.sh проверяет, что он активен."""
    text = EGRESS.read_text(encoding="utf-8")
    watch = text[text.index('if [[ "${1:-}" == "watch" ]]; then'):text.index("uid=$(id -u")]
    assert watch.index("if check 2>/dev/null; then exit 0; fi") < watch.index("systemctl restart cleaner-egress.service")
    assert "<4>cleaner-egress:" in watch
    service = (DEPLOY / "cleaner-egress-watch.service").read_text(encoding="utf-8")
    timer = (DEPLOY / "cleaner-egress-watch.timer").read_text(encoding="utf-8")
    assert "\r" not in service + timer
    for line in ("Type=oneshot", "ExecStart=/usr/local/sbin/cleaner-egress.sh watch"):
        assert line in service.splitlines(), line
    for line in ("OnBootSec=5min", "OnUnitActiveSec=5min", "Unit=cleaner-egress-watch.service", "WantedBy=timers.target"):
        assert line in timer.splitlines(), line
    installer = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    for line in ('install -o root -g root -m 0644 "$SRC/deploy/cleaner-egress-watch.service" "$EGRESS_WATCH.service"',
                 'install -o root -g root -m 0644 "$SRC/deploy/cleaner-egress-watch.timer" "$EGRESS_WATCH.timer"'):
        assert installer.index(line) < installer.index("systemctl daemon-reload\nsystemctl enable cleaner-egress")
    assert "systemctl enable cleaner-egress-watch.timer" in installer
    assert "systemctl restart cleaner-egress-watch.timer" in installer
    check = (DEPLOY / "check-cleaner.sh").read_text(encoding="utf-8")
    assert 'systemctl is-active cleaner-egress-watch.timer' in check
    assert "*.timer   text eol=lf" in (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()


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


def test_readme_dev_install_takes_the_application_lock_too():
    """Находка 12.11.2026: «-c requirements.txt» в requirements-dev.in только ограничивает версии, и замок
    разработки без замка приложения не ставил fastapi и др. — `cleaner init` из README падал на импорте."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    command = next(line for line in readme.splitlines() if "pip install" in line)
    locks = re.findall(r"-r (\S+)", command)
    pinned = set().union(*(_pins(ROOT / lock) for lock in locks))
    for source in ("requirements.in", "requirements-dev.in"):
        for line in (ROOT / source).read_text(encoding="utf-8").splitlines():
            if match := re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line):
                assert re.sub(r"[-_.]+", "-", match.group()).lower() in pinned, (source, line)
    assert "-r requirements-linux.txt -r requirements-dev-linux.txt" in readme


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
        # Без локального профиля проверка использует безопасные петлевые значения.
        example = _profile(HOSTS / "example.conf")
        assert f"HOST_IP={example['HOST_IP']}" in lines and f"CLIENTS={example['CLIENTS']}" in lines
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
    assert "example" in {p.stem for p in profiles}
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


def test_example_profile_matches_the_defaults_of_the_config_and_the_egress_chain():
    """Без рабочего профиля сервер и экран ограничены петлёй."""
    example = _profile(HOSTS / "example.conf")
    cfg = config.load(DEPLOY / "cleaner.toml")
    assert example["HOST_IP"] == cfg.host
    assert set(example["INTERNAL"].split()) == _internal(EGRESS)
    assert (example["GATEWAY"], example["SERVER_GUARD"]) == ("127.0.0.1:30000", "0")


def test_perimeter_keeps_the_port_open_to_the_profile_clients():
    """Необязательная локальная сверка сетей клиента со списком внешнего периметра."""
    nets = os.environ.get("CLEANER_PERIMETER_CONFIG")
    if not nets:
        pytest.skip("CLEANER_PERIMETER_CONFIG не задан")
    profile = Path(os.environ.get("CLEANER_HOST_PROFILE", str(HOSTS / "example.conf")))
    perimeter = _profile(Path(nets))
    cfg = config.load(DEPLOY / "cleaner.toml")
    assert (perimeter["CLEANER_PORT"], perimeter["CLEANER_NETS"]) == (str(cfg.port), _profile(profile)["CLIENTS"])
    assert "comment 'cleaner'" in (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")


def test_installer_renders_the_service_address_from_the_profile():
    """Адрес службы в /etc/cleaner/cleaner.toml берётся из профиля, и установщик проверяет подстановку."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    assert 's|^host = .*|host = \\"${HOST_IP}\\"' in text
    assert 'grep -q "^host = \\"${HOST_IP}\\"" "$CONF"' in text


def test_installer_refuses_a_profile_address_the_config_and_certificate_do_not_carry():
    """Находка 12.11.2026: адрес в cleaner.toml и SAN сертификата ставятся один раз. После смены HOST_IP проверка
    HTTPS по новому адресу откатывала код, а новый host.env оставался. Сверка — до любых изменений, с подсказкой."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    checks = text.index('conf_host=$(sed -n')
    assert text.index('FIRST_INSTALL=1') < checks < text.index("useradd --system")
    write_profile = text.index('install -o root -g root -m 0644 "$PROFILE" "$HOST_ENV"')
    assert checks < write_profile < text.index("\nsystemctl restart cleaner-egress.service\n")
    san = text[text.index("-ext subjectAltName"):text.index("# --- учётная запись")]
    # Ревью 12.11.2026: проверка HTTPS идёт по адресу; отказ — только при чужом IP, другое имя — предупреждение,
    # иначе обновление требовало бы перевыпуска (новый отпечаток у всех клиентов шлюза).
    ip_check, dns_check = san.index('*",IPAddress:${HOST_IP},"*'), san.index('*",DNS:${CERT_NAME},"*')
    assert san[ip_check:dns_check].count("|| fail ") == 1
    dns = san[dns_check:san.index("\nfi\n", dns_check)]
    assert '|| log "ВНИМАНИЕ:' in dns and "|| fail" not in dns and "${REISSUE_HINT}" in dns
    # Ревью 12.11.2026: до ловушки сбой openssl в $(…) под set -e завершал установщик без сообщения.
    assert "| tr -d ' ') || true" in san
    assert text.index("-ext subjectAltName") < text.index('mv "$TLS/cert.pem" "$TLS/cert.pem.prev-$STAMP"')
    # Профиль, выбранный CLEANER_HOST, подсказка называет: без неё перевыпуск искал бы профиль по hostname.
    assert 'REISSUE_HINT="sudo ${CLEANER_HOST:+CLEANER_HOST=$HOST_NAME }CLEANER_REISSUE_CERT=1 bash ' in text
    docs = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    section = docs[docs.index("## Смена адреса или имени"):docs.index("## Проверки локального периметра")]
    assert "sudo CLEANER_REISSUE_CERT=1 bash" in section and "sudoedit /etc/cleaner/cleaner.toml" in section
    assert "только предупреждение" in section


def test_server_dependencies_take_torch_without_cuda():
    """Сборка torch с PyPI тянет на Linux пакеты NVIDIA; видеокарта сервера занята языковой моделью."""
    text = (ROOT / "requirements-linux.txt").read_text(encoding="utf-8")
    assert "--extra-index-url https://download.pytorch.org/whl/cpu" in text.splitlines()
    pins = _pins(ROOT / "requirements-linux.txt")
    assert pins["torch"].endswith("+cpu")
    assert not [name for name in pins if name.startswith(("nvidia-", "cuda-")) or name == "triton"]


def test_installer_stops_the_service_before_it_replaces_the_code_and_rollback_starts_it_again():
    """Ревью 26.10.2026: служба, работающая над подменённым каталогом, лениво импортировала бы новые модули вперемешку
    со старыми — до перезапуска шли ещё копия базы и самопроверка."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    for swap in ('mv "$APP/.venv" "$APP/.venv.prev"', 'mv -T -- "$APP/cleaner" "$APP/cleaner.bak-$STAMP"'):
        preceding = text[:text.index(swap)].splitlines()[-3:]
        assert "stop_service" in [line.strip() for line in preceding], swap
    rollback = text[text.index("rollback() {"):text.index("trap 'rollback")]
    assert "$STOPPED -eq 1" in rollback


def test_failed_first_install_leaves_the_next_run_a_first_install():
    """Ревью 12.11.2026: откат первой установки снимал сценарий таблицы, но оставлял код и юнит — следующий прогон
    считался обновлением, и его откат перезапускал по кругу службу без сценария из ExecStartPre."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    assert '[[ -d "$APP/cleaner" || -f "$UNIT" ]] && FIRST_INSTALL=0' in text.splitlines()
    rollback = text[text.index("rollback() {"):text.index("trap 'rollback")]
    first = rollback[rollback.index("if [[ $FIRST_INSTALL -eq 1 ]]; then"):rollback.index("elif [[ $swapped -eq 1")]
    disable = first.index("systemctl disable --now cleaner.service")
    assert disable < first.index('rm -rf "$APP/cleaner"') and disable < first.index('rm -f "$UNIT"')
    assert first.index('rm -f "$UNIT"') < first.index("systemctl daemon-reload")
    # База и ключ остаются: ветка «оба есть» следующего прогона обходится без init.
    assert "$ENVF" not in first and "cleaner.db" not in first


def test_installer_rollback_returns_the_egress_files_with_the_code_and_keeps_the_checked_profile():
    """Находка 12.11.2026: откат возвращал код, окружение и юнит, а новые сценарий таблицы и юниты оставались;
    сломанный новый сценарий не дал бы стартовать и прежней службе. Копия снимается до первой записи этих файлов.
    Ревью 12.11.2026: host.env не возвращается — он сверен с host в cleaner.toml, а прежний разошёлся бы с ним."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    aux = text[text.index("AUX_FILES=("):text.index("AUX_PREV=")]
    for name in ("$CHECK", "cleaner-check-ipv6.py", "$EGRESS", "$EGRESS_UNIT", "$EGRESS_WATCH.service",
                 "$EGRESS_WATCH.timer"):
        assert name in aux, name
    assert "$HOST_ENV" not in aux
    targets = {'"$CHECK"', "/usr/local/sbin/cleaner-check-ipv6.py", '"$EGRESS"', '"$EGRESS_UNIT"',
               '"$EGRESS_WATCH.service"', '"$EGRESS_WATCH.timer"'}
    writes = [line for line in text.splitlines() if line.startswith("install ") and line.split()[-1] in targets]
    assert len(writes) == len(targets)
    assert all(text.index("AUX_PREV=$(mktemp -d)") < text.index(line) for line in writes)
    docs = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    assert "`host.env` остаётся новым" in docs
    rollback = text[text.index("rollback() {"):text.index("trap 'rollback")]
    assert "if restore_aux; then" in rollback
    assert rollback.index("restore_aux") < rollback.index("systemctl daemon-reload") < rollback.index(
        "systemctl restart cleaner-egress.service")


def test_ufw_rules_of_a_single_host_client_are_found_without_its_slash_32():
    """Наблюдение 12.11.2026: ufw пишет адрес узла без /32, и клиент `x.x.x.x/32` из CLIENTS не находился — установщик
    на каждом прогоне взводил страховку и добавлял правило заново, check-cleaner.sh проваливался. Правила ALLOW OUT
    в счёт открытых портов не входят."""
    installer = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    check = (DEPLOY / "check-cleaner.sh").read_text(encoding="utf-8")
    for text in (installer, check):
        assert "shown=${net%/32}" in text and "${shown//./\\\\.}" in text
    assert 'grep -vE " ALLOW (OUT|FWD) "' in check


def test_installer_names_ufw_rules_of_nets_no_longer_in_the_profile():
    """Находка 12.11.2026: правила для сетей, убранных из CLIENTS, оставались молча — установщик их называет."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    stale = text[text.index('[[ "${net%/32}" == "${client%/32}" ]] && continue 2'):text.index("отпечаток сертификата")]
    assert "sudo ufw delete <номер>" in stale and '<<< "$RULES"' in stale
    # Ревью 12.11.2026: сеть бралась третьим полем — «IN», «OUT» вместо адреса; правила без /tcp и (v6) пропускались,
    # а одиночный адрес, который ufw пишет без /32, считался чужим.
    assert '$1 == port || $1 == port "/tcp"' in stale
    assert '$(i + 1) == "OUT"' in stale and '$(i + 1) == "IN"' in stale and '" (v6)"' in stale


def test_installer_stops_a_service_waiting_for_its_automatic_restart():
    """Находка 12.11.2026: служба, падающая по кругу, между попытками в activating (auto-restart), и `is-active`
    её не останавливал — отложенный запуск новой версии мог поднять схему базы раньше копии."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    stop = text[text.index("stop_service() {"):text.index("schema_version() {")]
    assert "is-active --quiet" not in stop
    assert '"$state" != "inactive" && "$state" != "failed"' in stop
    assert "STOPPED=1" in stop and "systemctl stop cleaner.service" in stop
    # Ревью 12.11.2026: ловушка ERR функциями без set -E не наследуется — сбой stop выходил без отката.
    assert 'systemctl stop cleaner.service || rollback "' in stop


def test_installer_issues_a_certificate_claude_code_trusts():
    """Приёмка 5Б, 28.10.2026: Claude Code (Bun, BoringSSL) берёт самоподписанный сертификат из NODE_EXTRA_CA_CERTS, только
    если в keyUsage есть keyCertSign; Node и curl принимают и без него. Выпущенный раньше сертификат меняется только по
    явному CLEANER_REISSUE_CERT=1 — прежний остаётся рядом."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    command = text[text.index("openssl req -x509"):text.index('fail "сертификат не выпущен')]
    assert '-addext "keyUsage=digitalSignature,keyEncipherment,keyCertSign"' in command
    reissue = text[text.index("CLEANER_REISSUE_CERT"):text.index("openssl req -x509")]
    assert 'mv "$TLS/cert.pem" "$TLS/cert.pem.prev-$STAMP"' in reissue and 'mv "$TLS/key.pem" "$TLS/key.pem.prev-$STAMP"' in reissue


def test_installer_returns_the_previous_certificate_when_the_reissue_fails():
    """Ревью 12.11.2026: CLEANER_REISSUE_CERT=1 переименовывал cert.pem и key.pem, и при сбое openssl служба оставалась
    без сертификата. Прежний возвращается до выхода с ошибкой."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    failed = text[text.index('echo "$out" >&2'):text.index('fail "сертификат не выпущен')]
    assert 'mv -f "$TLS/cert.pem.prev-$STAMP" "$TLS/cert.pem"' in failed
    assert 'mv -f "$TLS/key.pem.prev-$STAMP" "$TLS/key.pem"' in failed


def test_installer_issues_a_certificate_codex_trusts():
    """Проверка 18.4 плана 5В: Codex (rustls, webpki) не принимает сертификатом сервера сертификат УЦ — а `openssl req
    -x509` без basicConstraints ставит CA:TRUE. Самоподписанный с CA:FALSE, keyCertSign и serverAuth принимают Codex,
    Claude Code и OpenCode."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    command = text[text.index("openssl req -x509"):text.index('fail "сертификат не выпущен')]
    assert '-addext "basicConstraints=critical,CA:FALSE"' in command and '-addext "extendedKeyUsage=serverAuth"' in command


def test_installer_copies_the_database_before_the_new_version_and_rollback_restores_it():
    """Обзор плана 2+4, I-4: новая версия мигрирует схему при старте, а прежний код базу новой версии не откроет.
    Копия снимается до перезапуска службы, откат возвращает её, если схема успела измениться."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    rollback = text[text.index("rollback() {"):text.index("trap 'rollback")]
    assert 'install -o cleaner -g cleaner -m 0600 "$DB_BACKUP" "$DATA/cleaner.db"' in rollback
    assert text.index('DB_BACKUP="$DATA/cleaner.db.bak-$STAMP"') < text.index("systemctl restart cleaner.service\ncode=")


def test_check_compares_the_code_on_disk_with_the_code_the_service_started_with():
    """Идея «Видимый отпечаток установленного кода»: verify печатает отпечаток первой строкой, служба — при старте;
    шаблоны sed проверки совпадают с тем, что печатает код, а установщик сохраняет время файлов (дату отпечатка)."""
    import re as regex_module

    from cleaner import version

    text = (DEPLOY / "check-cleaner.sh").read_text(encoding="utf-8")
    build = version.current()
    verify_line = build.line()
    start_line = f"Cleaner: служба запущена. {build.line()}"
    for pattern, line in (
        (r"s/^Код: \([0-9a-f]\{12\}\) от \([0-9-]*\) .*/\1 от \2/p", verify_line),
        (r"s/^Cleaner: служба запущена\. Код: \([0-9a-f]\{12\}\) от \([0-9-]*\) .*/\1 от \2/p", start_line),
    ):
        assert pattern in text
        sed_regex = pattern[2:pattern.index("/", 2)].replace(r"\(", "(").replace(r"\)", ")").replace(r"\{12\}", "{12}")
        assert regex_module.match(sed_regex, line), line
    assert "cp -r --preserve=timestamps \"$SRC/cleaner\"" in (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")


def test_check_looks_for_the_gateway_key_in_the_running_service_not_only_in_the_file():
    """Находка 12.11.2026: systemd читает cleaner.env только при старте, а ключ шлюза дописывают в уже работающую
    службу. Проверка смотрит окружение процесса, не печатая значения; установщик и инструкция велят перезапустить."""
    text = (DEPLOY / "check-cleaner.sh").read_text(encoding="utf-8")
    section = text[text.index('echo "8. '):text.index("models verify")]
    # Ревью 12.11.2026: «tr … | grep -q» под pipefail ложно проваливался на окружении больше 64 КБ (SIGPIPE у tr).
    assert 'grep -qz \'^CLEANER_GATEWAY_KEY=.\' "/proc/$pid/environ"' in section
    assert "| grep" not in section[section.index("/proc/$pid/environ"):section.index("перезапустите службу")]
    assert "перезапустите службу" in section
    assert not re.search(r"echo[^\n]*environ|cat [^\n]*environ", section)
    hint = next(line for line in (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8").splitlines()
                if "Ключа шлюза нет" in line)
    assert "systemctl restart cleaner.service" in hint
    steps = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    assert "systemctl restart cleaner.service" in steps[steps.index("4. Передайте"):steps.index("5. ")]


def test_deployment_commands_expand_masks_of_the_closed_data_directory_as_root():
    """Находка 12.11.2026: каталог данных закрыт (0700), и маску `sudo chown … cleaner.db*` раскрывала оболочка
    оператора без root — chown получал строку как есть. Маски под /var/lib/cleaner — только внутри `sudo bash -c`."""
    text = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    block = text[text.index("## Смена главного ключа"):]
    block = block[block.index("```bash"):block.index("```", block.index("```bash") + 3)]
    for line in block.splitlines():
        if "/var/lib/cleaner/" in line and "*" in line:
            assert line.startswith("sudo bash -c '"), line


def test_installer_removes_database_copies_once_the_service_answers():
    """Аудит 09.11.2026: копия базы хранит удалённые чаты вместе с обёрнутыми ключами, а главный ключ тот же (FR-1.4,
    AC-1.10). Копия нужна только откату этого прогона: после ответа службы она и копии прежних прогонов стираются."""
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    answered = text.index('[[ "$code" == "200" ]] || rollback')
    removal = text.index('shred -u -- "$DATA"/cleaner.db.bak-*')
    assert answered < removal < text.index('log "служба отвечает:')
    # Копий прежних прогонов больше не накапливается: нет «трёх последних» у базы.
    copy = text[text.index("# --- копия базы"):text.index("# --- самопроверка")]
    assert "cleaner.db.bak-*" not in copy


def _run_bash(script, tmp_path, **environment):
    bash = Path("C:/Program Files/Git/bin/bash.exe") if sys.platform == "win32" else shutil.which("bash")
    if not bash or not Path(bash).is_file():
        pytest.skip("Bash недоступен")
    with TemporaryFile(dir=tmp_path) as stdout, TemporaryFile(dir=tmp_path) as stderr:
        result = subprocess.run(
            [str(bash), "-c", script], cwd=tmp_path, stdout=stdout, stderr=stderr, timeout=15,
            env={**os.environ, **environment, "PYTHON_EXEC": Path(sys.executable).as_posix(), "PYTHONUTF8": "1",
                 "TEST_DIR": tmp_path.as_posix()},
        )
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(
            result.args, result.returncode, stdout.read().decode("utf-8"), stderr.read().decode("utf-8"),
        )


@pytest.mark.integration
def test_failed_first_code_rename_keeps_installed_code(tmp_path):
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    rollback = text[text.index("rollback() {"):text.index("trap 'rollback")]
    code_swap = text[text.index("# --- код: каталог"):text.index("# --- юнит и проверка")]
    app = tmp_path / "app"
    (app / "cleaner").mkdir(parents=True)
    (app / "cleaner" / "working.py").write_text("working", encoding="utf-8")
    (app / "cleaner.new").mkdir()
    result = _run_bash(
        r'''
set -euo pipefail
APP="$TEST_DIR/app"
PREV_CODE="" PREV_VENV="" PREV_UNIT="" DB_BACKUP="" STOPPED=0 FIRST_INSTALL=0
STAMP=test
log() { :; }
restore_aux() { return 1; }
stop_service() { STOPPED=1; }
mv() { return 1; }
systemctl() { printf '%s\n' "$*"; }
journalctl() { :; }
''' + rollback + "trap 'rollback failed' ERR\n" + code_swap,
        tmp_path,
    )
    assert result.returncode == 1, result.stderr
    assert "restart cleaner.service" in result.stdout
    assert (app / "cleaner" / "working.py").read_text(encoding="utf-8") == "working"
    assert not (app / "cleaner.new").exists()


@pytest.mark.integration
@pytest.mark.parametrize(("clients", "internal", "valid"), [
    ("192.0.2.0/24", "192.0.2.0/25 192.0.2.128/25", True),
    ("192.0.2.0/24", "192.0.2.0/25", False),
    ("192.0.2.7/24", "192.0.2.0/24", False),
    ("192.0.2.7", "192.0.2.0/24 nonsense", False),
])
def test_installer_validates_networks_of_the_selected_profile(tmp_path, clients, internal, valid):
    text = (DEPLOY / "install-cleaner.sh").read_text(encoding="utf-8")
    preflight = text[text.index("HOST_NAME=${"):text.index('log "профиль хоста:')]
    profiles = tmp_path / "deploy" / "hosts"
    profiles.mkdir(parents=True)
    (profiles / "selected.conf").write_text(
        f'HOST_IP=127.0.0.1\nCLIENTS="{clients}"\nINTERNAL="{internal}"\n'
        'GATEWAY=127.0.0.1:30000\nCERT_NAME=example\n', encoding="utf-8",
    )
    result = _run_bash(
        'set -eu\nSRC="$TEST_DIR"\nfail() { printf "%s\\n" "$1" >&2; exit 1; }\n'
        'python3.12() { "$PYTHON_EXEC" "$@"; }\n' + preflight,
        tmp_path, CLEANER_HOST="selected",
    )
    assert result.returncode == (0 if valid else 1), result.stderr
    if not valid:
        assert "selected.conf" in result.stderr


@pytest.mark.integration
@pytest.mark.parametrize("extras", ["", "CLEANER_GATEWAY_KEY=synthetic\n", None])
def test_documented_key_rotation_preserves_optional_environment(tmp_path, extras):
    text = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
    start = text.index("set -e; cd /etc/cleaner")
    end = text.index("' &&", start)
    command = text[start:end].replace("cd /etc/cleaner", 'cd "$TEST_DIR"')
    current, new = tmp_path / "cleaner.env", tmp_path / "cleaner.env.new"
    if extras is not None:
        current.write_text(f"CLEANER_MASTER_KEY=old\n{extras}", encoding="utf-8")
    new.write_text("CLEANER_MASTER_KEY=new\n", encoding="utf-8")
    result = _run_bash(command, tmp_path)
    if extras is None:
        assert result.returncode != 0 and not current.exists()
        assert new.read_text(encoding="utf-8") == "CLEANER_MASTER_KEY=new\n"
    else:
        assert result.returncode == 0, result.stderr
        assert current.read_text(encoding="utf-8") == f"CLEANER_MASTER_KEY=new\n{extras}"
        assert not new.exists()
    assert not list(tmp_path.glob(".cleaner.env.*"))


@pytest.mark.integration
@pytest.mark.parametrize(("scenario", "status"), [("old", 2), ("empty", 2), ("unreadable", 2), ("different", 1), ("same", 0)])
def test_version_check_uses_only_the_current_invocation(tmp_path, scenario, status):
    text = (DEPLOY / "check-cleaner.sh").read_text(encoding="utf-8")
    section = text[text.index("installed=$(sed"):text.index('echo "7.')]
    (tmp_path / "verify.txt").write_text("Код: aaaaaaaaaaaa от 2026-11-18 test\n", encoding="utf-8")
    result = _run_bash(
        r'''
set -uo pipefail
WORK="$TEST_DIR" UNIT=cleaner.service RET=0
ok() { RET=0; }
bad() { RET=1; }
miss() { RET=2; }
skip() { :; }
systemctl() { printf '%s\n' 11111111111111111111111111111111; }
journalctl() {
    if [[ "$*" != *"_SYSTEMD_INVOCATION_ID=11111111111111111111111111111111"* ]]; then
        printf '%s\n' 'Cleaner: служба запущена. Код: aaaaaaaaaaaa от 2026-11-18 test'
        return
    fi
    case "$SCENARIO" in
        old|empty) : ;;
        unreadable) return 1 ;;
        different) printf '%s\n' 'Cleaner: служба запущена. Код: bbbbbbbbbbbb от 2026-11-18 test' ;;
        same) printf '%s\n' 'Cleaner: служба запущена. Код: aaaaaaaaaaaa от 2026-11-18 test' ;;
    esac
}
''' + section + 'exit "$RET"',
        tmp_path, SCENARIO=scenario,
    )
    assert result.returncode == status, result.stderr


@pytest.mark.integration
@pytest.mark.parametrize(("database", "journal", "status"), [
    ("missing", "clean", 2), ("unreadable", "clean", 2), ("clean", "unreadable", 2),
    ("utf-8", "unreadable", 1), ("utf-16-le", "clean", 1), ("clean", "hit", 1), ("clean", "clean", 0),
])
def test_canary_check_distinguishes_a_hit_from_unreadable_sources(tmp_path, database, journal, status):
    text = (DEPLOY / "check-cleaner.sh").read_text(encoding="utf-8")
    section = text[text.index('echo "7.'):text.index('echo "8.')]
    db = tmp_path / "cleaner.db"
    canary = "Синтетическая-канарейка"
    if database == "unreadable":
        db.mkdir()
    elif database != "missing":
        db.write_bytes(b"safe")
        if database != "clean":
            (tmp_path / "cleaner.db-wal").write_bytes(b"x" * (1024 * 1024 - 2) + canary.encode(database))
    result = _run_bash(
        r'''
set -uo pipefail
WORK="$TEST_DIR" DATA="$TEST_DIR" UNIT=cleaner.service BAD=0 INCOMPLETE=0
ok() { :; }
bad() { BAD=1; }
miss() { INCOMPLETE=2; }
python3() { "$PYTHON_EXEC" "$@"; }
journalctl() {
    case "$JOURNAL" in
        unreadable) return 1 ;;
        hit) printf '%s\n' "$CANARY" ;;
        *) printf '%s\n' safe ;;
    esac
}
''' + section + 'exit "$((BAD ? BAD : INCOMPLETE))"',
        tmp_path, CANARY=canary, JOURNAL=journal,
    )
    assert result.returncode == status, result.stderr
