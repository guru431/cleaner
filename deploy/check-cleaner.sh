#!/usr/bin/env bash
# Проверка Cleaner фактом на живом сервере (значения ниже — example; на другом хосте их переопределяет
# профиль /etc/cleaner/host.env, который кладёт установщик): служба, права файлов, вход по HTTPS, экран,
# исходящие службы (с этапа 3 — только TCP 443), самопроверка. Образец — check-egress.sh и
# check-rerank.sh репозитория vLLM: проверяется то, что происходит, а не то, что написано.
#
#   sudo bash /usr/local/sbin/check-cleaner.sh [канарейка]
#
# Канарейка — строка, которую перед прогоном вставили в чат через интерфейс: её не должно
# быть ни в файлах базы (UTF-8 и UTF-16), ни в журнале службы (AC-1.8 на сервере).
# Код возврата: 0 — всё в порядке; 1 — провал; 2 — прогон неполный: проба не состоялась.
set -uo pipefail

UNIT=cleaner.service
HOST_IP=example
PORT=5464
CLIENTS=example/19
APP=/opt/cleaner
DATA=/var/lib/cleaner
ETC=/etc/cleaner
CERT=$ETC/tls/cert.pem
GATEWAY="127.0.0.1:30000"
SERVER_GUARD=1
HOST_ENV=$ETC/host.env
# shellcheck source=/dev/null
if [[ -f "$HOST_ENV" ]]; then . "$HOST_ENV"; fi
EXTERNAL="${CLEANER_PROBE_HOST:-1.1.1.1}"
EXTERNAL6="${CLEANER_PROBE_HOST6:-2606:4700:4700::1111}"
PROBE_NAME="${CLEANER_PROBE_NAME:-api.deepseek.com}"
CANARY="${1:-}"

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
fails=0
incomplete=0
ok()   { printf '  %sок%s   %s\n' "$GREEN" "$NC" "$1"; }
bad()  { printf '  %sПРОВАЛ%s %s\n' "$RED" "$NC" "$1"; fails=$((fails + 1)); }
skip() { printf '  --   %s\n' "$1"; }
miss() { printf '  %s??%s   %s\n' "$YELLOW" "$NC" "$1"; incomplete=$((incomplete + 1)); }

[[ $(id -u) -eq 0 ]] || { echo "нужны права root" >&2; exit 2; }
WORK=$(mktemp -d)
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

expect_mode() {  # $1 — путь, $2 — ожидаемое «права владелец:группа»
    local actual
    actual=$(stat -c '%a %U:%G' "$1" 2>/dev/null)
    if [[ "$actual" == "$2" ]]; then
        ok "$1: $2"
    else
        bad "$1: ${actual:-нет файла}, а должно быть $2"
    fi
}

echo "1. Служба"
if [[ "$(systemctl is-active "$UNIT")" == "active" ]]; then ok "$UNIT работает"; else bad "$UNIT не работает"; fi
if [[ "$(systemctl is-enabled "$UNIT" 2>/dev/null)" == "enabled" ]]; then
    ok "автозапуск включён"
else
    bad "автозапуск выключен"
fi
pid=$(systemctl show "$UNIT" -p MainPID --value)
uid=$(ps -o uid= -p "$pid" 2>/dev/null | tr -d ' ')
if [[ -n "$uid" && "$uid" == "$(id -u cleaner)" ]]; then
    ok "процесс $pid работает от учётной записи cleaner"
else
    bad "процесс ${pid:-?} работает от uid ${uid:-?}, а не от cleaner"
fi

echo "2. Файлы"
expect_mode "$ETC/cleaner.env" "600 root:root"
expect_mode "$ETC/tls/key.pem" "640 root:cleaner"
expect_mode "$DATA" "700 cleaner:cleaner"
expect_mode "$DATA/cleaner.db" "600 cleaner:cleaner"
if runuser -u cleaner -- test -r "$ETC/cleaner.env"; then
    bad "учётная запись cleaner читает файл с главным ключом"
else
    ok "файл с главным ключом службе не читается (SEC-5)"
fi

echo "3. Вход по HTTPS"
listeners=$(ss -Htln "sport = :$PORT" | awk '{print $4}' | sort -u | tr '\n' ' ')
if [[ "$listeners" == "${HOST_IP}:${PORT} " ]]; then
    ok "слушает только ${HOST_IP}:${PORT}"
else
    bad "слушает: ${listeners:-ничего}"
fi
headers=$(curl -s -D - -o /dev/null -m 5 --cacert "$CERT" "https://${HOST_IP}:${PORT}/login" || true)
if [[ "$headers" == "HTTP/"*" 200"* ]]; then
    ok "страница входа отвечает 200, сертификат совпадает с $CERT"
else
    bad "страница входа не открылась по HTTPS: ${headers%%$'\r'*}"
fi
if grep -qi "^content-security-policy: default-src 'self'" <<< "$headers"; then ok "заголовок CSP на месте"; else bad "нет заголовка CSP"; fi
if grep -qi '^strict-transport-security: max-age=' <<< "$headers"; then ok "заголовок HSTS на месте"; else bad "нет заголовка HSTS"; fi
plain=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://${HOST_IP}:${PORT}/login" || true)
if [[ "$plain" != "200" ]]; then ok "без TLS не отвечает (код ${plain})"; else bad "отвечает по открытому HTTP"; fi
fingerprint=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)

echo "4. Экран"
rules=$(ufw status 2>/dev/null || true)
port_rules=$(grep -E "^${PORT}/tcp" <<< "$rules" || true)
want=0
have=0
for net in $CLIENTS; do
    want=$((want + 1))
    if grep -qE "ALLOW +${net//./\\.}( |$)" <<< "$port_rules"; then have=$((have + 1)); fi
done
if [[ "$(grep -c . <<< "$port_rules")" == "$want" && "$have" == "$want" ]]; then
    ok "порт ${PORT} открыт только для ${CLIENTS}"
else
    bad "правила ufw для ${PORT}: ${port_rules:-нет}"
fi
if [[ "$(systemctl is-active ufw-failsafe.timer 2>/dev/null)" == "active" ]]; then
    bad "страховка ufw-failsafe ещё взведена: проверьте новое SSH-подключение и снимите её"
else
    ok "страховка ufw-failsafe не взведена"
fi

echo "5. Исходящие службы (этап 3: наружу только TCP 443)"
procs="/sys/fs/cgroup/system.slice/${UNIT}/cgroup.procs"
# Проба — от учётной записи cleaner внутри контрольной группы службы: таблица cleaner_egress выбирает
# пакеты по учётной записи, и проба от root прошла бы мимо неё. setpriv, а не runuser: без PAM процесс
# остаётся в группе службы.
probe() {  # $1 — адрес, $2 — порт. Код: 0 — соединение есть, 97 — не вошли в группу, иное — отказ
    bash -c "echo \$\$ > '$procs' || exit 97; exec setpriv --reuid=cleaner --regid=cleaner --init-groups \
        timeout 4 bash -c '</dev/tcp/$1/$2'" >/dev/null 2>&1
}
if [[ "$(systemctl is-active cleaner-egress.service)" == "active" ]]; then
    ok "cleaner-egress.service ставит границы выхода"
else
    bad "cleaner-egress.service не активен"
fi
if bash /usr/local/sbin/cleaner-egress.sh check >"$WORK/egress-table.txt" 2>&1; then
    ok "таблица nftables inet cleaner_egress на месте: отбор по учётной записи и отказ"
else
    bad "$(cat "$WORK/egress-table.txt") — выход наружу не ограничен"
fi
table=$(nft list table inet cleaner_egress 2>/dev/null || true)
if grep -q "ip6 daddr ::1 return" <<< "$table" && ! grep -q "nfproto ipv6" <<< "$table"; then
    ok "IPv6 наружу отклоняется (пропускается только петля)"
else
    bad "в таблице cleaner_egress нет правила IPv6 только для петли"
fi
nets() { sed -n "s/^${2}=\"\(\${[A-Z_]*:-\)\{0,1\}\([^}\"]*\)}\{0,1\}\"$/\2/p" "$1" | tr ' ' '\n' | sort | tr '\n' ' '; }
if [[ -n "${INTERNAL:-}" ]]; then
    ours=$(tr ' ' '\n' <<< "$INTERNAL" | sort | tr '\n' ' ')      # из профиля хоста
else
    ours=$(nets /usr/local/sbin/cleaner-egress.sh INTERNAL)
fi
guard=$(nets /usr/local/sbin/ai-egress-guard.sh INTERNAL)
if [[ "$SERVER_GUARD" != "1" ]]; then
    skip "ai-egress-guard.sh на этом хосте нет — внутренние сети заданы профилем: ${ours}"
elif [[ -z "$guard" ]]; then
    miss "нет /usr/local/sbin/ai-egress-guard.sh — список внутренних сетей не сверен"
elif [[ "$ours" == "$guard" ]]; then
    ok "внутренние сети совпадают с ai-egress-guard.sh"
else
    bad "внутренние сети расходятся с ai-egress-guard.sh: ${ours}≠ ${guard}"
fi
if [[ ! -w "$procs" ]]; then
    miss "контрольная группа $UNIT недоступна — пробы не выполнены"
else
    since=$(date +%s)
    # Положительный контроль: свой же порт. Без него «не соединилось» ничего не доказывает.
    probe "$HOST_IP" "$PORT"
    case $? in
        0) ok "свой порт ${HOST_IP}:${PORT} изнутри группы доступен — проба работает" ;;
        97) miss "войти в контрольную группу не удалось (служба перезапустилась?)" ;;
        *) bad "свой порт изнутри группы недоступен — проба ничего не доказывает" ;;
    esac
    probe "${GATEWAY%:*}" "${GATEWAY#*:}"
    case $? in
        0) ok "шлюз сервера ${GATEWAY} достижим" ;;
        97) miss "войти в контрольную группу не удалось" ;;
        *) bad "шлюз сервера ${GATEWAY} недостижим" ;;
    esac
    probe "$EXTERNAL" 443
    case $? in
        0) ok "${EXTERNAL}:443 доступен — выход к провайдерам открыт" ;;
        97) miss "войти в контрольную группу не удалось" ;;
        *) bad "${EXTERNAL}:443 недоступен — облачные подключения работать не будут" ;;
    esac
    probe "$EXTERNAL" 80
    case $? in
        0) bad "${EXTERNAL}:80 доступен — выход наружу шире порта 443" ;;
        97) miss "войти в контрольную группу не удалось" ;;
        *) ok "${EXTERNAL}:80 отклонён" ;;
    esac
    probe "$EXTERNAL6" 443
    case $? in
        0) bad "[${EXTERNAL6}]:443 доступен — IPv6 наружу открыт" ;;
        97) miss "войти в контрольную группу не удалось" ;;
        *) ok "[${EXTERNAL6}]:443 по IPv6 недоступен" ;;
    esac
    if bash -c "echo \$\$ > '$procs' || exit 97; exec setpriv --reuid=cleaner --regid=cleaner --init-groups \
        timeout 5 getent hosts $PROBE_NAME" >/dev/null 2>&1; then
        ok "имена разрешаются от учётной записи cleaner (DNS по петле)"
    else
        bad "имя $PROBE_NAME от учётной записи cleaner не разрешается — подключения по имени не сработают"
    fi
    # Записи ограничены по частоте (30 и 6 в минуту): если служба только что исчерпала предел, повторить пробу.
    for attempt in 1 2; do
        sleep 1
        kernel=$(journalctl -k --since "@$since" --no-pager 2>/dev/null || true)
        if grep -q "cleaner-egress: .*DST=${EXTERNAL} .*DPT=80 " <<< "$kernel" \
            && grep -q "cleaner-out: .*DST=${EXTERNAL} .*DPT=443 " <<< "$kernel"; then
            break
        fi
        if [[ $attempt == 1 ]]; then
            sleep 10
            since=$(date +%s)
            probe "$EXTERNAL" 80
            probe "$EXTERNAL" 443
        fi
    done
    if grep -q "cleaner-egress: .*DST=${EXTERNAL} .*DPT=80 " <<< "$kernel"; then
        ok "отказ на порт 80 записан в журнал ядра"
    else
        bad "отказа на порт 80 нет в журнале ядра (cleaner-egress:)"
    fi
    if grep -q "cleaner-out: .*DST=${EXTERNAL} .*DPT=443 " <<< "$kernel"; then
        ok "соединение на 443 записано в журнал ядра — проба шла через таблицу"
    else
        bad "соединения на 443 нет в журнале ядра (cleaner-out:) — проба прошла мимо таблицы"
    fi
fi
input_rule=$(nft list chain inet cleaner_egress input 2>/dev/null | grep "tcp dport ${PORT} ip saddr != {" | grep " drop" || true)
absent=""
for net in $CLIENTS 127.0.0.0/8; do
    grep -qF "$net" <<< "$input_rule" || absent="$absent $net"
done
if [[ -n "$input_rule" && -z "$absent" ]]; then
    ok "входящие на ${PORT} в таблице cleaner_egress — только из ${CLIENTS} и петли"
else
    bad "в таблице cleaner_egress нет входного фильтра порта ${PORT}${absent:+ (нет сетей:$absent)}"
fi
if [[ "$SERVER_GUARD" != "1" ]]; then
    skip "check-egress.sh сервера vLLM на этом хосте нет"
elif [[ -x /usr/local/sbin/check-egress.sh ]]; then
    bash /usr/local/sbin/check-egress.sh >"$WORK/egress.txt" 2>&1
    case $? in
        0) ok "check-egress.sh сервера: всё закрыто" ;;
        2) miss "check-egress.sh сервера: прогон неполный" ;;
        *) bad "check-egress.sh сервера: есть провалы"; grep "ПРОВАЛ" "$WORK/egress.txt" || true ;;
    esac
else
    miss "нет /usr/local/sbin/check-egress.sh"
fi

echo "6. Самопроверка (AC-1.9)"
if (cd "$APP" && runuser -u cleaner -- "$APP/.venv/bin/python" -m cleaner verify) >"$WORK/verify.txt" 2>&1; then
    ok "$(tail -n 1 "$WORK/verify.txt")"
else
    bad "самопроверка: $(tail -n 1 "$WORK/verify.txt")"
fi

echo "7. Канарейка в базе и журнале (AC-1.8)"
if [[ -z "$CANARY" ]]; then
    skip "канарейка не задана: sudo bash $0 <строка, вставленная в чат>"
else
    if python3 - "$CANARY" "$DATA" <<'PY'
import sys
from pathlib import Path

canary, data = sys.argv[1], Path(sys.argv[2])
raw = b"".join(path.read_bytes() for path in data.glob("cleaner.db*"))
sys.exit(1 if canary.encode("utf-8") in raw or canary.encode("utf-16-le") in raw else 0)
PY
    then
        ok "канарейки нет в файлах базы"
    else
        bad "канарейка найдена в файлах базы"
    fi
    journal=$(journalctl -u "$UNIT" --no-pager 2>/dev/null || true)
    if grep -qF -- "$CANARY" <<< "$journal"; then bad "канарейка в журнале службы"; else ok "канарейки нет в журнале службы"; fi
fi

echo "8. Этапы 2 и 4: ключ шлюза и модели"
# Значение ключа не выводится: проверяется только, что строка есть и не пустая.
if grep -q '^CLEANER_GATEWAY_KEY=..*' "$ETC/cleaner.env"; then
    ok "ключ шлюза задан"
else
    bad "в $ETC/cleaner.env нет CLEANER_GATEWAY_KEY"
fi
if (cd "$APP" && runuser -u cleaner -- env HOME="$DATA" "$APP/.venv/bin/python" -m cleaner --config "$ETC/cleaner.toml" models verify) >"$WORK/models.txt" 2>&1; then
    ok "модели совпадают с манифестом"
else
    bad "models verify: $(tr '\n' ' ' < "$WORK/models.txt")"
fi

echo
echo "Отпечаток сертификата (SHA-256): ${fingerprint:-не прочитан}"
if [[ $fails -gt 0 ]]; then
    printf '%sПровалов: %d%s\n' "$RED" "$fails" "$NC"
    exit 1
fi
if [[ $incomplete -gt 0 ]]; then
    printf '%sПрогон неполный: не состоялось проб — %d%s\n' "$YELLOW" "$incomplete" "$NC"
    exit 2
fi
printf '%sВсё в порядке%s\n' "$GREEN" "$NC"
exit 0
