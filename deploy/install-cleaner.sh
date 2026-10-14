#!/usr/bin/env bash
# Установка и обновление Cleaner на example. Идемпотентен: повторный прогон обновляет код,
# зависимости и юнит, а главный ключ, базу, настройки, сертификат и правило ufw не трогает.
#
#   sudo bash install-cleaner.sh <каталог доставки> [логин первого администратора]
#
# Каталог доставки — распакованный `git archive` репозитория Cleaner в каталоге под root
# (`/root/stage-cleaner` с правами 0700 или `sudo mktemp -d`). git отдаёт файлы с LF по .gitattributes,
# поэтому CRLF, как установщикам vLLM, снимать не нужно. Логин нужен только при первой
# установке: тогда создаются база и главный ключ, а пароль администратора спрашивается
# с клавиатуры (ssh -t).
#
# Откат: если после выкатки самопроверка не прошла или служба не ответила по HTTPS,
# возвращаются прежние код, окружение и юнит. Правило ufw ставится под отложенным откатом
# ufw-failsafe; снять страховку — после проверки НОВЫМ SSH-подключением.
set -euo pipefail

SRC=${1:?укажите каталог доставки}
ADMIN=${2:-}
APP=/opt/cleaner
DATA=/var/lib/cleaner
ETC=/etc/cleaner
ENVF=$ETC/cleaner.env
CONF=$ETC/cleaner.toml
TLS=$ETC/tls
UNIT=/etc/systemd/system/cleaner.service
CHECK=/usr/local/sbin/check-cleaner.sh
HOST_IP=example
PORT=5464
CLIENTS=example/19
STAMP=$(date +%Y%m%d-%H%M%S)

log() { echo "[cleaner] $*"; }
fail() { echo "[cleaner] ОШИБКА: $*" >&2; exit 1; }

# --- Сторож каталога доставки: копия dashboard/deploy/stage-guard.sh из vLLM ---
# Каталог доставки обязан принадлежать root и не быть открытым на запись группе
# и остальным: иначе непривилегированный сосед подменит файл, который поставится от root.
require_safe_src() {
    local dir=$1 owner perms
    if [[ ! -d "$dir" ]]; then
        echo "[guard] нет каталога доставки: $dir" >&2
        exit 2
    fi
    owner=$(stat -c '%u' "$dir")
    perms=$(stat -c '%a' "$dir")
    if [[ "$owner" != "0" ]]; then
        echo "[guard] каталог доставки $dir принадлежит uid $owner, а не root." >&2
        echo "[guard] Доставляйте в каталог под root: mktemp -d или /root/stage-<шаг>." >&2
        exit 2
    fi
    if (( 0${perms} & 0022 )); then
        echo "[guard] каталог доставки $dir открыт на запись не только root ($perms)." >&2
        echo "[guard] Поправьте: chmod go-w $dir" >&2
        exit 2
    fi
}

[[ $(id -u) -eq 0 ]] || fail "нужны права root"
require_safe_src "$SRC"
[[ -d "$SRC/cleaner" && -f "$SRC/requirements-linux.txt" ]] || fail "$SRC — не дерево репозитория Cleaner"
command -v python3.12 >/dev/null || fail "нет python3.12"
# Первая установка или обновление — решается до любых изменений: откат обновления не должен
# останавливать работающую службу, если до замены файлов дело не дошло.
FIRST_INSTALL=1
[[ -d "$APP/cleaner" || -f "$UNIT" ]] && FIRST_INSTALL=0

# --- учётная запись и каталоги --------------------------------------------------
# Своя учётная запись, не aiservice: цепочка наблюдения сервера пишет исходящие
# попытки aiservice как происшествия. /opt/cleaner, а не /opt/ai: туда cleaner не войдёт.
id -u cleaner >/dev/null 2>&1 || useradd --system --no-create-home --home-dir "$DATA" --shell /usr/sbin/nologin cleaner
install -d -o root -g cleaner -m 0750 "$APP" "$ETC" "$TLS"
install -d -o cleaner -g cleaner -m 0700 "$DATA"
install -d -o cleaner -g cleaner -m 0750 "$APP/models"     # модели слоя 4 и Docling: пишет только models download

# --- настройки: ставятся один раз ------------------------------------------------
if [[ ! -f "$CONF" ]]; then
    install -o root -g cleaner -m 0640 "$SRC/deploy/cleaner.toml" "$CONF"
    log "настройки установлены: $CONF"
else
    log "настройки уже есть — не трогаю: $CONF"
fi

# --- сертификат: собственный, выпускается один раз -------------------------------
# Общий сертификат сервера (/etc/ai-services/tls/dashboard.*) не годится: его ключ
# читает только группа aidash, а в SAN нет example. Отпечаток в документы не
# выписывается — его печатают этот установщик и check-cleaner.sh.
if [[ ! -s "$TLS/cert.pem" || ! -s "$TLS/key.pem" ]]; then
    (
        umask 077
        openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
            -keyout "$TLS/key.pem" -out "$TLS/cert.pem" \
            -subj "/CN=example Cleaner" \
            -addext "subjectAltName=IP:${HOST_IP},DNS:example" \
            -addext "keyUsage=digitalSignature,keyEncipherment" \
            -addext "extendedKeyUsage=serverAuth" 2>/dev/null
    )
    chown root:cleaner "$TLS/key.pem" "$TLS/cert.pem"
    chmod 0640 "$TLS/key.pem"
    chmod 0644 "$TLS/cert.pem"
    log "сертификат выпущен: $TLS/cert.pem"
fi

# --- откат ----------------------------------------------------------------------
PREV_CODE=""
PREV_VENV=""
PREV_UNIT=""
rollback() {
    trap - ERR
    log "ОТКАТ: $1"
    local swapped=0
    if [[ -n "$PREV_CODE" ]]; then rm -rf "$APP/cleaner"; mv "$PREV_CODE" "$APP/cleaner"; swapped=1; fi
    if [[ -n "$PREV_VENV" ]]; then rm -rf "$APP/.venv"; mv "$PREV_VENV" "$APP/.venv"; swapped=1; fi
    if [[ -n "$PREV_UNIT" ]]; then cp -a "$PREV_UNIT" "$UNIT"; swapped=1; fi
    rm -rf "$APP/.venv.new" "$APP/cleaner.new"
    systemctl daemon-reload || true
    if [[ $FIRST_INSTALL -eq 1 ]]; then
        systemctl disable --now cleaner.service >/dev/null 2>&1 || true
        log "первая установка не удалась: служба остановлена, ключ и база не тронуты"
    elif [[ $swapped -eq 1 ]]; then
        systemctl restart cleaner.service || true
        log "прежняя версия возвращена"
    else
        log "обновление не удалось до замены файлов: работающая служба не тронута"
    fi
    journalctl -u cleaner.service -n 30 --no-pager || true
    exit 1
}
trap 'rollback "сбой в строке $LINENO"' ERR

# --- окружение Python: пересобирается, только если изменился файл зависимостей ---
# Пакеты качает установщик от root, а не служба: её юнит закрыт IPAddressDeny=any.
if ! cmp -s "$SRC/requirements-linux.txt" "$APP/.venv/requirements-linux.txt"; then
    rm -rf "$APP/.venv.new"
    python3.12 -m venv "$APP/.venv.new"
    "$APP/.venv.new/bin/pip" install --no-input --quiet --require-hashes --only-binary=:all: \
        -r "$SRC/requirements-linux.txt"
    cp "$SRC/requirements-linux.txt" "$APP/.venv.new/requirements-linux.txt"
    if [[ -d "$APP/.venv" ]]; then
        rm -rf "$APP/.venv.prev"
        mv "$APP/.venv" "$APP/.venv.prev"
        PREV_VENV="$APP/.venv.prev"
    fi
    mv "$APP/.venv.new" "$APP/.venv"
    log "окружение собрано по requirements-linux.txt"
else
    log "зависимости не менялись — окружение прежнее"
fi

# --- код: каталог заменяется целиком, прежний уезжает в копию --------------------
rm -rf "$APP/cleaner.new"
cp -r "$SRC/cleaner" "$APP/cleaner.new"
find "$APP/cleaner.new" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:cleaner "$APP/cleaner.new"
find "$APP/cleaner.new" -type d -exec chmod 0750 {} +
find "$APP/cleaner.new" -type f -exec chmod 0640 {} +
if [[ -d "$APP/cleaner" ]]; then
    PREV_CODE="$APP/cleaner.bak-$STAMP"
    mv "$APP/cleaner" "$PREV_CODE"
fi
mv "$APP/cleaner.new" "$APP/cleaner"
mapfile -t backups < <(ls -1dt "$APP"/cleaner.bak-* 2>/dev/null || true)
for old in "${backups[@]:3}"; do
    rm -rf "$old"                  # хранятся три последние копии
done

# --- юнит и проверка ---------------------------------------------------------------
if [[ -f "$UNIT" ]] && ! cmp -s "$SRC/deploy/cleaner.service" "$UNIT"; then
    PREV_UNIT="$UNIT.bak-$STAMP"
    cp -a "$UNIT" "$PREV_UNIT"
fi
install -o root -g root -m 0644 "$SRC/deploy/cleaner.service" "$UNIT"
install -o root -g root -m 0755 "$SRC/deploy/check-cleaner.sh" "$CHECK"
systemctl daemon-reload

# --- первая установка: база, главный ключ, первый администратор -------------------
if [[ ! -f "$ENVF" && ! -f "$DATA/cleaner.db" ]]; then
    [[ -n "$ADMIN" ]] || rollback "первая установка: укажите логин администратора вторым аргументом"
    ( cd "$APP" && CLEANER_CONFIG="$CONF" "$APP/.venv/bin/python" -m cleaner init --admin "$ADMIN" --env-file "$ENVF" )
    chown cleaner:cleaner "$DATA"/cleaner.db*
    chmod 0600 "$DATA"/cleaner.db*
elif [[ ! -f "$ENVF" || ! -f "$DATA/cleaner.db" ]]; then
    rollback "есть только одно из двух — $ENVF или $DATA/cleaner.db; верните второе (key import или копия базы)"
fi
if ! grep -q '^CLEANER_GATEWAY_KEY=..*' "$ENVF"; then
    log "Ключа шлюза нет: выпустите его (sudo ai-ctl gateway-key create cleaner) и допишите строку CLEANER_GATEWAY_KEY=… в $ENVF через sudoedit"
fi

# --- самопроверка и запуск ------------------------------------------------------------
( cd "$APP" && runuser -u cleaner -- "$APP/.venv/bin/python" -m cleaner verify ) \
    || rollback "самопроверка на подложенных значениях не прошла"
systemctl enable cleaner.service >/dev/null 2>&1
systemctl restart cleaner.service
code=""
for _ in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 --cacert "$TLS/cert.pem" \
        "https://${HOST_IP}:${PORT}/login" || true)
    [[ "$code" == "200" ]] && break
    sleep 2
done
[[ "$code" == "200" ]] || rollback "служба не ответила по HTTPS (код ${code:-нет ответа})"
trap - ERR
log "служба отвечает: https://${HOST_IP}:${PORT}/login"

# --- вход: порт открыт только сети клиентов -------------------------------------------
# Имя страховки постоянное: ai-ctl boot-readiness и панель ищут ровно ufw-failsafe.timer.
# После правки ufw — рестарт ai-egress-guard, как у install-step8-perimeter.sh.
RULES="$(ufw status 2>/dev/null || true)"
if grep -qE "^${PORT}/tcp +ALLOW +${CLIENTS//./\\.}( |$)" <<< "$RULES"; then
    log "правило ufw для ${PORT} уже есть — страховку не взвожу"
else
    systemctl stop ufw-failsafe.timer ufw-failsafe.service >/dev/null 2>&1 || true
    systemctl reset-failed ufw-failsafe.timer ufw-failsafe.service >/dev/null 2>&1 || true
    systemd-run --on-active=10m --unit=ufw-failsafe /usr/sbin/ufw --force disable >/dev/null \
        || fail "страховка ufw-failsafe не поставлена — правила не тронуты"
    ufw allow proto tcp from "$CLIENTS" to any port "$PORT" comment 'cleaner' >/dev/null
    systemctl try-restart ai-egress-guard.service >/dev/null 2>&1 || true
    log "правило ufw добавлено: ${PORT}/tcp из ${CLIENTS}; страховка ufw-failsafe — 10 минут"
    log "ТЕПЕРЬ откройте НОВОЕ SSH-подключение и убедитесь, что оно проходит."
    log "После этого снимите страховку:  sudo systemctl stop ufw-failsafe.timer"
    log "Если что-то пошло не так — подождите 10 минут, ufw выключится сам."
fi

log "отпечаток сертификата — сверить в браузере при первом входе:"
openssl x509 -in "$TLS/cert.pem" -noout -fingerprint -sha256
log "проверка фактом: sudo bash $CHECK"
