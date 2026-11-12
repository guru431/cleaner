#!/usr/bin/env bash
# Установка и обновление Cleaner на сервере. Идемпотентен: повторный прогон обновляет код,
# зависимости и юнит, а главный ключ, базу, настройки, сертификат и правило ufw не трогает.
#
#   sudo bash install-cleaner.sh <каталог доставки> [логин первого администратора]
#
# Адрес, сети клиентов и шлюз — в профиле хоста deploy/hosts/<hostname -s>.conf (другое имя —
# CLEANER_HOST=<имя>); профиля нет — установка не начинается.
#
# Каталог доставки — распакованный `git archive` репозитория Cleaner в каталоге под root
# (`/root/stage-cleaner` с правами 0700 или `sudo mktemp -d`). git отдаёт файлы с LF по .gitattributes,
# поэтому CRLF, как установщикам vLLM, снимать не нужно. Логин нужен только при первой
# установке: тогда создаются база и главный ключ, а пароль администратора спрашивается
# с клавиатуры (ssh -t).
#
# Откат: если после выкатки самопроверка не прошла или служба не ответила по HTTPS,
# возвращаются прежние код, окружение и юнит. Копия базы живёт только до ответа службы.
# Правило ufw ставится под отложенным откатом ufw-failsafe, который установщик взводит сам;
# снять страховку — после проверки НОВЫМ SSH-подключением.
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
EGRESS=/usr/local/sbin/cleaner-egress.sh
EGRESS_UNIT=/etc/systemd/system/cleaner-egress.service
HOST_ENV=$ETC/host.env
PORT=5464
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

# --- профиль хоста: HOST_IP, CLIENTS, INTERNAL, GATEWAY, CERT_NAME, SERVER_GUARD, GATEWAY_KEY_HINT ----
# Читается после проверки каталога доставки: он принадлежит root и закрыт на запись остальным.
HOST_NAME=${CLEANER_HOST:-$(hostname -s)}
PROFILE="$SRC/deploy/hosts/$HOST_NAME.conf"
[[ -f "$PROFILE" ]] || fail "нет профиля хоста $PROFILE — заведите его в deploy/hosts/ или задайте CLEANER_HOST"
# shellcheck source=/dev/null
. "$PROFILE"
[[ -n "${HOST_IP:-}" && -n "${CLIENTS:-}" && -n "${INTERNAL:-}" && -n "${GATEWAY:-}" && -n "${CERT_NAME:-}" ]] \
    || fail "профиль $PROFILE неполон: нужны HOST_IP, CLIENTS, INTERNAL, GATEWAY, CERT_NAME"
log "профиль хоста: $HOST_NAME ($HOST_IP, клиенты: $CLIENTS)"
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
# Профиль — для cleaner-egress.sh и check-cleaner.sh, которые живут вне каталога доставки. Секретов в нём нет.
install -o root -g root -m 0644 "$PROFILE" "$HOST_ENV"

# --- настройки: ставятся один раз, адрес службы — из профиля хоста -----------------
if [[ ! -f "$CONF" ]]; then
    sed "s|^host = .*|host = \"${HOST_IP}\"   # профиль ${HOST_NAME}: только интерфейс сети клиентов (SEC-8)|" \
        "$SRC/deploy/cleaner.toml" > "$CONF"
    chown root:cleaner "$CONF"
    chmod 0640 "$CONF"
    grep -q "^host = \"${HOST_IP}\"" "$CONF" || fail "в $CONF не подставился адрес $HOST_IP"
    log "настройки установлены: $CONF"
else
    log "настройки уже есть — не трогаю: $CONF"
fi

# --- сертификат: собственный, выпускается один раз -------------------------------
# Общий сертификат сервера (/etc/ai-services/tls/dashboard.*) не годится: его ключ
# может быть недоступен учётной записи службы и не содержать её адреса в SAN. Отпечаток в документы не
# выписывается — его печатают этот установщик и check-cleaner.sh.
# CLEANER_REISSUE_CERT=1 — выпустить заново (новый отпечаток: браузеры и агенты принимают его снова); прежний остаётся
# рядом. Нужен сертификатам до 28.10.2026: без keyCertSign их не принимает Claude Code (Bun) — шлюз агентов, план 5Б;
# и до 29.10.2026: с CA:TRUE (так openssl выпускает самоподписанный по умолчанию) их не принимает Codex (rustls) — план 5В.
if [[ "${CLEANER_REISSUE_CERT:-0}" == "1" && -s "$TLS/cert.pem" ]]; then
    mv "$TLS/cert.pem" "$TLS/cert.pem.prev-$STAMP"
    mv "$TLS/key.pem" "$TLS/key.pem.prev-$STAMP"
    log "сертификат будет выпущен заново (CLEANER_REISSUE_CERT=1); прежний — $TLS/cert.pem.prev-$STAMP"
fi
if [[ ! -s "$TLS/cert.pem" || ! -s "$TLS/key.pem" ]]; then
    # Вывод openssl (точки генерации ключа) показывается, только если выпуск не удался.
    if ! out=$(
        umask 077
        openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
            -keyout "$TLS/key.pem" -out "$TLS/cert.pem" \
            -subj "/CN=${CERT_NAME} Cleaner" \
            -addext "subjectAltName=IP:${HOST_IP},DNS:${CERT_NAME}" \
            -addext "basicConstraints=critical,CA:FALSE" \
            -addext "keyUsage=digitalSignature,keyEncipherment,keyCertSign" \
            -addext "extendedKeyUsage=serverAuth" 2>&1
    ); then
        echo "$out" >&2
        fail "сертификат не выпущен — причина в выводе openssl выше"
    fi
    chown root:cleaner "$TLS/key.pem" "$TLS/cert.pem"
    chmod 0640 "$TLS/key.pem"
    chmod 0644 "$TLS/cert.pem"
    log "сертификат выпущен: $TLS/cert.pem"
fi

# --- откат ----------------------------------------------------------------------
PREV_CODE=""
PREV_VENV=""
PREV_UNIT=""
DB_BACKUP=""
SCHEMA_BEFORE=""
STOPPED=0
# Работающая служба останавливается до замены окружения и кода: её путь к пакету — $APP/cleaner, и после замены
# ленивые импорты брали бы новые модули вперемешку с уже загруженными старыми, до самого перезапуска.
# Останавливается в любом состоянии, кроме inactive и failed: служба, падающая по кругу (Restart=always), между
# попытками в activating (auto-restart), и отложенный запуск новой версии успел бы поднять схему базы до её копии.
stop_service() {
    local state
    state=$(systemctl is-active cleaner.service 2>/dev/null || true)
    if [[ $STOPPED -eq 0 && -n "$state" && "$state" != "inactive" && "$state" != "failed" ]]; then
        STOPPED=1
        systemctl stop cleaner.service
        log "служба остановлена до замены файлов"
    fi
}
schema_version() {  # номер схемы базы; читается от cleaner, чтобы файлы журнала WAL не стали чужими
    runuser -u cleaner -- python3 -c \
        'import sqlite3, sys; print(sqlite3.connect(sys.argv[1]).execute("PRAGMA user_version").fetchone()[0])' \
        "$DATA/cleaner.db"
}
rollback() {
    trap - ERR
    log "ОТКАТ: $1"
    local swapped=0
    if [[ -n "$PREV_CODE" ]]; then rm -rf "$APP/cleaner"; mv "$PREV_CODE" "$APP/cleaner"; swapped=1; fi
    if [[ -n "$PREV_VENV" ]]; then rm -rf "$APP/.venv"; mv "$PREV_VENV" "$APP/.venv"; swapped=1; fi
    if [[ -n "$PREV_UNIT" ]]; then cp -a "$PREV_UNIT" "$UNIT"; swapped=1; fi
    rm -rf "$APP/.venv.new" "$APP/cleaner.new"
    # Новая версия могла успеть поднять схему базы при старте: прежний код такую базу не откроет.
    if [[ -n "$DB_BACKUP" && "$(schema_version 2>/dev/null || echo '?')" != "$SCHEMA_BEFORE" ]]; then
        systemctl stop cleaner.service || true
        rm -f "$DATA/cleaner.db-wal" "$DATA/cleaner.db-shm"
        install -o cleaner -g cleaner -m 0600 "$DB_BACKUP" "$DATA/cleaner.db"
        log "база возвращена из копии $DB_BACKUP: новая версия успела изменить её схему"
    fi
    systemctl daemon-reload || true
    if [[ $FIRST_INSTALL -eq 1 ]]; then
        systemctl disable --now cleaner.service >/dev/null 2>&1 || true
        log "первая установка не удалась: служба остановлена, ключ и база не тронуты"
    elif [[ $swapped -eq 1 || $STOPPED -eq 1 ]]; then
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
# Пакеты качает установщик от root, а не служба: её выход наружу ограничен портом 443 и записывается.
if ! cmp -s "$SRC/requirements-linux.txt" "$APP/.venv/requirements-linux.txt"; then
    rm -rf "$APP/.venv.new"
    python3.12 -m venv "$APP/.venv.new"
    "$APP/.venv.new/bin/pip" install --no-input --quiet --require-hashes --only-binary=:all: \
        -r "$SRC/requirements-linux.txt"
    cp "$SRC/requirements-linux.txt" "$APP/.venv.new/requirements-linux.txt"
    if [[ -d "$APP/.venv" ]]; then
        rm -rf "$APP/.venv.prev"
        stop_service
        mv "$APP/.venv" "$APP/.venv.prev"
        PREV_VENV="$APP/.venv.prev"
    fi
    mv "$APP/.venv.new" "$APP/.venv"
    # Окружение собрано под именем .venv.new, чтобы работающая служба до замены не лишилась пакетов,
    # которые она подгружает лениво. Пути в заголовках скриптов bin/ (pip и др.) и в activate
    # переписываются на настоящее имя; ссылки на интерпретатор grep -r не открывает.
    { grep -rlF "$APP/.venv.new" "$APP/.venv/bin" || true; } | xargs -r sed -i "s|$APP/\.venv\.new|$APP/.venv|g"
    log "окружение собрано по requirements-linux.txt"
else
    log "зависимости не менялись — окружение прежнее"
fi

# --- код: каталог заменяется целиком, прежний уезжает в копию --------------------
rm -rf "$APP/cleaner.new"
# Время файлов сохраняется: git archive ставит им время коммита, и дата отпечатка кода (cleaner verify, подвал) — его.
cp -r --preserve=timestamps "$SRC/cleaner" "$APP/cleaner.new"
find "$APP/cleaner.new" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:cleaner "$APP/cleaner.new"
find "$APP/cleaner.new" -type d -exec chmod 0750 {} +
find "$APP/cleaner.new" -type f -exec chmod 0640 {} +
if [[ -d "$APP/cleaner" ]]; then
    stop_service
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
    mapfile -t units < <(ls -1t "$UNIT".bak-* 2>/dev/null || true)
    for old in "${units[@]:3}"; do
        rm -f "$old"                   # хранятся три последние копии, как у кода
    done
fi
install -o root -g root -m 0644 "$SRC/deploy/cleaner.service" "$UNIT"
install -o root -g root -m 0755 "$SRC/deploy/check-cleaner.sh" "$CHECK"
install -o root -g root -m 0644 "$SRC/deploy/check_ipv6.py" /usr/local/sbin/cleaner-check-ipv6.py
# Границы выхода наружу (этап 3): цепочка ставится до перезапуска службы — без неё служба не стартует.
install -o root -g root -m 0755 "$SRC/deploy/cleaner-egress.sh" "$EGRESS"
install -o root -g root -m 0644 "$SRC/deploy/cleaner-egress.service" "$EGRESS_UNIT"
systemctl daemon-reload
systemctl enable cleaner-egress.service >/dev/null 2>&1
systemctl restart cleaner-egress.service

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
    log "Ключа шлюза нет: ${GATEWAY_KEY_HINT:-выпустите его в шлюзе сервера}; допишите строку CLEANER_GATEWAY_KEY=… в $ENVF через sudoedit и перезапустите службу: sudo systemctl restart cleaner.service"
fi

# --- копия базы: новая версия мигрирует схему при старте, а прежний код базу новой версии не откроет ----
if [[ $FIRST_INSTALL -eq 0 ]]; then
    SCHEMA_BEFORE=$(schema_version)
    DB_BACKUP="$DATA/cleaner.db.bak-$STAMP"
    runuser -u cleaner -- python3 - "$DATA/cleaner.db" "$DB_BACKUP" <<'PY'
import sqlite3
import sys

source, target = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])
source.backup(target)
target.close()
source.close()
PY
    chmod 0600 "$DB_BACKUP"
    log "копия базы до обновления: $DB_BACKUP (схема версии $SCHEMA_BEFORE); стирается, когда служба ответит"
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
# Копия базы нужна только откату этого прогона. В ней удалённые чаты вместе с ключами, обёрнутыми тем же главным
# ключом (FR-1.4, AC-1.10): она стирается, как и копии прежних прогонов (до 09.11.2026 их хранилось три, а после
# отката копия остаётся до следующего удачного прогона). shred — по возможности: журнал ФС и SSD его не гарантируют.
if compgen -G "$DATA/cleaner.db.bak-*" >/dev/null; then
    shred -u -- "$DATA"/cleaner.db.bak-* || rm -f -- "$DATA"/cleaner.db.bak-*
    log "копии базы стёрты: служба ответила, откат больше не нужен"
fi
log "служба отвечает: https://${HOST_IP}:${PORT}/login"

# --- вход: порт открыт только сети клиентов -------------------------------------------
# Имя страховки постоянное: ai-ctl boot-readiness и панель ищут ровно ufw-failsafe.timer.
# После правки ufw — рестарт ai-egress-guard, как у install-step8-perimeter.sh.
RULES="$(ufw status 2>/dev/null || true)"
missing=()
for net in $CLIENTS; do
    grep -qE "^${PORT}/tcp +ALLOW +${net//./\\.}( |$)" <<< "$RULES" || missing+=("$net")
done
if [[ ${#missing[@]} -eq 0 ]]; then
    log "правила ufw для ${PORT} уже есть — страховку не взвожу"
else
    systemctl stop ufw-failsafe.timer ufw-failsafe.service >/dev/null 2>&1 || true
    systemctl reset-failed ufw-failsafe.timer ufw-failsafe.service >/dev/null 2>&1 || true
    systemd-run --on-active=10m --unit=ufw-failsafe /usr/sbin/ufw --force disable >/dev/null \
        || fail "страховка ufw-failsafe не поставлена — правила не тронуты"
    # Без этой проверки set -e молча вышел бы с взведённой страховкой, и ufw выключился бы через 10 минут.
    for net in "${missing[@]}"; do
        if ! ufw allow proto tcp from "$net" to any port "$PORT" comment 'cleaner' >/dev/null; then
            systemctl stop ufw-failsafe.timer >/dev/null 2>&1 || true
            fail "правило ufw для ${PORT} из ${net} не добавлено; страховка снята — служба недоступна части клиентов"
        fi
    done
    systemctl try-restart ai-egress-guard.service >/dev/null 2>&1 || true
    log "правила ufw добавлены: ${PORT}/tcp из ${missing[*]}; страховка ufw-failsafe — 10 минут"
    log "ТЕПЕРЬ откройте НОВОЕ SSH-подключение и убедитесь, что оно проходит."
    log "После этого снимите страховку:  sudo systemctl stop ufw-failsafe.timer"
    log "Если что-то пошло не так — подождите 10 минут, ufw выключится сам."
fi

log "отпечаток сертификата — сверить в браузере при первом входе:"
openssl x509 -in "$TLS/cert.pem" -noout -fingerprint -sha256
log "проверка фактом: sudo bash $CHECK"
