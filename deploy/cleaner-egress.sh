#!/usr/bin/env bash
# Границы выхода наружу службы Cleaner на example (SEC-15, раздел 15 спецификации).
#
#   cleaner-egress.sh          — поставить таблицу nftables inet cleaner_egress (юнит cleaner-egress.service)
#   cleaner-egress.sh check    — код 0, если таблица на месте и кончается отказом (ExecStartPre=+ у cleaner.service)
#
# Пакеты учётной записи cleaner:
#   к внутренним сетям сервера              → пропустить
#   TCP 443 по IPv4, новое соединение       → записать «cleaner-out: » (не чаще 30 в минуту) и пропустить
#   остальное, в том числе весь IPv6 кроме петли → записать «cleaner-egress: » (не чаще 6 в минуту) и отклонить
# Запросы DNS идут локальному резолверу по петле.
#
# Своя таблица nftables, а не цепочка iptables рядом с ufw: ufw работает через iptables-nft в таблицах
# ip filter / ip6 filter и при reload и disable чистит их целиком, а чужую таблицу не видит. Цепочка
# iptables пропадала бы молча — и выход службы становился бы ШИРЕ, а не уже. Таблица заменяется одной
# транзакцией nft: пустой она не бывает ни мгновения. Отказ в своей таблице окончателен, что бы ни
# решили цепочки ufw, — пакет проходит, только если его пропустили все таблицы.
set -euo pipefail

USER_NAME=cleaner
TABLE=cleaner_egress
PORT=5464
CLIENTS=example/19
# Копия INTERNAL из ai-egress-guard.sh сервера: правило vLLM — менять все копии вместе. Тест vLLM видит
# только свой репозиторий, поэтому совпадение списков сверяет check-cleaner.sh.
INTERNAL="127.0.0.0/8 example/24 example/24 example/19 example/24 172.16.0.0/12"

if [[ "${1:-}" == "check" ]]; then
    rules=$(nft list chain inet "$TABLE" output 2>/dev/null) \
        || { echo "cleaner-egress: нет таблицы $TABLE — выход наружу не ограничен" >&2; exit 1; }
    grep -q "skuid" <<< "$rules" && grep -q "reject with tcp reset" <<< "$rules" \
        || { echo "cleaner-egress: таблица $TABLE без отбора по учётной записи или без отказа" >&2; exit 1; }
    exit 0
fi

uid=$(id -u "$USER_NAME") || { echo "нет пользователя $USER_NAME" >&2; exit 1; }
nets=$(tr ' ' ',' <<< "$INTERNAL")

nft -f - <<EOF
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
    chain output {
        type filter hook output priority filter; policy accept;
        meta skuid != $uid return
        ip daddr { $nets } return
        ip6 daddr ::1 return
        meta nfproto ipv4 tcp dport 443 ct state new limit rate 30/minute log prefix "cleaner-out: " level info
        meta nfproto ipv4 tcp dport 443 return
        limit rate 6/minute log prefix "cleaner-egress: " level warn
        meta l4proto tcp reject with tcp reset
        reject
    }
    # Входящие на порт службы — только из сети клиентов и петли: второй слой за правилом ufw, как раньше
    # IPAddressDeny= юнита (он ограничивал оба направления и снят ради выхода на 443).
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport $PORT ip saddr != { $CLIENTS, 127.0.0.0/8 } drop
        tcp dport $PORT meta nfproto ipv6 ip6 saddr != ::1 drop
    }
}
EOF
