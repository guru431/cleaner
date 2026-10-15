#!/usr/bin/env bash
# Границы выхода наружу службы Cleaner на example (SEC-15, раздел 15 спецификации).
#
#   cleaner-egress.sh          — поставить цепочку CLEANER-EGRESS и вход в неё (юнит cleaner-egress.service)
#   cleaner-egress.sh check    — код 0, если вход в обе цепочки (IPv4 и IPv6) на месте (ExecStartPre=+ у cleaner.service)
#
# Образец — ai-egress-guard.sh репозитория vLLM, но здесь цепочка не только пишет, а решает:
#   к внутренним сетям сервера              → пропустить
#   TCP 443, новое соединение               → записать «cleaner-out: » (не чаще 30 в минуту) и пропустить
#   остальное                               → записать «cleaner-egress: » (не чаще 6 в минуту) и отклонить
# IPv6 наружу — только петля. Запросы DNS идут локальному резолверу по петле.
#
# Правила iptables не переживают перезагрузку, а `ufw reload` убирает вход из OUTPUT — так же, как у
# ai-egress-guard. Поэтому: юнит на загрузке и `systemctl try-restart cleaner-egress.service` после
# каждой правки ufw. Пропажа входа делает выход ШИРЕ: служба без него не стартует (ExecStartPre),
# а у работающей её ловит check-cleaner.sh.
set -euo pipefail

USER_NAME=cleaner
CHAIN=CLEANER-EGRESS
# Копия INTERNAL из ai-egress-guard.sh сервера: правило vLLM — менять все копии вместе. Тест vLLM видит
# только свой репозиторий, поэтому совпадение списков сверяет check-cleaner.sh.
INTERNAL="127.0.0.0/8 example/24 example/24 example/19 example/24 172.16.0.0/12"

if [[ "${1:-}" == "check" ]]; then
    iptables -C OUTPUT -m owner --uid-owner "$USER_NAME" -j "$CHAIN" 2>/dev/null \
        && ip6tables -C OUTPUT -m owner --uid-owner "$USER_NAME" -j "$CHAIN" 2>/dev/null \
        || { echo "cleaner-egress: нет входа в цепочку $CHAIN — выход наружу не ограничен" >&2; exit 1; }
    exit 0
fi

id -u "$USER_NAME" >/dev/null 2>&1 || { echo "нет пользователя $USER_NAME" >&2; exit 1; }

# Своя цепочка, а не правила прямо в OUTPUT: содержимое OUTPUT ведёт ufw.
iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
for net in $INTERNAL; do
    iptables -A "$CHAIN" -d "$net" -j RETURN
done
iptables -A "$CHAIN" -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 30/min \
    -j LOG --log-prefix "cleaner-out: " --log-level info
iptables -A "$CHAIN" -p tcp --dport 443 -j RETURN
# Предел частоты обязателен: процесс, потерявший сеть, повторяет попытку в цикле.
iptables -A "$CHAIN" -m limit --limit 6/min -j LOG --log-prefix "cleaner-egress: " --log-level warning
iptables -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset
iptables -A "$CHAIN" -j REJECT

ip6tables -N "$CHAIN" 2>/dev/null || ip6tables -F "$CHAIN"
ip6tables -A "$CHAIN" -d ::1/128 -j RETURN
ip6tables -A "$CHAIN" -m limit --limit 6/min -j LOG --log-prefix "cleaner-egress: " --log-level warning
ip6tables -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset
ip6tables -A "$CHAIN" -j REJECT

# Вход — первым правилом: собственные цепочки ufw в OUTPUT пропускают новые исходящие соединения,
# и переход после них таких соединений не увидел бы.
for tool in iptables ip6tables; do
    "$tool" -C OUTPUT -m owner --uid-owner "$USER_NAME" -j "$CHAIN" 2>/dev/null \
        || "$tool" -I OUTPUT 1 -m owner --uid-owner "$USER_NAME" -j "$CHAIN"
done
