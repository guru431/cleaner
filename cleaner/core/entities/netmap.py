"""Подмены IP-адресов с сохранением структуры сети."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections.abc import Iterable

from cleaner.core.types import ChatState

Address = ipaddress.IPv4Address | ipaddress.IPv6Address

_KEEP_V4 = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    )
)
_PRIVATE_V4 = tuple(
    (ipaddress.ip_network(net), bits)
    for net, bits in (("10.0.0.0/8", 8), ("172.16.0.0/12", 12), ("192.168.0.0/16", 16), ("100.64.0.0/10", 10))
)
_DOC_V4 = ("203.0.113.", "198.51.100.", "192.0.2.")
_KEEP_V6 = tuple(ipaddress.ip_network(net) for net in ("::/127", "ff00::/8", "2001:db8::/32"))
_LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")


def unpadded(address: str) -> str:
    """«010.001.002.005» из таблиц и выгрузок — это 10.1.2.5: ipaddress нулей впереди не принимает.
    Только если все четыре числа дополнены до трёх цифр: «01.02.03.04» — скорее номер, чем адрес."""
    octets = address.split(".")
    if len(octets) == 4 and all(len(octet) == 3 and octet.isdecimal() for octet in octets):
        return ".".join(str(int(octet)) for octet in octets)
    return address


def parse(token: str) -> tuple[Address, int | None]:
    """Адрес и длина префикса (если указана). ValueError, если токен — не адрес.

    Запись с нулями впереди читается как обычная (unpadded): у неё та же сущность и та же подмена,
    а восстанавливается обычная запись адреса."""
    address, _, prefix = token.partition("/")
    return ipaddress.ip_address(unpadded(address.split("%")[0])), (int(prefix) if prefix else None)


def canonical_forms(token: str) -> set[str]:
    """Записи адреса в каноническом виде, как их выдаёт подмена: сам адрес и, с длиной префикса, ещё и сеть —
    «2001:0db8:0001::0001» — это 2001:db8:1::1, «203.0.113.1/24» — и 203.0.113.1/24, и 203.0.113.1. Сравнение по ним
    не зависит от записи. Не адрес — пустое множество."""
    try:
        ip, prefix = parse(token)
    except ValueError:
        return set()
    return {str(ip)} if prefix is None else {str(ip), f"{ip}/{prefix}"}


def addresses(values: Iterable[str]) -> set[str]:
    """Канонические записи всех адресов среди values (список «никогда не скрывать», правила «открыть»)."""
    return {form for value in values for form in canonical_forms(value)}


def is_maskable(ip: Address) -> bool:
    keep = _KEEP_V4 if ip.version == 4 else _KEEP_V6
    return not any(ip in net for net in keep)


def private_bits(ip: Address) -> int | None:
    if ip.version != 4:
        return None
    for net, bits in _PRIVATE_V4:
        if ip in net:
            return bits
    return None


def _flip(key: bytes, position: int, prefix: int) -> int:
    message = bytes([position]) + prefix.to_bytes(4, "big")
    return hmac.new(key, message, hashlib.sha256).digest()[0] & 1


def map_private(addr: int, fixed_bits: int, key: bytes) -> int:
    """Перестановка с сохранением префиксов: первые fixed_bits и последний октет не меняются."""
    out = addr & (((1 << fixed_bits) - 1) << (32 - fixed_bits))
    for i in range(fixed_bits, 24):
        bit = (addr >> (31 - i)) & 1
        out |= (bit ^ _flip(key, i, addr >> (32 - i))) << (31 - i)
    return out | (addr & 0xFF)


def unmap_private(fake: int, fixed_bits: int, key: bytes) -> int:
    orig = fake & (((1 << fixed_bits) - 1) << (32 - fixed_bits))
    for i in range(fixed_bits, 24):
        bit = (fake >> (31 - i)) & 1
        orig |= (bit ^ _flip(key, i, orig >> (32 - i))) << (31 - i)
    return orig | (fake & 0xFF)


def _fake_public(state: ChatState) -> str | None:
    number = state.counters.get("ip_public", 0) + 1
    if number > 254 * len(_DOC_V4):
        return None
    state.counters["ip_public"] = number
    return _DOC_V4[(number - 1) // 254] + str((number - 1) % 254 + 1)


def _fake_v6(ip: ipaddress.IPv6Address, state: ChatState) -> str:
    host = state.counters.get("ip6_host", 0) + 1
    state.counters["ip6_host"] = host
    if ip in _LINK_LOCAL_V6:
        return str(ipaddress.IPv6Address((0xFE80 << 112) | host))
    subnet = format(int(ip) >> 64, "x")
    number = state.net6.setdefault(subnet, len(state.net6) + 1)
    return str(ipaddress.IPv6Address((0x20010DB8 << 96) | (number << 80) | host))


def fake_ip(token: str, state: ChatState) -> str | None:
    """Подмена для адреса или записи «сеть/префикс». None — выдать подмену нельзя, нужна метка."""
    ip, prefix = parse(token)
    if ip.version == 6:
        return _fake_v6(ip, state)
    bits = private_bits(ip)
    if bits is None:
        return _fake_public(state)
    fake = map_private(int(ip), bits, state.net_key)
    if prefix is None:
        return str(ipaddress.IPv4Address(fake))
    network = fake & ~((1 << (32 - prefix)) - 1) & 0xFFFFFFFF
    return f"{ipaddress.IPv4Address(network)}/{prefix}"
