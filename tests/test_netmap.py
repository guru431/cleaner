import ipaddress

import pytest

from cleaner.core.entities import netmap

KEY = bytes(range(32))


def mapped(address: str) -> ipaddress.IPv4Address:
    ip = ipaddress.IPv4Address(address)
    return ipaddress.IPv4Address(netmap.map_private(int(ip), netmap.private_bits(ip), KEY))


def test_subnets_and_host_octet_survive():
    a, b, c = mapped("10.1.2.5"), mapped("10.1.2.77"), mapped("10.1.9.5")
    assert int(a) >> 8 == int(b) >> 8
    assert int(a) >> 16 == int(c) >> 16
    assert int(a) >> 8 != int(c) >> 8
    assert str(a).endswith(".5") and str(b).endswith(".77")


@pytest.mark.parametrize(
    "address, block",
    [
        ("10.1.2.5", "10.0.0.0/8"),
        ("172.20.30.40", "172.16.0.0/12"),
        ("192.168.1.10", "192.168.0.0/16"),
        ("100.64.1.1", "100.64.0.0/10"),
    ],
)
def test_private_address_stays_in_its_range_and_mapping_is_reversible(address, block):
    fake = mapped(address)
    assert fake in ipaddress.ip_network(block)
    original = netmap.unmap_private(int(fake), netmap.private_bits(fake), KEY)
    assert str(ipaddress.IPv4Address(original)) == address


def test_mapping_depends_on_the_chat_key():
    addresses = [int(ipaddress.IPv4Address(f"10.{n}.{n}.1")) for n in range(1, 9)]
    assert any(
        netmap.map_private(a, 8, KEY) != netmap.map_private(a, 8, bytes(32)) for a in addresses
    )


def test_service_addresses_are_not_maskable():
    for address in ("127.0.0.1", "0.0.0.0", "255.255.255.0", "224.0.0.5", "169.254.1.1", "192.0.2.1", "::1"):
        assert not netmap.is_maskable(ipaddress.ip_address(address)), address
    for address in ("10.1.2.3", "8.8.8.8", "2a00:1450:4010::65", "fe80::1"):
        assert netmap.is_maskable(ipaddress.ip_address(address)), address


def test_zero_padded_address_is_read_as_decimal():
    assert netmap.parse("010.001.002.005") == (ipaddress.IPv4Address("10.1.2.5"), None)
    assert netmap.parse("192.168.001.000/24") == (ipaddress.IPv4Address("192.168.1.0"), 24)
    for token in ("01.02.03.04", "010.1.2.5"):
        with pytest.raises(ValueError):
            netmap.parse(token)


def test_public_addresses_get_documentation_addresses_in_order(state):
    assert netmap.fake_ip("85.143.10.20", state) == "203.0.113.1"
    assert netmap.fake_ip("8.8.4.4", state) == "203.0.113.2"


def test_public_pool_is_finite(state):
    state.counters["ip_public"] = 762
    assert netmap.fake_ip("85.143.10.20", state) is None


def test_network_with_a_short_prefix_keeps_zero_host_bits(state):
    fake = netmap.fake_ip("10.1.0.0/16", state)
    assert fake.startswith("10.") and fake.endswith(".0.0/16")


def test_ipv6_keeps_the_64_bit_subnet(state):
    assert netmap.fake_ip("2a00:1450:4010::65", state) == "2001:db8:1::1"
    assert netmap.fake_ip("2a00:1450:4010::66", state) == "2001:db8:1::2"
    assert netmap.fake_ip("2a00:1450:4011::1", state) == "2001:db8:2::3"
    assert netmap.fake_ip("fe80::1ff:fe23:4567:890a", state) == "fe80::4"
