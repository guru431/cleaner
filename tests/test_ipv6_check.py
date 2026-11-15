"""The generated output path blocks external IPv6 regardless of the input rules."""
import copy

from deploy.check_ipv6 import ipv6_closed


def match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def table():
    def rule(chain, expr):
        return {"rule": {"family": "inet", "table": "cleaner_egress", "chain": chain, "expr": expr}}
    return {"nftables": [
        rule("output", [match({"meta": {"key": "skuid"}}, 1001), {"jump": {"target": "cleaner"}}]),
        rule("cleaner", [match({"payload": {"protocol": "ip", "field": "daddr"}}, {"set": ["127.0.0.0/8"]}), {"return": None}]),
        rule("cleaner", [match({"payload": {"protocol": "ip6", "field": "daddr"}}, "::1"), {"return": None}]),
        rule("cleaner", [match({"meta": {"key": "nfproto"}}, "ipv4"), match({"payload": {"protocol": "tcp", "field": "dport"}}, 443), {"return": None}]),
        rule("cleaner", [match({"meta": {"key": "l4proto"}}, "tcp"), {"reject": {"type": "tcp reset"}}]),
        rule("cleaner", [{"reject": None}]),
        rule("input", [match({"meta": {"key": "nfproto"}}, "ipv6"), {"drop": None}]),
    ]}


def test_generated_rules_pass_and_external_ipv6_return_or_missing_reject_fails():
    original = table()
    assert ipv6_closed(original)
    changed = copy.deepcopy(original)
    changed["nftables"][3]["rule"]["expr"][0]["match"]["right"] = "ipv6"
    assert not ipv6_closed(changed)
    changed = copy.deepcopy(original)
    changed["nftables"][5]["rule"]["expr"] = [{"return": None}]
    assert not ipv6_closed(changed)


def test_missing_or_incorrect_tcp_reset_is_refused():
    changed = table()
    del changed["nftables"][4]
    assert not ipv6_closed(changed)
    changed = table()
    changed["nftables"][4]["rule"]["expr"][1] = {"reject": None}
    assert not ipv6_closed(changed)
