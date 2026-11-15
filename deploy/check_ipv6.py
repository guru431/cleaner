"""Read-only validation of the generated nftables output path; stdin is `nft -j`."""
import json
import sys


def ipv6_closed(document: dict) -> bool:
    """Malformed nft output fails closed for library callers as well as the CLI."""
    try:
        return _ipv6_closed(document)
    except (ValueError, TypeError, AttributeError, KeyError, IndexError):
        return False


def _ipv6_closed(document: dict) -> bool:
    rules = {"output": [], "cleaner": []}
    for item in document.get("nftables", []):
        rule = item.get("rule", {})
        if rule.get("family") == "inet" and rule.get("table") == "cleaner_egress" and rule.get("chain") in rules:
            rules[rule["chain"]].append(rule.get("expr", []))
    output = rules["output"]
    if len(output) != 1 or len(output[0]) != 2:
        return False
    match = output[0][0].get("match", {})
    if (match.get("left") != {"meta": {"key": "skuid"}} or match.get("op") != "=="
            or not isinstance(match.get("right"), int) or output[0][1] != {"jump": {"target": "cleaner"}}):
        return False
    cleaner = rules["cleaner"]
    if not cleaner or len(cleaner[-1]) != 1 or "reject" not in cleaner[-1][0]:
        return False
    tcp_reset = [
        {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
        {"reject": {"type": "tcp reset"}},
    ]
    if len(cleaner) < 2 or cleaner[-2] != tcp_reset:
        return False
    loopback = False
    for expressions in cleaner:
        if any(set(expr) - {"match", "return", "reject", "drop", "log", "limit", "counter"} for expr in expressions):
            return False
        if not any("return" in expr for expr in expressions):
            continue
        matches = [expr["match"] for expr in expressions if "match" in expr and expr["match"].get("op") == "=="]
        ipv4 = any(m.get("left", {}).get("payload", {}).get("protocol") == "ip" or
                   m.get("left") == {"meta": {"key": "nfproto"}} and m.get("right") == "ipv4" for m in matches)
        local = any(m.get("left") == {"payload": {"protocol": "ip6", "field": "daddr"}} and m.get("right") == "::1"
                    for m in matches)
        if not (ipv4 or local):
            return False
        loopback |= local
    return loopback


if __name__ == "__main__":
    try:
        valid = ipv6_closed(json.load(sys.stdin))
    except (ValueError, TypeError, AttributeError):
        valid = False
    sys.exit(0 if valid else 1)
