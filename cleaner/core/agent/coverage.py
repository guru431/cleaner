"""SEC-2 over the serialized request, with exact exceptions from the conversation ledger."""
from __future__ import annotations

import hashlib
import json
import re

from cleaner.core.agent import walk

_ATTRIBUTION = re.compile(
    r"x-anthropic-billing-header: cc_version=[A-Za-z0-9._()-]+; cc_entrypoint=[A-Za-z0-9_-]+;"
    r"(?: cch=[0-9a-f]+;)?"
)
_ENVELOPE = frozenset({"model", "system", "messages", "input", "instructions", "tools", "role", "content", "tool_calls"})


def identity(unit: walk.Unit) -> str:
    raw = json.dumps([unit.role, unit.kind, unit.node], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def validate(body: object) -> None:
    """Cache hints are movable protocol data, never an arbitrary side channel."""
    if isinstance(body, list):
        for item in body:
            validate(item)
    elif isinstance(body, dict):
        for key, value in body.items():
            if key == "cache_control":
                if (not isinstance(value, dict) or set(value) - {"type", "ttl"}
                        or value.get("type") != "ephemeral" or value.get("ttl", "5m") not in ("5m", "1h")):
                    raise ValueError("invalid_cache_control")
            validate(value)


def validate_opaque(unit: walk.Unit) -> None:
    if unit.kind != "opaque":
        return
    if unit.role == "system":
        node = unit.node
        if (unit.path != ("system", 0) or not isinstance(node, dict) or set(node) != {"type", "text"}
                or node.get("type") != "text" or not _ATTRIBUTION.fullmatch(str(node.get("text", "")))):
            raise ValueError("invalid_attribution")
    elif unit.role != "assistant":
        raise ValueError("invalid_opaque_role")


def checked(body: dict, protocol: str, frozen: tuple[str, ...] = ()) -> list[str]:
    # Import here: protocol implementations themselves use the walker.
    from cleaner.core.agent import chat, responses
    from cleaner.core.agent.protocol import PROTOCOLS

    validate(body)
    proto = PROTOCOLS[protocol]
    units = proto.units(body)
    skipped = {unit.path for unit in units}
    out = list(proto.structural(body))
    for unit in units:
        validate_opaque(unit)
        if identity(unit) not in frozen:
            out.extend(walk.checked_strings(unit.kind, unit.node))
            if unit.kind == "other" and isinstance(unit.path[-1], str):
                out.append(unit.path[-1])
        # Rebuild keeps these fields outside the ledger's canonical node.
        raw = body
        for part in unit.path:
            raw = raw[part]
        if isinstance(raw, dict) and isinstance(unit.node, dict):
            for key in raw.keys() - unit.node.keys():
                out.extend(walk.strings_of(raw[key]))

    def envelope(node, path=()):
        if path in skipped:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if (*path, key) in skipped:
                    continue
                if key not in _ENVELOPE:
                    out.append(key)
                if key == "role" and value in ("user", "assistant", "system", "developer", "tool"):
                    continue
                envelope(value, (*path, key))
        elif isinstance(node, list):
            for i, value in enumerate(node):
                envelope(value, (*path, i))
        elif isinstance(node, str):
            out.append(node)

    # Parameter schemas have their own protocol exceptions (property names and required).
    params = {"anthropic": walk.PARAMS, "chat": chat.PARAMS, "responses": responses.PARAMS}[protocol]
    envelope({key: value for key, value in body.items() if key not in params})
    return out
