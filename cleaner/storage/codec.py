"""ChatState ядра ↔ JSON: состояние чата хранится целиком (раздел 4 спецификации)."""
from __future__ import annotations

import base64
import json

from cleaner.core.types import ChatRule, ChatState, Entity, EntityType, Surrogate

# Список сверяется с полями ChatState тестом: новое поле без сериализации — красный тест.
FIELDS = (
    "chat_id", "net_key", "label_style", "entities", "surrogates", "issued", "rules",
    "key_alias", "foreign_labels", "counters", "net6", "written",
)


def state_to_json(state: ChatState) -> bytes:
    data = {
        "chat_id": state.chat_id,
        "net_key": base64.b64encode(state.net_key).decode("ascii"),
        "label_style": state.label_style,
        "entities": [
            {
                "id": e.id, "type": e.type.value, "number": e.number, "key": e.key,
                "restore_value": e.restore_value, "origin": e.origin, "forms": e.forms,
                "parts": e.parts, "words": e.words, "restore_rank": e.restore_rank,
            }
            for e in state.entities.values()
        ],
        "surrogates": {text: [s.entity_id, s.original, s.kind] for text, s in state.surrogates.items()},
        "issued": state.issued,
        "rules": [[r.action, r.value, r.type.value if r.type else None, r.bounds] for r in state.rules],
        "key_alias": state.key_alias,
        "foreign_labels": sorted(state.foreign_labels),
        "counters": state.counters,
        "net6": state.net6,
        "written": state.written,
    }
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def state_from_json(raw: bytes) -> ChatState:
    try:
        return _state_from_json(raw)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        raise ValueError("Повреждено состояние чата: неверный формат данных") from None


def _state_from_json(raw: bytes) -> ChatState:
    data = json.loads(raw.decode("utf-8"))
    rules = []
    for row in data["rules"]:
        if not isinstance(row, list) or len(row) not in (3, 4):
            raise ValueError("invalid rule")
        action, value, type_ = row[:3]
        bounds = row[3] if len(row) == 4 else "none"
        if action not in ("mask", "unmask") or not isinstance(value, str) or bounds not in ("none", "letters", "strict"):
            raise ValueError("invalid rule")
        rules.append(ChatRule(action, value, EntityType(type_) if type_ else None, bounds))
    entities = {
        e["id"]: Entity(
            e["id"], EntityType(e["type"]), e["number"], e["key"], e["restore_value"], e["origin"], list(e["forms"]),
            dict(e.get("parts", {})), list(e.get("words", [])), int(e.get("restore_rank", 0)),
        )
        for e in data["entities"]
    }
    return ChatState(
        chat_id=data["chat_id"],
        net_key=base64.b64decode(data["net_key"], validate=True),
        label_style=data["label_style"],
        entities=entities,
        surrogates={text: Surrogate(v[0], v[1], v[2]) for text, v in data["surrogates"].items()},
        issued=dict(data["issued"]),
        # Правило до 15.10.2026 — тройка без границ: оно ищется где угодно, как и искалось.
        rules=rules,
        key_alias=dict(data["key_alias"]),
        foreign_labels=set(data["foreign_labels"]),
        counters={key: int(value) for key, value in data["counters"].items()},
        net6={key: int(value) for key, value in data["net6"].items()},
        written=bool(data.get("written", False)),       # чаты до плана 5Б — обычные
    )
