import json
from dataclasses import fields

from cleaner.core.pipeline import sanitize
from cleaner.core.types import ChatRule, ChatState, Settings
from cleaner.core.types import EntityType as T
from cleaner.storage import codec


def test_every_field_of_the_chat_state_is_stored():
    """Потеря issued или счётчиков выдала бы известным сущностям другие замены."""
    assert set(codec.FIELDS) == {f.name for f in fields(ChatState)}
    state = ChatState(chat_id="c", net_key=bytes(32))
    assert set(json.loads(codec.state_to_json(state))) == set(codec.FIELDS)


def test_state_after_sanitizing_survives_the_round_trip(state):
    state.rules.append(ChatRule("mask", "Заря", T.TERM))
    state.rules.append(ChatRule("unmask", "a@x.example"))
    state.rules.append(ChatRule("mask", "Иванову Ивану", T.PERSON))
    state.rules.append(ChatRule("mask", "corp", T.TERM, "strict"))
    state.foreign_labels.add("<PERSON_9>")
    text = (
        "Заря: <PERSON_9>, CONTOSO\\ivanov, srv-dc01.corp.contoso.ru, 10.1.2.5, 2a00:1450:4010::65, "
        "MAC 00:1A:2B:3C:4D:5E, S-1-5-21-1-2-3-500, пароль: Qwerty123!, Иванову Ивану"
    )
    sanitize(state, text, Settings())
    assert codec.state_from_json(codec.state_to_json(state)) == state


def test_rules_stored_without_bounds_are_read_as_rules_searched_anywhere(state):
    """Правило до 15.10.2026 хранилось тройкой: чат читается без миграции, правило ищется, как искалось."""
    state.rules += [ChatRule("mask", "Заря", T.TERM), ChatRule("unmask", "a@x.example")]
    data = json.loads(codec.state_to_json(state))
    data["rules"] = [rule[:3] for rule in data["rules"]]
    restored = codec.state_from_json(json.dumps(data).encode("utf-8"))
    assert restored.rules == state.rules and [rule.bounds for rule in restored.rules] == ["none", "none"]
