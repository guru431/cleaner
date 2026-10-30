"""Проверка утечек (раздел 8): адрес IP находится по адресу, а не только по записям, которые чат уже видел."""
import copy
from dataclasses import replace

import pytest

from cleaner.core import leakcheck
from cleaner.core.entities import ops
from cleaner.core.pipeline import sanitize
from cleaner.core.types import DictEntry, Entity, Policy, Settings, Surrogate, default_policies
from cleaner.core.types import EntityType as T


def leaked(text, state, settings) -> list[tuple[str, str | None]]:
    return [(text[leak.start:leak.end], leak.entity_id) for leak in leakcheck.check(text, state, settings)]


def fresh(text, state, settings) -> list[tuple[str, str | None]]:
    """leaked по копии состояния под новым id чата: таблицы проверки собираются с начала."""
    fresh.count = getattr(fresh, "count", 0) + 1
    return leaked(text, replace(copy.deepcopy(state), chat_id=f"fresh-{fresh.count}"), settings)


def add(state, entity_id: str, type_: T, *forms: str) -> Entity:
    state.entities[entity_id] = Entity(entity_id, type_, len(state.entities) + 1, forms[0], forms[0], "detector", [*forms])
    return state.entities[entity_id]


def test_tables_kept_between_checks_follow_every_change_of_the_state(state, settings):
    """Задача 5a плана 5Г: таблицы проверки чата берутся из памяти, только пока всё, из чего они собраны, то же. Сущность,
    добавленная после сборки (в том числе адрес — он находится и в другой записи), новое и заменённое на месте написание
    прежней, правило «открыть», список «никогда не скрывать», выключенный тип и значение словаря меняют находки так же,
    как при сборке с начала; находка не пропадает ни разу."""
    text = "ivanov petrov vanya sidorov 010.001.002.005 contoso"

    def found(current: Settings = settings) -> list[str]:
        out = leaked(text, state, current)
        assert out == fresh(text, state, current)
        return [f"{value}:{entity_id}" for value, entity_id in out]

    add(state, "a1", T.ACCOUNT, "ivanov")
    assert found() == ["ivanov:a1"]
    add(state, "a2", T.ACCOUNT, "petrov")                  # новая сущность в конце — таблицы дополняются
    assert found() == ["ivanov:a1", "petrov:a2"]
    add(state, "ip", T.IP, "10.1.2.5")
    assert found() == ["ivanov:a1", "petrov:a2", "010.001.002.005:ip"]
    state.entities["a1"].forms.append("vanya")              # новое написание прежней сущности — в её же списке
    assert found() == ["ivanov:a1", "petrov:a2", "vanya:a1", "010.001.002.005:ip"]
    state.entities["a2"].forms[0] = "sidorov"               # написание заменено на месте: та же длина списков
    assert found() == ["ivanov:a1", "vanya:a1", "sidorov:a2", "010.001.002.005:ip"]
    ops.unmask(state, "ivanov")
    assert found() == ["vanya:a1", "sidorov:a2", "010.001.002.005:ip"]
    state.rules.clear()
    assert found() == ["ivanov:a1", "vanya:a1", "sidorov:a2", "010.001.002.005:ip"]
    assert found(Settings(never=frozenset({"vanya"}))) == ["ivanov:a1", "sidorov:a2", "010.001.002.005:ip"]
    assert found(Settings(policies=default_policies() | {T.IP: Policy.OFF})) == ["ivanov:a1", "vanya:a1", "sidorov:a2"]
    assert found(Settings(always=(DictEntry(T.ORG, "contoso"),))) == [
        "ivanov:a1", "vanya:a1", "sidorov:a2", "010.001.002.005:ip", "contoso:None",
    ]
    assert found() == ["ivanov:a1", "vanya:a1", "sidorov:a2", "010.001.002.005:ip"]


def test_snapshot_is_checked_against_its_own_state(state, settings):
    """Снимок состояния, который проверяет egress вне замка чата, проверяется по своим сущностям, а не по таблицам
    живого состояния, собранным позже (и наоборот); подмена, выданная после снимка, вырезается только в живом."""
    add(state, "a1", T.ACCOUNT, "ivanov")
    snapshot = replace(state, entities=dict(state.entities), surrogates=dict(state.surrogates))
    add(state, "a2", T.ACCOUNT, "petrov")
    state.surrogates["petrov"] = Surrogate("a2", "petrov", "host")
    text = "ivanov petrov"
    assert leaked(text, state, settings) == [("ivanov", "a1")]
    assert leaked(text, snapshot, settings) == [("ivanov", "a1")]
    del state.surrogates["petrov"]
    assert leaked(text, snapshot, settings) == [("ivanov", "a1")]
    assert leaked(text, state, settings) == [("ivanov", "a1"), ("petrov", "a2")]
    assert leaked(text, snapshot, settings) == [("ivanov", "a1")]


def test_address_key_of_an_entity_added_later_wins_over_the_dictionary(state):
    """Ключ адреса — у сущности раньше, чем у словаря, как при сборке с начала, и когда сущность добавлена к прежним
    таблицам."""
    always = Settings(always=(DictEntry(T.IP, "10.1.2.5"),))
    add(state, "a1", T.ACCOUNT, "ivanov")
    assert leaked("010.001.002.005", state, always) == [("010.001.002.005", None)]
    add(state, "ip", T.IP, "10.1.2.5")
    text = "010.001.002.005"
    assert leaked(text, state, always) == [(text, "ip")] == fresh(text, state, always)


@pytest.mark.parametrize(
    "written, other, found",
    [
        ("2A00:1450:4010:0::0065", "x 2a00:1450:4010:0:0:0:0:65 y", "2a00:1450:4010:0:0:0:0:65"),
        ("2a00:1450:4010::65", "x 2a00:1450:4010:0000::0065, y", "2a00:1450:4010:0000::0065"),
        ("2a00:1450:4010::65", "Source:2A00:1450:4010:0::65: занят", "2A00:1450:4010:0::65"),
        ("10.1.2.5", "x 010.001.002.005 y", "010.001.002.005"),
        ("10.1.2.5", "маршрут 010.001.002.005/24", "010.001.002.005/24"),
    ],
    ids=["full", "padded", "after_label", "ipv4_zeros", "ipv4_with_prefix"],
)
def test_ip_address_is_found_in_a_notation_the_chat_has_not_seen(state, settings, written, other, found):
    """FINDINGS «Restore round of 15.10», (1): написания сущности — только записи, которые чат видел, а адрес бывает
    записан и иначе. Слой 3 разбирает любую запись, поэтому слабее была только вторая линия защиты."""
    sanitize(state, f"узел {written}", settings)
    [entity] = state.entities.values()
    assert leaked(other, state, settings) == [(found, entity.id)]


def test_network_and_dictionary_address_are_found_in_another_notation(state, settings):
    ops.mask(state, "2a00:1450:4010::/64", T.IP)
    sanitize(state, "сеть 2a00:1450:4010::/64", settings)
    [entity] = state.entities.values()
    assert leaked("сеть 2A00:1450:4010:0::/64", state, settings) == [("2A00:1450:4010:0::/64", entity.id)]
    always = Settings(always=(DictEntry(T.IP, "192.168.10.7"),))
    assert leaked("узел 192.168.010.007", state, always) == [("192.168.010.007", None)]


def test_written_notation_is_reported_once(state, settings):
    """Запись, которую нашло написание сущности, второй находкой по адресу не становится."""
    sanitize(state, "узел 2A00:1450:4010:0::0065 и 10.1.2.5", settings)
    text = "x 2A00:1450:4010:0::0065 и 2a00:1450:4010::65 и 10.1.2.5/24"
    assert [found for found, _ in leaked(text, state, settings)] == ["2A00:1450:4010:0::0065", "2a00:1450:4010::65", "10.1.2.5"]


@pytest.mark.parametrize(
    "change",
    [
        lambda state, settings: (ops.unmask(state, "10.1.2.5"), settings)[1],
        lambda state, settings: Settings(never=frozenset({"010.001.002.005"})),
        lambda state, settings: Settings(policies=default_policies() | {T.IP: Policy.OFF}),
    ],
    ids=["unmasked", "never_list", "policy_off"],
)
def test_open_address_in_another_notation_is_not_a_leak(state, settings, change):
    """С другой стороны: адрес, с которого сняли замену, из списка «никогда не скрывать» и тип с выключенной
    политикой — не утечка ни в какой записи, как и в написаниях (шаг 1)."""
    sanitize(state, "узел 10.1.2.5", settings)
    assert leaked("x 010.001.002.005 y", state, change(state, settings)) == []


@pytest.mark.parametrize("text, found", [
    (r'my $to = "ivanov\@contoso.ru";', r"ivanov\@contoso.ru"),
    (r"/^ivanov\@contoso\.ru$/", r"ivanov\@contoso\.ru"),
    (r'"ivanov\\@contoso.ru"', None),
], ids=["perl", "regex", "escaped-backslash"])
def test_known_email_written_with_an_escaped_at_is_a_leak(state, settings, text, found):
    """Ревью раунда 5, P3: адрес в строке Perl и PHP пишут через «\\@» — это тот же адрес, и проверка утечек находит
    известный. «\\\\@» — обратная косая и массив Perl, не «@»: такой записи адреса нет."""
    sanitize(state, "почта ivanov@contoso.ru", settings)
    [email] = state.entities.values()
    assert leaked(text, state, settings) == ([(found, email.id)] if found else [])


def test_replacement_and_other_addresses_are_not_leaks(state, settings):
    """Подмена в другой записи — подмена, как на шаге 1, даже если совпала с настоящим адресом другой сущности
    (позже в чате появился адрес, равный выданной подмене); адрес не из чата, адрес внутри цепочки через двоеточие
    и число, похожее на адрес, — не утечки."""
    sanitize(state, "узел 2a00:1450:4010::65 и 10.1.2.5", settings)
    fake = next(text for text, surrogate in state.surrogates.items() if surrogate.kind == "ip")
    state.entities["twin"] = Entity("twin", T.IP, 9, fake, fake, "detector", [fake])
    padded = ".".join(octet.zfill(3) for octet in fake.split("."))
    text = f"{padded}, 2001:0db8:0001::0001, 010.001.002.006, ab:cd:2a00:1450:4010:0:0:0:0:65, 1.2.3.4.5"
    assert leaked(text, state, settings) == []
