import ipaddress

import pytest

from cleaner.core.detect.base import load_builtin
from cleaner.core.detect.merge import MergedSpan
from cleaner.core.entities import ops
from cleaner.core.entities.resolve import Resolver, canonical_key
from cleaner.core.pipeline import sanitize
from cleaner.core.types import ChatState, DictEntry, Entity, Settings, Surrogate
from cleaner.core.types import EntityType as T

GENERIC = frozenset({"www", "mail"})


def resolve(
    state: ChatState, text: str, *spans: tuple[str, T], settings: Settings = Settings(), generic: frozenset[str] = GENERIC,
) -> list[str]:
    merged = [
        MergedSpan(text.index(value), text.index(value) + len(value), type_, ("infra",))
        for value, type_ in spans
    ]
    return [r.surrogate for r in Resolver(state, settings, text, generic).run(text, merged)]


def searched_forms(state: ChatState) -> set[str]:
    return {form for entity in state.entities.values() for form in entity.forms}


def test_labels_are_numbered_per_type_and_stay_the_same(state):
    text = "a@x.example b@x.example Иванов"
    spans = (("a@x.example", T.EMAIL), ("b@x.example", T.EMAIL), ("Иванов", T.PERSON))
    assert resolve(state, text, *spans) == ["<EMAIL_1>", "<EMAIL_2>", "<PERSON_1>"]
    assert resolve(state, "снова b@x.example", ("b@x.example", T.EMAIL)) == ["<EMAIL_2>"]


def test_canonical_keys_join_notations():
    assert canonical_key(T.PHONE, "+7 (916) 123-45-67") == canonical_key(T.PHONE, "89161234567")
    assert canonical_key(T.EMAIL, "Ivanov@Corp.Example") == "ivanov@corp.example"
    assert canonical_key(T.ACCOUNT, r"CONTOSO\Ivanov") == "ivanov"
    assert canonical_key(T.ORG, "ООО «Ромашка»") == canonical_key(T.ORG, "ромашка")
    assert canonical_key(T.PASSPORT, "45 08 123456") == canonical_key(T.PASSPORT, "4508 номер 123456")
    assert canonical_key(T.EMAIL, "Ivanov%40Contoso.ru") == canonical_key(T.EMAIL, "ivanov@contoso.ru")
    assert canonical_key(T.EMAIL, "i%2bivanov%40contoso.ru") == canonical_key(T.EMAIL, "i+ivanov@contoso.ru")
    assert canonical_key(T.PHONE, "9031112233") == canonical_key(T.PHONE, "+7 (903) 111-22-33")
    assert canonical_key(T.PHONE, "(903) 111-22-33") == canonical_key(T.PHONE, "8 903 111 22 33")
    assert canonical_key(T.PHONE, "+49 30 1234567") != canonical_key(T.PHONE, "+7 493 012-34-56")


def test_phone_entities_of_saved_chats_keep_their_labels(state):
    """Ключ десяти цифр без кода страны — с «7», как у «+7 …» и «8 …». Сущность, сохранённая со старым ключом (десять
    цифр), находится по написанию: ключи сохранённых чатов не переписываются, сравнение идёт по новому ключу."""
    assert resolve(state, "тел. 903 111-22-33", ("903 111-22-33", T.PHONE)) == ["<PHONE_1>"]
    [entity] = state.entities.values()
    entity.key = "9031112233"                       # так ключ записан до 09.11.2026
    assert resolve(state, "звоните +7 903 111-22-33", ("+7 903 111-22-33", T.PHONE)) == ["<PHONE_1>"]
    assert resolve(state, "или 9031112233", ("9031112233", T.PHONE)) == ["<PHONE_1>"]
    assert len(state.entities) == 1


def test_square_label_style(state):
    state.label_style = "square"
    assert resolve(state, "a@x.example", ("a@x.example", T.EMAIL)) == ["[[EMAIL_1]]"]


def test_host_names_keep_their_structure(state):
    text = "srv-dc01.msk.corp.contoso.ru, SRV-DC01, corp.contoso.ru, www.contoso.ru"
    spans = (
        ("srv-dc01.msk.corp.contoso.ru", T.HOST),
        ("SRV-DC01", T.HOST),
        ("corp.contoso.ru", T.HOST),
        ("www.contoso.ru", T.HOST),
    )
    assert resolve(state, text, *spans) == [
        "host-1.sub-2.sub-3.domain-1.example",
        "HOST-1",
        "sub-3.domain-1.example",
        "www.domain-1.example",
    ]
    searchable = {form for entity in state.entities.values() for form in entity.forms}
    assert "srv-dc01" in searchable and "corp" not in searchable


def test_netbios_domain_shares_the_number_with_its_dns_name(state):
    settings = Settings(always=(DictEntry(T.DOMAIN, "contoso.ru", ("CONTOSO",)),))
    spans = (("contoso.ru", T.DOMAIN), ("CONTOSO", T.DOMAIN))
    assert resolve(state, "contoso.ru CONTOSO", *spans, settings=settings) == ["domain-1.example", "DOMAIN-1"]


def test_aliases_of_a_host_entry_form_one_entity(state):
    """Обзор 1А, P1: варианты написания хоста из словаря — одна сущность (раздел 5.8)."""
    settings = Settings(always=(DictEntry(T.HOST, "srv-dc01", ("dc01",)),))
    spans = (("srv-dc01", T.HOST), ("dc01", T.HOST))
    assert resolve(state, "srv-dc01 dc01", *spans, settings=settings) == ["host-1", "host-1"]


def test_aliases_of_a_dotted_host_entry_share_its_host_part(state):
    """Находка «dotted dictionary aliases split»: короткий и полный варианты записи — одна часть host-N.

    Домен варианта «dc01.contoso.local» свой: иначе contoso.local у всех узлов восстанавливался бы как contoso.ru.
    """
    entry = DictEntry(T.HOST, "srv-dc01.contoso.ru", ("dc01", "DC01.contoso.local"))
    text = "srv-dc01.contoso.ru, dc01 и DC01.contoso.local"
    spans = (("srv-dc01.contoso.ru", T.HOST), ("dc01", T.HOST), ("DC01.contoso.local", T.HOST))
    assert resolve(state, text, *spans, settings=Settings(always=(entry,))) == [
        "host-1.domain-1.example", "host-1", "HOST-1.domain-2.example",
    ]
    assert state.surrogates["HOST-1.domain-2.example"].original == "DC01.contoso.local"


def test_alias_whose_lead_part_is_of_another_kind_keeps_its_own_entity(state):
    """Вариант, у которого первой стоит не часть имени, а домен, с частью имени не сводится."""
    entry = DictEntry(T.HOST, "srv-dc01.contoso.ru", ("mail.contoso.ru",))
    text = "srv-dc01.contoso.ru и mail.contoso.ru"
    spans = (("srv-dc01.contoso.ru", T.HOST), ("mail.contoso.ru", T.HOST))
    assert resolve(state, text, *spans, settings=Settings(always=(entry,))) == [
        "host-1.domain-1.example", "mail.domain-1.example",
    ]


def test_tech_words_in_front_of_a_domain_stay_and_are_not_searched(state):
    """Находка «Detection: false positives…»: после k8s.contoso.ru слово k8s не скрывается во всём тексте."""
    words = ("k8s", "k3s", "s3", "i18n", "l10n", "x64", "x86", "amd64", "arm64", "win10", "win11", "ipv4", "ipv6", "utf8")
    names = [f"{word}.contoso.ru" for word in words]
    text = " ".join(names)
    surrogates = resolve(state, text, *((name, T.HOST) for name in names), generic=load_builtin().generic_labels)
    assert surrogates == [f"{word}.domain-1.example" for word in words]
    assert searched_forms(state) == {"contoso.ru"}


def test_short_host_names_with_digits_stay_searchable(state):
    labels = ("srv-db02", "dc01", "web-03", "k8s-01", "win10-pc", "s3a")
    names = [f"{label}.contoso.ru" for label in labels]
    text = " ".join(names)
    surrogates = resolve(state, text, *((name, T.HOST) for name in names), generic=load_builtin().generic_labels)
    assert surrogates == [f"host-{number}.domain-1.example" for number in range(1, len(labels) + 1)]
    assert searched_forms(state) == {"contoso.ru", *labels}


def test_addresses_macs_and_sids(state):
    sid = "S-1-5-21-1004336348-1177238915-682003330-1104"
    text = f"10.1.2.5 10.1.2.77 00:1A:2B:3C:4D:5E 00-1a-2b-3c-4d-5e {sid}"
    a, b, mac_colon, mac_dash, fake_sid = resolve(
        state,
        text,
        ("10.1.2.5", T.IP),
        ("10.1.2.77", T.IP),
        ("00:1A:2B:3C:4D:5E", T.MAC),
        ("00-1a-2b-3c-4d-5e", T.MAC),
        (sid, T.SID),
    )
    assert a.startswith("10.") and a != "10.1.2.5"
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    assert a.endswith(".5") and b.endswith(".77")
    assert (mac_colon, mac_dash) == ("02:00:00:00:00:01", "02-00-00-00-00-01")
    assert fake_sid == "S-1-5-21-1111111111-2222222222-3333333331-1104"


def test_address_colliding_with_an_open_value_gets_a_label(state):
    fake = resolve(state, "10.1.2.5", ("10.1.2.5", T.IP))[0]
    other = ChatState(chat_id="other", net_key=state.net_key)
    settings = Settings(never=frozenset({fake}))
    assert resolve(other, "10.1.2.5", ("10.1.2.5", T.IP), settings=settings) == ["<IP_1>"]


def _padded(address: str) -> str:
    return ".".join(f"{int(octet):03d}" for octet in address.split("."))


@pytest.mark.parametrize(
    "real, listed",
    [
        ("10.1.2.5", None),                                     # частная подмена, записанная с нулями
        ("8.8.8.8", "203.000.113.001"),
        ("2a00:1450:4010::65", "2001:0db8:0001:0000:0000:0000:0000:0001"),
        ("2a00:1450:4010::65", "2001:db8:1:0::1/64"),
    ],
)
def test_address_colliding_with_an_open_value_written_otherwise_gets_a_label(state, real, listed):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: открытое значение сравнивалось с подменой как текст,
    и адрес списка «никогда не скрывать» в другой записи не останавливал совпавшую с ним подмену."""
    if listed is None:
        listed = _padded(resolve(state, real, (real, T.IP))[0])
        state = ChatState(chat_id="other", net_key=state.net_key)
    assert resolve(state, real, (real, T.IP), settings=Settings(never=frozenset({listed}))) == ["<IP_1>"]


@pytest.mark.parametrize("listed", ["2001:0db8:0001::0002", "203.000.113.002", "srv-dc01.contoso.ru"])
def test_open_value_of_another_address_or_not_an_address_leaves_the_surrogate(state, listed):
    surrogates = resolve(state, "8.8.8.8 и 2a00:1450:4010::65", ("8.8.8.8", T.IP), ("2a00:1450:4010::65", T.IP),
                         settings=Settings(never=frozenset({listed})))
    assert surrogates == ["203.0.113.1", "2001:db8:1::1"]


@pytest.mark.parametrize(
    "text, real, fake",
    [
        ("Source:2001:db8:1::1, узел 2a00:1450:4010::65", "2a00:1450:4010::65", "2001:db8:1::2"),
        ("IPv6:2001:db8:1::1 и 2a00:1450:4010::65", "2a00:1450:4010::65", "2001:db8:1::2"),
        ("адрес 2001:db8:1::1: занят, 2a00:1450:4010::65", "2a00:1450:4010::65", "2001:db8:1::2"),
        ("Source:203.0.113.1, DNS 8.8.8.8", "8.8.8.8", "203.0.113.2"),
    ],
)
def test_surrogate_written_after_a_label_and_a_colon_is_taken(state, text, real, fake):
    """Финальный обзор партии: проверка совпадения с адресом в тексте не видела «Source:2001:db8:1::1»
    (адрес сразу за подписью и двоеточием), хотя слой 3 и восстановление его находят."""
    assert resolve(state, text, (real, T.IP)) == [fake]


@pytest.mark.parametrize(
    "text, real, fake",
    [
        ("было 2001:0db8:0001::0001, узел 2a00:1450:4010::65", "2a00:1450:4010::65", "2001:db8:1::2"),
        ("было 2001:DB8:1:0:0:0:0:1, узел 2a00:1450:4010::65", "2a00:1450:4010::65", "2001:db8:1::2"),
        ("было 203.000.113.001, DNS 8.8.8.8", "8.8.8.8", "203.0.113.2"),
        ("интерфейс 203.0.113.1/24, DNS 8.8.8.8", "8.8.8.8", "203.0.113.2"),
    ],
)
def test_surrogate_equal_to_an_address_written_otherwise_is_taken(state, text, real, fake):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: проверка сравнивала запись, а не адрес, и подмена
    2001:db8:1::1 совпадала с «2001:0db8:0001::0001» текста — ответ не мог их различить."""
    assert resolve(state, text, (real, T.IP)) == [fake]


@pytest.mark.parametrize(
    "text, real, fake",
    [
        ("было 2001:db8:1::10, узел 2a00:1450:4010::65", "2a00:1450:4010::65", "2001:db8:1::1"),
        ("было 203.0.113.10/24, DNS 8.8.8.8", "8.8.8.8", "203.0.113.1"),
    ],
)
def test_surrogate_next_to_another_address_is_issued(state, text, real, fake):
    assert resolve(state, text, (real, T.IP)) == [fake]


def test_ipv6_network_keeps_its_written_notation_for_restoring(state):
    """Решение владельца 15.10.2026: сеть IPv6 восстанавливается так, как написана; ключ сущности — канонический."""
    [fake] = resolve(state, "сеть 2A00:1450:4010:0::/64", ("2A00:1450:4010:0::/64", T.IP))
    [entity] = state.entities.values()
    assert (entity.key, entity.restore_value) == ("2a00:1450:4010::/64", "2A00:1450:4010:0::/64")
    assert state.surrogates[fake].original == "2A00:1450:4010:0::/64"


def test_ipv6_given_a_label_instead_of_a_surrogate_keeps_its_written_notation(state):
    settings = Settings(never=frozenset({"2001:db8:1::1"}))
    assert resolve(state, "узел 2A00:1450:4010:0::0065", ("2A00:1450:4010:0::0065", T.IP), settings=settings) == ["<IP_1>"]
    [entity] = state.entities.values()
    assert (entity.key, entity.restore_value) == ("2a00:1450:4010::65", "2A00:1450:4010:0::0065")


@pytest.mark.parametrize(
    "network, fake",
    [("2a00:1450:4010::/64", "2001:db8:1::1/64"), ("8.8.8.0/24", "203.0.113.1/24")],
    ids=["ipv6", "public_ipv4"],
)
def test_network_from_a_rule_keeps_its_prefix_in_the_surrogate(state, network, fake):
    """FINDINGS «Restore round of 15.10», остаток (2): сеть IPv6 и публичная IPv4 из правила получали подмену-адрес без
    длины префикса, и модель не видела, что это сеть."""
    assert resolve(state, f"сеть {network}", (network, T.IP)) == [fake]
    assert state.surrogates[fake].original == network
    assert state.surrogates[fake.split("/")[0]].original == network.split("/")[0]


@pytest.mark.parametrize(
    "text, network, fake",
    [
        ("сеть 2a00:1450:4010::/64, пример 2001:db8:1::1", "2a00:1450:4010::/64", "2001:db8:1::2/64"),
        ("сеть 8.8.8.0/24, пример 203.0.113.1", "8.8.8.0/24", "203.0.113.2/24"),
    ],
    ids=["ipv6", "public_ipv4"],
)
def test_network_surrogate_skips_an_address_of_the_text_equal_to_its_address(state, text, network, fake):
    """С другой стороны: подмена сети 2001:db8:1::1/64 восстанавливается и адресом без длины префикса, и пример
    2001:db8:1::1 из того же текста восстанавливался бы адресом сети. С текстом сравниваются обе записи подмены."""
    assert resolve(state, text, (network, T.IP)) == [fake]


@pytest.mark.parametrize("network", ["10.1.0.0/16", "2a00:1450:4010::/64", "8.8.8.0/24"])
def test_network_surrogate_equal_to_an_open_address_without_its_prefix_gets_a_label(state, network):
    """Находка ревью раунда IP (15.10): подмена сети сверялась с открытыми адресами только целиком. Правило 10.1.0.0/16 и
    «никогда не скрывать» 10.90.0.0 давали подмену 10.90.0.0/16, и восстановление превращало открытый 10.90.0.0 в
    10.1.0.0. С открытыми адресами сравниваются обе записи подмены."""
    [fake] = resolve(ChatState(chat_id="other", net_key=state.net_key), f"сеть {network}", (network, T.IP))
    address = ipaddress.ip_address(fake.split("/")[0])
    opened = Settings(never=frozenset({str(address)}))
    assert resolve(state, f"сеть {network}", (network, T.IP), settings=opened) == ["<IP_1>"]
    neighbour = Settings(never=frozenset({str(address + 1)}))
    assert resolve(ChatState(chat_id="another", net_key=state.net_key), f"сеть {network}", (network, T.IP),
                   settings=neighbour) == [fake]


def test_address_inside_a_longer_colon_chain_is_not_taken(state):
    assert resolve(state, "ab:cd:2001:db8:1::1 и 2a00:1450:4010::65", ("2a00:1450:4010::65", T.IP)) == [
        "2001:db8:1::1"
    ]


def test_merged_key_points_to_the_kept_entity(state):
    first = resolve(state, "Иванов", ("Иванов", T.PERSON))
    kept = next(iter(state.entities.values()))
    state.key_alias["PERSON:иванов и."] = kept.id
    assert resolve(state, "Иванов И.", ("Иванов И.", T.PERSON)) == first
    assert kept.forms == ["Иванов", "Иванов И."]


def old_style_state() -> ChatState:
    """Состояние, записанное до 15.10: ключи посчитаны нормализацией, которая оставляла невидимые знаки. У ORG мягкий
    перенос остался в ключе, у ADDRESS стал пробелом (знаки препинания ключа адреса — пробелы)."""
    state = ChatState(chat_id="old", net_key=bytes(range(32)))
    for type_, key, form in (
        (T.ORG, "ро\u00adмашка", "ООО «Ро\u00adмашка»"),
        (T.ADDRESS, "ул лени на д 5", "ул. Лени\u00adна, д. 5"),
        (T.PERSON, "ива\u200bнов", "Ива\u200bнов"),
    ):
        entity = Entity(type_.value.lower(), type_, 1, key, form, "detector", [form])
        state.entities[entity.id] = entity
        label = f"<{type_.value}_1>"
        state.surrogates[label] = Surrogate(entity.id)
        state.issued[f"{entity.id}|label"] = label
        state.counters[type_.value] = 1
    return state


def test_entity_stored_with_invisible_characters_in_its_key_keeps_its_label():
    """FINDINGS «Small gaps left by the findings batch of 15.10»: после того как нормализация стала выбрасывать
    невидимые знаки, сущность из такого значения получала при следующей очистке новый ключ и новую метку."""
    state = old_style_state()
    text = "Договор с ООО «Ро\u00adмашка», ул. Лени\u00adна, д. 5; снова ООО «Ромашка», Ива\u200bнов и Иванов"
    result = sanitize(state, text, Settings())
    assert result.sanitized == "Договор с <ORG_1>, <ADDRESS_1>; снова <ORG_1>, <PERSON_1> и <PERSON_1>"
    assert len(state.entities) == 3 and state.counters == {"ORG": 1, "ADDRESS": 1, "PERSON": 1}


def test_old_style_key_merged_into_another_entity_leads_to_it():
    """Та же находка: значение, влитое объединением до 15.10, ведёт к оставленной сущности, а не к влитой."""
    state = old_style_state()
    keep = Entity("keep", T.ORG, 2, "ромашка-холдинг", "Ромашка-Холдинг", "detector", ["Ромашка-Холдинг"])
    state.entities[keep.id] = keep
    state.surrogates["<ORG_2>"] = Surrogate(keep.id)
    state.issued["keep|label"] = "<ORG_2>"
    state.counters["ORG"] = 2
    ops.merge_entities(state, keep.id, "org")
    assert sanitize(state, "Счёт от ООО «Ромашка»", Settings()).sanitized == "Счёт от <ORG_2>"


def test_value_of_the_wrong_shape_falls_back_to_a_label(state):
    assert resolve(state, "не адрес", ("не адрес", T.IP)) == ["<IP_1>"]


def test_network_of_an_impossible_length_gets_a_label_and_leaves_nothing_behind(state):
    """Находка «Core: unvalidated inputs»: подмена, сорвавшаяся на середине, оставляла сущность и номер."""
    assert resolve(state, "сеть 10.0.0.0/040", ("10.0.0.0/040", T.IP)) == ["<IP_1>"]
    assert resolve(state, "сеть 10.1.2.5/33", ("10.1.2.5/33", T.IP)) == ["<IP_2>"]
    assert len(state.entities) == 2 and state.counters == {"IP": 2}


def test_network_of_a_possible_length_keeps_its_replacement(state):
    network, host = resolve(state, "10.1.0.0/16 и 10.1.2.5/32", ("10.1.0.0/16", T.IP), ("10.1.2.5/32", T.IP))
    assert network.startswith("10.") and network.endswith(".0.0/16") and network != "10.1.0.0/16"
    assert host.startswith("10.") and host.endswith(".5/32")
