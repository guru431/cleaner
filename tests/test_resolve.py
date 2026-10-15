from cleaner.core.detect.merge import MergedSpan
from cleaner.core.entities.resolve import Resolver, canonical_key
from cleaner.core.types import ChatState, DictEntry, Settings
from cleaner.core.types import EntityType as T

GENERIC = frozenset({"www", "mail"})


def resolve(state: ChatState, text: str, *spans: tuple[str, T], settings: Settings = Settings()) -> list[str]:
    merged = [
        MergedSpan(text.index(value), text.index(value) + len(value), type_, ("infra",))
        for value, type_ in spans
    ]
    return [r.surrogate for r in Resolver(state, settings, text, GENERIC).run(text, merged)]


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


def test_merged_key_points_to_the_kept_entity(state):
    first = resolve(state, "Иванов", ("Иванов", T.PERSON))
    kept = next(iter(state.entities.values()))
    state.key_alias["PERSON:иванов и."] = kept.id
    assert resolve(state, "Иванов И.", ("Иванов И.", T.PERSON)) == first
    assert kept.forms == ["Иванов", "Иванов И."]


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
