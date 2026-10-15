import re

import pytest

from cleaner.core import leakcheck
from cleaner.core.detect import infra
from cleaner.core.detect.base import DetectorError
from cleaner.core.entities import ops
from cleaner.core.pipeline import Layers, sanitize
from cleaner.core.restore import restore
from cleaner.core.types import ChatRule, DictEntry, Policy, Settings, Span, Surrogate, default_policies
from cleaner.core.types import EntityType as T


def test_end_to_end(state, settings):
    text = r"CONTOSO\ivanov пишет с srv-dc01.corp.contoso.ru (10.1.2.5), пароль: Qwerty123!"
    result = sanitize(state, text, settings)
    ip = next(s.surrogate for s in result.spans if state.entities[s.entity_id].type is T.IP)
    assert ip.startswith("10.") and ip.endswith(".5")
    assert result.sanitized == (
        rf"DOMAIN-1\<ACCOUNT_1> пишет с host-1.sub-2.domain-2.example ({ip}), пароль: <SECRET_1>"
    )
    assert result.deliverable


def test_short_host_name_in_the_same_text_is_linked(state, settings):
    result = sanitize(state, "srv-dc01.corp.contoso.ru упал; Server=SRV-DC01;", settings)
    assert "Server=HOST-1;" in result.sanitized


def test_address_equal_to_an_earlier_surrogate_is_treated_as_already_replaced(state, settings):
    fake = sanitize(state, "узел 10.1.2.5", settings).spans[0].surrogate
    again = sanitize(state, f"проверьте {fake}", settings)
    assert again.sanitized == f"проверьте {fake}"
    assert [notice.code for notice in again.notices] == ["surrogate_in_input"]


def test_sanitizing_the_same_text_twice_changes_nothing(state, settings):
    text = r"CONTOSO\ivanov, i.ivanov@contoso.ru, 10.1.2.5, srv-dc01.corp.contoso.ru"
    first = sanitize(state, text, settings)
    counts = (len(state.entities), len(state.surrogates))
    second = sanitize(state, text, settings)
    assert second.sanitized == first.sanitized
    assert (len(state.entities), len(state.surrogates)) == counts


def test_crlf_and_astral_characters_do_not_shift_replacements(state, settings):
    text = "Готово 🎉\r\nПочта: a@x.example\r\n😀 адрес 10.1.2.5 🎯"
    result = sanitize(state, text, settings)
    ip = result.spans[-1].surrogate
    assert result.sanitized == f"Готово 🎉\r\nПочта: <EMAIL_1>\r\n😀 адрес {ip} 🎯"


@pytest.mark.parametrize("text", ["", "Просто текст без чувствительных данных."])
def test_text_without_sensitive_data_is_returned_unchanged(state, settings, text):
    result = sanitize(state, text, settings)
    assert (result.sanitized, result.spans, result.notices, result.leaks) == (text, [], [], [])
    assert state.entities == {}


def test_dictionary_value_is_one_entity_whatever_the_spacing_and_spelling(state):
    """Обзор 1А, P1: пробелы и «ё/е» не должны ни прятать значение, ни делить его на две метки."""
    settings = Settings(always=(DictEntry(T.PERSON, "Иванов Иван Иванович", ("Семёнов",)),))
    result = sanitize(state, "Иванов Иван  Иванович, он же Семенов", settings)
    assert result.sanitized == "<PERSON_1>, он же <PERSON_1>"
    assert result.deliverable


def test_url_credentials_keep_the_host_mapping(state, settings):
    """Обзор 1А, P2: правило e-mail не должно захватывать «пароль@хост» из адреса."""
    result = sanitize(state, "REDACTED_DB_URL_CREDENTIALSdb01.contoso.ru:5432/crm", settings)
    assert result.sanitized == "postgres://app:<SECRET_1>@host-1.domain-1.example:5432/crm"


def test_login_at_an_address_is_an_account_and_the_address_keeps_its_mapping(state, settings):
    result = sanitize(state, "ssh ivanov@10.1.2.5", settings)
    ip = next(s.surrogate for s in result.spans if state.entities[s.entity_id].type is T.IP)
    assert result.sanitized == f"ssh <ACCOUNT_1>@{ip}"


def test_new_label_skips_the_number_of_a_foreign_one(state, settings):
    """Обзор 1А, P2: метка из другого чата и новая метка не должны совпасть."""
    result = sanitize(state, "Коллега <EMAIL_1> просил написать на b@x.example", settings)
    assert result.sanitized == "Коллега <EMAIL_1> просил написать на <EMAIL_2>"
    assert restore(state, result.sanitized, settings).text == "Коллега <EMAIL_1> просил написать на b@x.example"


def test_opened_value_does_not_block_delivery(state, settings):
    """Обзор 1А, P2: после «открыть» проверка утечек не должна находить части открытого значения."""
    sanitize(state, "узел srv-dc01.corp.contoso.ru", settings)
    ops.unmask(state, "srv-dc01.corp.contoso.ru")
    result = sanitize(state, "узел srv-dc01.corp.contoso.ru", settings)
    assert result.sanitized == "узел srv-dc01.corp.contoso.ru"
    assert result.deliverable


def test_network_surrogate_written_without_its_prefix_restores_to_the_network(state, settings):
    """Обзор 1А, P2."""
    fake = sanitize(state, "сеть 10.1.0.0/16", settings).spans[0].surrogate.split("/")[0]
    restored = restore(state, f"сеть {fake} маска 255.255.0.0", settings)
    assert restored.text == "сеть 10.1.0.0 маска 255.255.0.0"


def test_public_surrogate_does_not_repeat_an_address_of_the_text(state, settings):
    """Обзор 1А, P2 (FR-5.7): документационный адрес в тексте и подмена не совпадают."""
    text = "Пример из документации: 203.0.113.1. Наш адрес 85.143.10.20."
    result = sanitize(state, text, settings)
    assert result.sanitized == "Пример из документации: 203.0.113.1. Наш адрес 203.0.113.2."
    assert restore(state, result.sanitized, settings).text == text


def test_surrogate_does_not_repeat_an_address_of_the_text_in_another_notation(state, settings):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: подмена совпадала с адресом текста в полной записи,
    и восстановление возвращало чужой адрес вместо документационного."""
    text = "было 2001:0db8:0001::0001, узел 2a00:1450:4010::65"
    result = sanitize(state, text, settings)
    assert result.sanitized == "было 2001:0db8:0001::0001, узел 2001:db8:1::2"
    assert restore(state, result.sanitized, settings).text == text


@pytest.mark.parametrize(
    "text",
    ["узел 2A00:1450:4010:0::0065", "узел 2a00:1450:4010:0:0:0:0:65", "Source:2A00:1450:4010::65."],
    ids=["padded", "full", "label"],
)
def test_ipv6_is_restored_as_written(state, settings, text):
    """Решение владельца 15.10.2026: IPv6 восстанавливается в записи из текста, а не в канонической (2a00:1450:4010::65)."""
    result = sanitize(state, text, settings)
    assert "2001:db8:1::1" in result.sanitized
    assert restore(state, result.sanitized, settings).text == text


def test_two_notations_of_one_ipv6_are_one_entity_restored_as_first_written(state, settings):
    result = sanitize(state, "узел 2A00:1450:4010:0::0065, он же 2a00:1450:4010::65", settings)
    assert result.sanitized == "узел 2001:db8:1::1, он же 2001:db8:1::1"
    assert sanitize(state, "снова 2a00:1450:4010:0:0:0:0:65", settings).sanitized == "снова 2001:db8:1::1"
    assert len(state.entities) == 1
    assert restore(state, "ответ: 2001:db8:1::1", settings).text == "ответ: 2A00:1450:4010:0::0065"


def test_zero_padded_ipv4_is_still_restored_in_the_plain_notation(state, settings):
    """Раздел 5.4: у IPv4 запись с нулями впереди восстанавливается простой — и адрес, и сеть без длины префикса."""
    address = sanitize(state, "узел 010.001.002.005", settings).sanitized
    assert restore(state, address, settings).text == "узел 10.1.2.5"
    network = sanitize(state, "сеть 010.001.000.000/16", settings).sanitized
    assert restore(state, network, settings).text == "сеть 10.1.0.0/16"
    assert restore(state, network.split("/")[0], settings).text == "сеть 10.1.0.0"


@pytest.mark.parametrize(
    "text, rules",
    [
        ("сеть 192.168.0.0/23, интерфейс 192.168.1.0/23", ()),
        ("интерфейс 192.168.1.0/23, сеть 192.168.0.0/23", ()),
        ("сеть 10.1.0.0/16, узел 10.1.132.0/16", ()),
        ("сеть 192.168.0.0/23, интерфейс 192.168.1.0/23", ("192.168.0.0/23", "192.168.1.0/23")),
    ],
    ids=["network_first", "address_first", "short_prefix", "both_by_rules"],
)
def test_address_whose_surrogate_restores_to_another_address_gets_a_label(state, settings, text, rules):
    """Ревью раунда IP (15.10): «192.168.1.0/23» — узел в верхней половине /23, слой 3 берёт его без длины префикса, и
    его подмена совпадала с подменой сети без длины префикса — в тексте выходили две «192.168.94.0/23», и обе
    восстанавливались сетью. Подмена, которая уже восстанавливается в другой адрес, второй раз не выдаётся (6.2)."""
    for rule in rules:
        ops.mask(state, rule, T.IP)
    result = sanitize(state, text, settings)
    first, second = (word.rstrip(",") for word in result.sanitized.split()[1::2])
    assert first != second and "<IP_" in result.sanitized and result.deliverable
    assert restore(state, result.sanitized, settings).text == text
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized


@pytest.mark.parametrize(
    "text, rules, octets",
    [
        ("сеть 10.1.0.0/16, половины 10.1.0.0/17 и 10.1.128.0/17", (), 2),
        ("сеть 10.1.2.0/24, шлюз 10.1.2.0 и узел 10.1.2.5", ("10.1.2.0/24",), 3),
    ],
    ids=["halves", "same_address"],
)
def test_networks_and_addresses_of_one_subnet_keep_their_surrogates(state, settings, text, rules, octets):
    """С другой стороны: у подмен сетей 10.90.0.0/16 и 10.90.0.0/17 (верхняя половина) совпал только адрес без длины
    префикса, а его не выдавали никому; шлюз 10.1.2.0 и сеть 10.1.2.0/24 — один адрес. Меток нет, подсети те же (FR-5.4)."""
    for rule in rules:
        ops.mask(state, rule, T.IP)
    result = sanitize(state, text, settings)
    assert "<IP_" not in result.sanitized
    assert len({span.surrogate.split("/")[0].rsplit(".", 4 - octets)[0] for span in result.spans}) == 1
    assert restore(state, result.sanitized, settings).text == text


@pytest.mark.parametrize("leaked", ["2a00:1450:4010::65", "2A00:1450:4010:0::0065"], ids=["canonical", "written"])
def test_leak_check_finds_an_ipv6_in_the_canonical_and_in_the_written_notation(state, settings, leaked):
    """Запись из текста хранится для восстановления, но каноническая остаётся искомой: проверка утечек
    по-прежнему находит адрес, записанный не так, как в первом тексте."""
    sanitize(state, "узел 2A00:1450:4010:0::0065", settings)
    assert len(leakcheck.check(f"x {leaked} y", state, settings)) == 1


def test_ipv6_of_a_chat_saved_with_the_canonical_notation_still_restores_to_it(state, settings):
    """Чаты, сохранённые до 15.10.2026, хранят каноническую запись: она и восстанавливается, без миграции."""
    sanitize(state, "узел 2A00:1450:4010:0::0065", settings)
    [entity] = state.entities.values()
    entity.restore_value, entity.forms = "2a00:1450:4010::65", ["2a00:1450:4010::65"]
    state.surrogates["2001:db8:1::1"] = Surrogate(entity.id, "2a00:1450:4010::65", "ip6")
    assert sanitize(state, "снова 2A00:1450:4010:0::0065", settings).sanitized == "снова 2001:db8:1::1"
    assert len(state.entities) == 1
    assert restore(state, "ответ: 2001:db8:1::1", settings).text == "ответ: 2a00:1450:4010::65"


def test_sanitized_text_pasted_back_changes_nothing(state, settings):
    """Обзор 1А, P2 (FR-5.9): своя замена в другом виде записи — всё равно своя."""
    text = (
        "SID S-1-5-21-1004336348-1177238915-682003330-1104, MAC 00:1A:2B:3C:4D:5E, "
        "узел srv-dc01.corp.contoso.ru, почта i.ivanov@contoso.ru, адрес 10.1.2.5, "
        "IPv6 2a00:1450:4010::65"
    )
    first = sanitize(state, text, settings)
    counts = (len(state.entities), len(state.surrogates))
    mac = next(s.surrogate for s in first.spans if state.entities[s.entity_id].type is T.MAC)
    pasted = f"{first.sanitized}; {mac.replace(':', '-')}; postmaster@domain-1.example"
    second = sanitize(state, pasted, settings)
    assert second.sanitized == pasted
    assert (len(state.entities), len(state.surrogates)) == counts


def test_foreign_label_is_reported_and_left_alone(state, settings):
    result = sanitize(state, "В шаблоне стоит <PERSON_7>", settings)
    assert result.sanitized == "В шаблоне стоит <PERSON_7>"
    assert [notice.code for notice in result.notices] == ["foreign_label"]
    assert "<PERSON_7>" in state.foreign_labels


def test_own_label_pasted_back_creates_nothing(state, settings):
    sanitize(state, "почта a@x.example", settings)
    result = sanitize(state, "ответьте на <EMAIL_1>", settings)
    assert result.sanitized == "ответьте на <EMAIL_1>"
    assert len(state.entities) == 1


@pytest.mark.parametrize(
    "listed, text",
    [
        ("2a00:1450:4010:0:0:0:0:65", "узел 2a00:1450:4010::65"),
        ("2a00:1450:4010::65", "узел 2A00:1450:4010:0::0065"),
        ("010.001.002.005", "узел 10.1.2.5"),
        ("10.1.2.5", "узел 010.001.002.005"),
        ("10.1.2.0/24", "сеть 10.1.2.0/24"),
    ],
)
def test_never_listed_address_written_otherwise_stays_open(state, settings, listed, text):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: список «никогда не скрывать» сравнивался с адресом
    текста как запись. Адрес скрывался и до записи в список — у его сущности есть написание, и проверка утечек
    не должна принять открытый адрес за утечку."""
    sanitize(state, text, settings)
    result = sanitize(state, text, Settings(never=frozenset({listed})))
    assert (result.sanitized, result.deliverable) == (text, True)


def test_unmasked_address_written_otherwise_stays_open(state, settings):
    sanitize(state, "узел 2a00:1450:4010::65", settings)
    ops.unmask(state, "2a00:1450:4010:0:0:0:0:65")
    result = sanitize(state, "узел 2a00:1450:4010::65", settings)
    assert (result.sanitized, result.deliverable) == ("узел 2a00:1450:4010::65", True)


@pytest.mark.parametrize(
    "listed, text",
    [("2a00:1450:4010::66", "узел 2a00:1450:4010::65"), ("10.1.2.50", "узел 10.1.2.5"), ("10.1.2.0/24", "узел 10.1.2.5")],
)
def test_never_listed_address_does_not_open_another_one(state, listed, text):
    result = sanitize(state, text, Settings(never=frozenset({listed})))
    assert result.sanitized != text and result.deliverable


def test_manual_rules(state, settings):
    state.rules.append(ChatRule("mask", "Проект Заря", T.TERM))
    state.rules.append(ChatRule("unmask", "10.1.2.5"))
    result = sanitize(state, "Проект Заря развёрнут на 10.1.2.5", settings)
    assert result.sanitized == "<TERM_1> развёрнут на 10.1.2.5"


def test_blocking_policy_makes_the_result_undeliverable(state):
    settings = Settings(policies=default_policies() | {T.CARD: Policy.BLOCK})
    result = sanitize(state, "карта 4111 1111 1111 1111", settings)
    assert result.sanitized == "карта <CARD_1>"
    assert [state.entities[s.entity_id].type for s in result.blocked] == [T.CARD]
    assert not result.deliverable


def test_failing_layer_stops_sanitizing(state, settings, monkeypatch):
    def broken(text, ctx):
        raise RuntimeError("слой сломан")

    monkeypatch.setattr(infra, "detect", broken)
    with pytest.raises(RuntimeError):
        sanitize(state, "узел 10.1.2.5", settings)


def test_leakcheck_finds_a_planted_original_and_ignores_surrogates(state, settings):
    result = sanitize(state, "Узел srv-dc01.corp.contoso.ru, почта admin@contoso.ru", settings)
    assert leakcheck.check(result.sanitized, state, settings) == []
    planted = result.sanitized + " см. также contoso.ru"
    assert [planted[leak.start:leak.end] for leak in leakcheck.check(planted, state, settings)] == ["contoso.ru"]


def test_login_in_a_url_is_masked_and_the_host_keeps_its_mapping(state, settings):
    result = sanitize(state, "git clone https://ivanov@git.contoso.ru/team/repo.git", settings)
    assert result.sanitized == "git clone https://<ACCOUNT_1>@host-1.domain-1.example/team/repo.git"
    assert restore(state, result.sanitized, settings).text == "git clone https://ivanov@git.contoso.ru/team/repo.git"


def test_new_values_next_to_an_issued_surrogate_are_masked(state, settings):
    """Обзор пакета исправлений 1А, P1: часть составной записи вне выданной замены скрывается."""
    sanitize(state, r"Сервер srv-dc01.contoso.ru, учётка CONTOSO\ivanov", settings)
    assert sanitize(state, "Писал с petrov@domain-1.example", settings).sanitized == (
        "Писал с <ACCOUNT_2>@domain-1.example"
    )
    assert sanitize(state, "Пишу с ivanov@domain-1.example", settings).sanitized == "Пишу с <ACCOUNT_1>@domain-1.example"
    assert sanitize(state, "Проверь host-1.fabrikam.ru", settings).sanitized == "Проверь host-1.domain-3.example"
    assert sanitize(state, "CN=host-1,OU=Servers,DC=fabrikam,DC=local", settings).sanitized == "CN=host-1,<DN_1>"
    assert restore(state, "Напишите на <ACCOUNT_2>@domain-1.example", settings).text == (
        "Напишите на petrov@contoso.ru"
    )


@pytest.mark.parametrize("retype, text, expected", [
    ("host", "Проверь <TERM_1>.fabrikam.ru", "Проверь <TERM_1>.domain-2.example"),
    ("host", "Проверь srv-db02.<TERM_1>.domain-1.example", "Проверь host-2.<TERM_1>.domain-1.example"),
    ("host", "Проверь <ORG_7>.fabrikam.ru", "Проверь <ORG_7>.domain-2.example"),
    ("domain", "Проверь <ORG_1>.fabrikam.ru", "Проверь <ORG_1>.domain-2.example"),
    ("domain", "Проверь srv-db02.<ORG_1>", "Проверь host-2.<ORG_1>"),
    ("domain", "Проверь srv-db02.host-1.<ORG_1>", "Проверь host-2.host-1.<ORG_1>"),
    ("host", "Проверь <TERM_1>.corp.domain-1.example, corp wiki", "Проверь <TERM_1>.sub-2.domain-1.example, corp wiki"),
    ("host", "Проверь <TERM_1>.corp.fabrikam.ru", "Проверь <TERM_1>.sub-2.domain-2.example"),
], ids=[
    "domain-after", "part-before", "foreign-label", "domain-after-org", "part-before-org", "part-before-name",
    "part-between", "name-after",
])
def test_real_name_next_to_a_label_part_is_masked(state, settings, retype, text, expected):
    """Обзор, Minor 8: после смены типа части имени метка стоит в имени (<TERM_1>.domain-1.example, host-1.<ORG_1>),
    и пользователь может вписать рядом настоящее имя. Скрывается часть вне замены, сама метка остаётся (5.10)."""
    if retype == "host":
        sanitize(state, "узел srv01.contoso.ru и srv01", settings)
        ops.retype(state, next(e for e in state.entities.values() if e.key == "srv01").id, T.TERM)
        sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    else:
        sanitize(state, "узел srv01.contoso.ru, сайт contoso.ru", settings)
        ops.retype(state, next(e for e in state.entities.values() if e.type is T.DOMAIN).id, T.ORG)
        sanitize(state, "узел srv01.contoso.ru, сайт contoso.ru", settings)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, expected, settings).sanitized == expected        # повторная вставка ничего не меняет
    assert (len(state.entities), len(state.surrogates)) == counts


def test_name_longer_than_a_dns_name_is_masked_and_restored_by_parts(state, settings):
    """FINDINGS P2 «Layer 3 takes quadratic time on a long dotted run»: имя длиннее 253 знаков целиком в таблицу не
    записывается — поиск замен перебирал бы цепочки частей до его длины, — но скрывается и восстанавливается по частям."""
    text = "цепочка " + "srv-01." * 40 + "contoso.ru"
    result = sanitize(state, text, settings)
    assert result.sanitized == "цепочка " + "host-1." * 40 + "domain-1.example" and result.deliverable
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert restore(state, result.sanitized, settings).text == text


@pytest.mark.parametrize("text, expected", [
    ("Проверь srv-02.msk.domain-1.example", "Проверь host-2.sub-3.domain-1.example"),
    ("Проверь www.srv-02.domain-1.example", "Проверь www.host-2.domain-1.example"),
    ("Проверь host-1.ru, ru и msk", "Проверь host-1.sub-2, ru и msk"),
    ("Проверь host-1.fabrikam.ru", "Проверь host-1.domain-2.example"),
], ids=["parts-before", "generic-before", "part-after", "domain-after"])
def test_part_cut_off_an_issued_replacement_keeps_its_place_in_the_name(state, settings, text, expected):
    """FINDINGS «Retyping a host name part: what it leaves» (1): часть вне выданной замены разбиралась как имя само по
    себе — «srv-02.msk» получал подмену домена, а одиночная часть («ru» после host-1) — искомой и скрывалась везде.
    Части перед заменой — части слева от домена, часть после неё — не первая; домен после замены — домен."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, expected, settings).sanitized == expected        # повторная вставка ничего не меняет
    assert (len(state.entities), len(state.surrogates)) == counts
    assert restore(state, expected, settings).text == text.replace("host-1", "srv01").replace("domain-1.example", "contoso.ru")


def test_first_part_after_generic_ones_is_the_leading_part(state, settings):
    """FINDINGS «Review fixes round of 15.10: small leftovers»: первой считалась только часть на месте 0, и у
    www.srv02.corp.contoso.ru часть srv02 получала sub-N и не становилась искомой — отдельное srv02 оставалось открытым.
    Первая — первая не служебная часть; средняя часть искомой не становится, как прежде."""
    text = "узел www.srv02.corp.contoso.ru, позже srv02, mail.corp.contoso.ru и corp wiki"
    result = sanitize(state, text, settings)
    assert result.sanitized == (
        "узел www.host-1.sub-2.domain-1.example, позже host-1, mail.sub-2.domain-1.example и corp wiki"
    )
    assert restore(state, result.sanitized, settings).text == text


def test_rule_inside_a_name_with_a_label_part_leaves_the_label(state, settings):
    """Правило пользователя поглощает фрагмент целиком (5.7): метка во фрагмент имени не входит и остаётся (FR-5.9)."""
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == "srv01").id, T.TERM)
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    ops.mask(state, "fabrikam", T.TERM)
    assert sanitize(state, "Проверь <TERM_1>.fabrikam.ru", settings).sanitized == "Проверь <TERM_1>.<TERM_2>"


@pytest.mark.parametrize("text, expected", [
    ("Проверь host-1.fabrikam.ru", "Проверь host-1.<TERM_1>"),
    ("Проверь srv-db02.host-1.fabrikam.ru", "Проверь host-2.host-1.<TERM_1>"),
    ("Проверь srv02.fabrikam.ru", "Проверь <TERM_1>"),
], ids=["part-before", "parts-around", "no-replacement"])
def test_selection_inside_a_name_leaves_the_issued_replacement_next_to_it(state, settings, text, expected):
    """FINDINGS «Retyping a host name part: what it leaves» (3): выделение не на целой части поглощало имя вместе с
    выданной заменой — <TERM_1> восстанавливался в «host-1.fabrikam.ru», с подменой вместо оригинала. Замену правило не
    трогает (FR-5.9) и поглощает только задетые им части; имя без замены — целиком, как прежде (5.7)."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    ops.mask(state, "fabrikam", T.TERM)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    assert sanitize(state, expected, settings).sanitized == expected
    assert restore(state, expected, settings).text == text.replace("host-1", "srv01")


@pytest.mark.parametrize("text, expected", [
    ("почта ivanov@host-1.fabrikam.ru", "почта <ACCOUNT_1>@host-1.<TERM_1>"),
    ("почта postmaster@srv-db02.host-1.fabrikam.ru", "почта postmaster@host-2.host-1.<TERM_1>"),
    ("почта ivanov@srv02.fabrikam.ru", "почта <TERM_1>"),
], ids=["part-before", "role-mailbox", "no-replacement"])
def test_selection_inside_an_email_leaves_the_issued_replacement_next_to_it(state, settings, text, expected):
    """Обзор пакета, Minor: выделение внутри имени узла уже не поглощало выданную в нём замену, а внутри адреса e-mail —
    поглощало: <TERM_1> восстанавливался в «ivanov@host-1.fabrikam.ru», с подменой вместо srv01. Адрес делится, как
    имя: имя входа — ACCOUNT, части имени — как рядом с заменой (5.10), задетые правилом — его тип."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    ops.mask(state, "fabrikam", T.TERM)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    assert sanitize(state, expected, settings).sanitized == expected
    assert restore(state, expected, settings).text == text.replace("host-1", "srv01")


def test_person_selection_inside_an_email_leaves_the_issued_replacement_next_to_it(state, settings):
    """Найдено в раунде слияний: шаг 3 (5.7) пересобирал фрагмент PERSON и терял, где в нём лежат правила, — выделение
    «ivanov» с типом «человек» поглощало адрес вместе с выданной заменой, и метка восстанавливалась в
    «ivanov@host-1.fabrikam.ru», с подменой вместо srv01."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    ops.mask(state, "ivanov", T.PERSON)
    result = sanitize(state, "почта ivanov@host-1.fabrikam.ru", settings)
    assert result.sanitized == "почта <PERSON_1>@host-1.domain-2.example"
    assert restore(state, result.sanitized, settings).text == "почта ivanov@srv01.fabrikam.ru"


def test_email_with_a_strict_part_next_to_a_replacement_is_split_and_blocked(state):
    """Та же находка вместе с политикой части: адрес, который поглотила часть со строже политикой, рядом с выданной
    заменой делится так же, и часть блокирует выдачу своей меткой."""
    settings = Settings(policies=default_policies() | {T.SECRET: Policy.BLOCK})
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == "srv01").id, T.SECRET)
    result = sanitize(state, "почта ivanov@srv01.domain-1.example", settings)
    assert result.sanitized == "почта <ACCOUNT_1>@<SECRET_1>.domain-1.example"
    assert [state.entities[s.entity_id].type for s in result.blocked] == [T.SECRET]
    assert restore(state, result.sanitized, settings).text == "почта ivanov@srv01.contoso.ru"


def test_email_with_a_retyped_host_part_stays_an_email(state, settings):
    """FINDINGS «Retyping a host name part: what it leaves» (2): правило смены типа части имени поглощало адрес e-mail с
    этой частью — он становился меткой TERM. Правило на целой части имени после «@» адрес не поглощает (5.7, шаг 4)."""
    text = "узел srv01.contoso.ru и srv01, почта ivanov@srv01.contoso.ru"
    assert sanitize(state, text, settings).sanitized.endswith("почта <EMAIL_1>")
    ops.retype(state, next(e for e in state.entities.values() if e.key == "srv01").id, T.TERM)
    result = sanitize(state, text, settings)
    assert result.sanitized == "узел <TERM_1>.domain-1.example и <TERM_1>, почта <EMAIL_1>"
    assert restore(state, result.sanitized, settings).text == text
    ops.mask(state, "srv0", T.TERM)        # выделение не на целой части поглощает адрес, как прежде
    assert sanitize(state, "почта ivanov@srv01.contoso.ru", settings).sanitized == "почта <TERM_2>"


@pytest.mark.parametrize("policy", [Policy.BLOCK, Policy.HIDE])
def test_email_keeps_the_stricter_policy_of_a_retyped_host_part(state, policy):
    """Обзор пакета, Important: после смены типа srv01 на SECRET адрес ivanov@srv01.contoso.ru оставался <EMAIL_1> —
    выдача не блокировалась, а при «скрывать без восстановления» метка восстанавливалась в адрес вместе с srv01. Часть
    со строже политикой поглощает адрес, как до пакета; у имени узла политика части и так держит всё имя."""
    settings = Settings(policies=default_policies() | {T.SECRET: policy})
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == "srv01").id, T.SECRET)
    result = sanitize(state, "почта ivanov@srv01.contoso.ru", settings)
    assert result.sanitized == "почта <SECRET_1>"
    assert [state.entities[s.entity_id].type for s in result.blocked] == ([T.SECRET] if policy is Policy.BLOCK else [])
    restored = restore(state, result.sanitized, settings)
    assert restored.text == ("почта ivanov@srv01.contoso.ru" if policy is Policy.BLOCK else "почта <SECRET_1>")
    host = sanitize(state, "узел srv01.contoso.ru", settings)     # у имени узла — так же
    assert host.sanitized == "узел <SECRET_2>.domain-1.example" and host.deliverable is (policy is Policy.HIDE)


@pytest.mark.parametrize("text, expected", [
    ("почта ivanov@<TERM_1>.northwind.ru", "почта <ACCOUNT_1>@<TERM_1>.domain-3.example"),
    ("почта ivanov@host-1.<ORG_1>", "почта <ACCOUNT_1>@host-1.<ORG_1>"),
    ("почта ivanov@<ORG_1>", "почта <ACCOUNT_1>@<ORG_1>"),
    ("почта postmaster@<TERM_1>.domain-1.example", "почта postmaster@<TERM_1>.domain-1.example"),
    ("звонил <PERSON_1>, ivanov@<PERSON_1>", "звонил <PERSON_1>, ivanov@<PERSON_1>"),
    ("почта ivanov@srv02.<ORG_1>", "почта <ACCOUNT_1>@host-2.<ORG_1>"),
    ("почта ivanov@srv03.domain-1.example", "почта <ACCOUNT_1>@host-3.domain-1.example"),
    ("почта ivanov@contoso.ru.<TERM_1>", "почта <EMAIL_1>.<TERM_1>"),
], ids=[
    "label-and-name", "name-and-label", "domain-label", "role-mailbox", "not-a-domain", "part-and-label",
    "part-and-domain", "label-after",
])
def test_email_with_a_label_in_its_domain_is_found(state, settings, text, expected):
    """FINDINGS «Retyping a host name part: what it leaves» (2): правило e-mail не брало метку в домене, и в
    «ivanov@<TERM_1>.fabrikam.ru» оставались открытыми и логин, и домен. Метка, выданная домену в имени (<ORG_1> из
    host-1.<ORG_1>), — домен и сама по себе; другая метка после «@» доменом не считается."""
    sanitize(state, "узел srv01.contoso.ru и srv01, узел srv02.fabrikam.ru, сайт fabrikam.ru", settings)
    for key, type_ in (("srv01", T.TERM), ("fabrikam.ru", T.ORG)):
        ops.retype(state, next(e for e in state.entities.values() if e.key == key).id, type_)
    sanitize(state, "узел srv01.contoso.ru и srv01, узел srv02.fabrikam.ru, сайт fabrikam.ru", settings)
    ops.mask(state, "Петров", T.PERSON)
    sanitize(state, "звонил Петров", settings)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    assert sanitize(state, expected, settings).sanitized == expected


@pytest.mark.parametrize("text, expected", [
    ("Проверь srv02.<TERM_1>", "Проверь host-2.<TERM_1>"),
    ("Проверь srv02.host-1.<TERM_1>", "Проверь host-2.host-1.<TERM_1>"),
    ("почта ivanov@<TERM_1>", "почта <ACCOUNT_1>@<TERM_1>"),
    ("почта ivanov@srv02.<TERM_1>", "почта <ACCOUNT_1>@host-2.<TERM_1>"),
    ("Проверь www.<TERM_1>", "Проверь www.<TERM_1>"),
    ("отчёт.<TERM_2>, ivanov@<TERM_2>", "отчёт.<TERM_2>, ivanov@<TERM_2>"),
    ("отчёт.<PERSON_1>, ivanov@<PERSON_1>", "отчёт.<PERSON_1>, ivanov@<PERSON_1>"),
], ids=["part-before", "parts-before", "email", "email-part", "generic", "not-a-domain", "person"])
def test_label_of_a_domain_name_is_a_domain_as_in_restore(state, settings, text, expected):
    """Наблюдение раунда имён узлов, P3: конвейер считал доменом только метку в конце записанного имени (<ORG_1> из
    host-1.<ORG_1>), а восстановление — любую метку, значение которой — доменное имя. После host-1.<TERM_1> (выделение
    «fabrikam» в host-1.fabrikam.ru) srv02.<TERM_1> оставался открытым, а ivanov@<TERM_1> — не адресом. Метка другого
    значения («Заря», человек) доменом не становится."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    for value, type_, sample in (
        ("fabrikam", T.TERM, "Проверь host-1.fabrikam.ru"), ("Заря", T.TERM, "проект Заря"),
        ("Петров", T.PERSON, "звонил Петров"),
    ):
        ops.mask(state, value, type_)
        sanitize(state, sample, settings)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    assert sanitize(state, expected, settings).sanitized == expected
    originals = {"host-1": "srv01", "<TERM_1>": "fabrikam.ru", "<TERM_2>": "Заря", "<PERSON_1>": "Петров"}
    restored = text
    for fake, original in originals.items():
        restored = restored.replace(fake, original)
    assert restore(state, expected, settings).text == restored


def test_chain_of_overlapping_emails_is_hidden_but_not_searched_as_a_whole(state, settings):
    """Наблюдение раунда имён узлов, P2: в «a@b.c.» * N адреса пересекаются (следующий начинается в домене
    предыдущего), и второй проход сливал найденные написания в один фрагмент длиной в текст. Он становился искомым
    написанием, и поиск известных значений разрезал его с каждого слова: 160 КБ — 2,6 с, 500 КБ — 12 с. Искомы сами
    адреса; цепочка скрыта одной меткой и восстанавливается целиком."""
    text = "a@b.c." * 50
    result = sanitize(state, text, settings)
    assert result.sanitized == "<EMAIL_3>@b.c." and result.deliverable
    assert sorted(form for e in state.entities.values() for form in e.forms) == ["a@b.c.a", "b.c.a@b.c.a"]
    assert sanitize(state, text, settings).sanitized == result.sanitized
    assert restore(state, result.sanitized, settings).text == text
    sanitize(state, "почта ivanov@contoso.ru", settings)      # адрес с одним «@» — искомое написание, как прежде
    assert any("ivanov@contoso.ru" in e.forms for e in state.entities.values())


def test_overlapping_dictionary_values_are_hidden_but_not_searched_as_a_whole(state):
    """Наблюдение раунда имён узлов, P2: «Иван Иван» словаря в «Иван Иван Иван …» — пересекающиеся находки, и их слияние
    становилось искомым написанием длиной в цепочку. Оно скрыто одной меткой и восстанавливается целиком, а искомо
    написание находки; то же значение потом в другом тексте скрывается."""
    settings = Settings(always=(DictEntry(T.PERSON, "Иван Иван"),))
    text = "Иван Иван Иван Иван Иван"
    result = sanitize(state, text, settings)
    assert result.sanitized == "<PERSON_1>" and result.deliverable
    assert [form for e in state.entities.values() for form in e.forms] == ["Иван Иван"]
    assert sanitize(state, text, settings).sanitized == result.sanitized
    assert restore(state, result.sanitized, settings).text == text
    later = sanitize(state, "Пришёл Иван Иван.", settings)
    assert "Иван" not in later.sanitized and later.deliverable


def test_overlapping_rule_values_are_hidden_but_not_searched_as_a_whole(state, settings):
    """То же у правила пользователя «la la» в «la la la …»: слияние — своя сущность, которая восстанавливается целиком,
    а её написание — значение правила. Смена её типа даёт правило на это значение, а не на всю цепочку."""
    ops.mask(state, "la la", T.TERM)
    text = "la la la la la"
    result = sanitize(state, text, settings)
    assert result.sanitized == "<TERM_1>" and result.deliverable
    [chain] = state.entities.values()
    assert chain.forms == ["la la"]
    assert sanitize(state, text, settings).sanitized == result.sanitized
    assert restore(state, result.sanitized, settings).text == text
    later = sanitize(state, "la la", settings)
    assert later.sanitized == "<TERM_2>" and restore(state, later.sanitized, settings).text == "la la"
    ops.retype(state, chain.id, T.ORG)
    assert [(rule.value, rule.type) for rule in state.rules] == [("la la", T.ORG)]


def test_run_of_surnames_is_not_one_person(state, settings):
    """Наблюдение раунда имён узлов, P2: ряд фамилий через пробел сливался шагом 3 (5.7) в один PERSON длиной в ряд. Ряд
    длиннее четырёх слов — список людей: каждый — своя метка, и каждый искомый."""
    names = ["Иванов", "Петров", "Сидоров", "Козлов", "Морозов"]
    text = "Присутствовали " + " ".join(names) + "."
    result = sanitize(state, text, settings, Layers(ner=Marks({name: T.PERSON for name in names})))
    assert result.sanitized == "Присутствовали <PERSON_1> <PERSON_2> <PERSON_3> <PERSON_4> <PERSON_5>."
    assert sorted(form for e in state.entities.values() for form in e.forms) == sorted(names)
    assert restore(state, result.sanitized, settings).text == text
    assert sanitize(state, "Звонил Петров", settings).sanitized == "Звонил <PERSON_2>"


def test_email_without_an_at_sign_next_to_a_replacement_does_not_stop_sanitizing(state, settings):
    """Фрагмент типа EMAIL без «@» бывает — правило пользователя с этим типом; рядом с заменой он делится, как прежде."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    ops.mask(state, "host-1 fabrikam", T.EMAIL)
    assert sanitize(state, "узел host-1 fabrikam", settings).sanitized == "узел host-1 <ACCOUNT_1>"


def test_labels_with_dots_outside_names_stay_as_they_are(state, settings):
    sanitize(state, "узел srv01.contoso.ru, сайт contoso.ru", settings)
    ops.retype(state, next(e for e in state.entities.values() if e.type is T.DOMAIN).id, T.ORG)
    text = "узел host-1.<ORG_1>, сайт <ORG_1>, файл <ORG_1>.docx, сайт <ORG_1>.ru, <ORG_1>.example.com"
    assert sanitize(state, text, settings).sanitized == text


def test_well_known_part_next_to_a_surrogate_is_not_masked(state, settings):
    """Часть рядом с заменой, которая сама общеизвестна («example» после NetBIOS-имени, «www»),
    не скрывается и не становится искомым написанием для следующих текстов."""
    sanitize(state, r"Учётка CONTOSO\ivanov", settings)
    assert sanitize(state, "Пишу с petrov@domain-1.example", settings).sanitized == "Пишу с <ACCOUNT_2>@domain-1.example"
    text = "Ссылка https://www.domain-1.example/x, например example"
    assert sanitize(state, text, settings).sanitized == text


def test_issued_surrogate_in_another_notation_stays_as_is(state, settings):
    sanitize(state, "Сервер srv-dc01.contoso.ru", settings)
    for text in ("Ответ ушёл на postmaster@domain-1.example", "Узел host-1.domain-1.example, домен domain-1.example"):
        result = sanitize(state, text, settings)
        assert (result.sanitized, len(state.entities)) == (text, 2), text


def test_opened_value_does_not_hide_a_longer_original_from_the_leak_check(state, settings):
    """Обзор пакета исправлений 1А, P1: открытое «Ivan» не прячет «ivanov» от проверки утечек."""
    sanitize(state, r"учётка CONTOSO\ivanov", settings)
    ops.unmask(state, "Ivan")
    planted = "пишет ivanov"
    assert [planted[leak.start:leak.end] for leak in leakcheck.check(planted, state, settings)] == ["ivanov"]


def test_sanitized_text_with_masked_pieces_pasted_back_changes_nothing(state, settings):
    """Review Focus: повторная вставка очищенного текста, где части рядом с заменой уже скрыты."""
    sanitize(state, r"Сервер srv-dc01.contoso.ru, учётка CONTOSO\ivanov", settings)
    first = sanitize(state, "Писал petrov@domain-1.example про CN=host-1,OU=Servers,DC=fabrikam,DC=local", settings)
    counts = (len(state.entities), len(state.surrogates))
    again = sanitize(state, first.sanitized, settings)
    assert again.sanitized == first.sanitized == "Писал <ACCOUNT_2>@domain-1.example про CN=host-1,<DN_1>"
    assert (len(state.entities), len(state.surrogates)) == counts


@pytest.mark.parametrize("text, expected, restored", [
    (r"RewriteCond %{HTTP_HOST} ^www\.contoso\.ru$", r"RewriteCond %{HTTP_HOST} ^www\.domain-1\.example$", None),
    (r"server_name ~^srv01\.contoso\.ru$;", r"server_name ~^host-1\.domain-1\.example$;", None),
    (r"server_name ~^(.+)\.corp\.contoso\.local$;", r"server_name ~^(.+)\.host-1\.domain-1\.example$;", None),
    (r"Select-String '\bsrv01\.contoso\.ru\b'", r"Select-String '\bhost-1\.domain-1\.example\b'", None),
    (r'if address :regex "from" "@contoso\.ru$"', r'if address :regex "from" "@domain-1\.example$"', None),
    (r"^srv01\.contoso.ru$", r"^host-1\.domain-1\.example$", r"^srv01\.contoso\.ru$"),
], ids=["rewrite", "nginx", "nginx-capture", "word-bounds", "sieve", "both-separators"])
def test_name_written_with_escaped_dots_is_masked_and_restored_with_them(state, settings, text, expected, restored):
    """Наблюдение раунда 3 имён узлов, P1: имя через «\\.» уходило в облако как есть. Подмена пишется тем же разделителем,
    и восстановление (раздел 7, шаг 2) возвращает оригинал с ним; имя с обоими разделителями — целиком через «\\.».
    Повторная вставка ничего не меняет."""
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, expected, settings).sanitized == expected
    assert (len(state.entities), len(state.surrogates)) == counts
    assert restore(state, expected, settings).text == (restored or text)


def test_known_name_written_with_escaped_dots_is_masked_and_caught_by_the_leak_check(state, settings):
    """Та же находка: после известного srv01.contoso.ru в «^Srv01\\.Contoso\\.ru$» (смешанный регистр — слой 3 имя не
    берёт) скрывалась только первая часть, а «Contoso\\.ru» уходил открытым; проверка утечек его не видела."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    planted = r"RewriteCond ^Srv01\.Contoso\.ru$"
    assert [planted[leak.start:leak.end] for leak in leakcheck.check(planted, state, settings)] == ["Srv01", r"Contoso\.ru"]
    result = sanitize(state, planted, settings)
    assert result.sanitized == r"RewriteCond ^host-1\.domain-1\.example$" and result.deliverable
    assert restore(state, result.sanitized, settings).text == r"RewriteCond ^srv01\.contoso\.ru$"


def test_opened_name_and_a_retyped_part_act_on_a_name_with_escaped_dots(state, settings):
    """Через «\\.» действуют те же решения пользователя, что через точку: открытое имя остаётся открытым (5.7, шаг 5), а
    правило на целой части имени не поглощает его (5.7, шаг 4)."""
    sanitize(state, "узел srv01.contoso.ru и srv01, узел srv02.contoso.ru", settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == "srv01").id, T.TERM)
    ops.unmask(state, "srv02.contoso.ru")
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    text = r"^srv01\.contoso\.ru$ и ^srv02\.contoso\.ru$"
    result = sanitize(state, text, settings)
    assert result.sanitized == r"^<TERM_1>\.domain-1\.example$ и ^srv02\.contoso\.ru$" and result.deliverable
    assert restore(state, result.sanitized, settings).text == text


@pytest.mark.parametrize("text, expected", [
    (r"^srv-db02\.<TERM_1>\.domain-1\.example$", r"^host-2\.<TERM_1>\.domain-1\.example$"),
    (r"^<TERM_1>\.fabrikam\.ru$", r"^<TERM_1>\.domain-2\.example$"),
    (r"^srv-db02\.msk\.domain-1\.example$", r"^host-2\.sub-3\.domain-1\.example$"),
], ids=["part-before-label", "domain-after-label", "parts-before-replacement"])
def test_name_with_escaped_dots_next_to_a_replacement_keeps_its_place(state, settings, text, expected):
    """Часть рядом с заменой или меткой через «\\.» — часть имени, как через точку (5.10): части перед заменой — части
    слева от домена, домен после метки — домен."""
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == "srv01").id, T.TERM)
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, expected, settings).sanitized == expected
    assert (len(state.entities), len(state.surrogates)) == counts
    assert restore(state, expected, settings).text == text.replace("<TERM_1>", "srv01").replace("domain-1", "contoso").replace(
        "example", "ru"
    )


def test_mixed_case_name_around_an_issued_replacement_is_masked(state, settings):
    """Наблюдение раунда 3 имён узлов, P3: «Petrov.host-1.fabrikam.ru» слой 3 принимал за код (смешанный регистр, 5.4),
    и fabrikam.ru уходил открытым. Имя с выданной заменой внутри — имя; код без неё остаётся как есть."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    text = "Проверь Petrov.host-1.fabrikam.ru и System.Net, re.search(x)"
    result = sanitize(state, text, settings)
    assert result.sanitized == "Проверь host-2.host-1.domain-2.example и System.Net, re.search(x)" and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert (len(state.entities), len(state.surrogates)) == counts
    assert restore(state, result.sanitized, settings).text == text.replace("host-1", "srv01")


def test_windows_paths_with_dot_folders_keep_their_meaning(state, settings):
    """Та же находка с другой стороны: «\\» перед частью — разделитель пути, а не точки; папка на точку с суффиксом из
    списка («.android», «.azure») именем не становится."""
    text = r"C:\Users\ivanov\.ssh\config, C:\Users\ivanov\.android\avd и \\fs01\share\.azure"
    result = sanitize(state, text, settings)
    assert result.sanitized == r"C:\Users\<ACCOUNT_1>\.ssh\config, C:\Users\<ACCOUNT_1>\.android\avd и \\host-1\share\.azure"
    assert restore(state, result.sanitized, settings).text == text


class Marks:
    """Слой 4 для теста: помечает заданные строки и считает вызовы."""

    name = "ner"

    def __init__(self, marks):
        self.marks, self.calls = marks, 0

    def detect(self, text, ctx=None):
        self.calls += 1
        return [
            Span(m.start(), m.end(), type_, "ner", 0.9)
            for value, type_ in self.marks.items() for m in re.finditer(re.escape(value), text)
        ]


class SecondPass:
    """Слой 5 для теста: запоминает, какой текст видел, и помечает заданные строки в оригинале."""

    def __init__(self, marks):
        self.marks, self.seen = marks, []

    def find(self, text, sanitized, state):
        self.seen.append(sanitized)
        return [
            Span(m.start(), m.end(), type_, "llm")
            for value, type_ in self.marks.items() for m in re.finditer(re.escape(value), text)
        ]


def test_layer_4_runs_once_per_text_and_its_findings_are_returned(state, settings):
    ner = Marks({"Петров": T.PERSON})
    result = sanitize(state, "Петров, a@x.example", settings, Layers(ner=ner))
    assert result.sanitized == "<PERSON_1>, <EMAIL_1>"
    assert ner.calls == 1                                   # не на каждый проход 5.10
    assert [(s.start, s.end, s.source) for s in result.model_spans] == [(0, 6, "ner")]


def test_cached_findings_are_used_instead_of_the_models(state, settings):
    ner = Marks({})
    result = sanitize(state, "Петров", settings, Layers(ner=ner, cached=(Span(0, 6, T.PERSON, "ner", 0.9),)))
    assert (result.sanitized, ner.calls) == ("<PERSON_1>", 0)


def test_second_pass_reads_the_text_cleaned_by_layers_1_to_4(state, settings):
    llm = SecondPass({"sunflower77": T.SECRET})
    result = sanitize(state, "a@x.example, на стикере sunflower77", settings, Layers(llm=llm))
    assert llm.seen == ["<EMAIL_1>, на стикере sunflower77"]
    assert result.sanitized == "<EMAIL_1>, на стикере <SECRET_1>"
    assert [s.source for s in result.model_spans] == ["llm"]


def test_failing_model_layer_stops_sanitizing_and_changes_nothing(state, settings):
    class Broken:
        name = "ner"

        def detect(self, text, ctx=None):
            raise DetectorError("модели не загружены")

    with pytest.raises(DetectorError):
        sanitize(state, "почта a@x.example", settings, Layers(ner=Broken()))
    assert state.entities == {}
