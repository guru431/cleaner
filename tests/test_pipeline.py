import re

import pytest

from cleaner.core import leakcheck
from cleaner.core.detect import dictionary as dictionary_layer
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


@pytest.mark.parametrize("command", [
    "ssh admin@SRV-DC01.corp.contoso.ru; ping srv-dc01",
    "scp report.txt root@srv-dc01.corp.contoso.ru:/tmp/; ping srv-dc01",
    "rsync -a report.txt ivanov@srv-dc01.corp.contoso.ru:/tmp/; ping srv-dc01",
])
@pytest.mark.parametrize("written", [False, True])
def test_remote_login_registers_the_host_and_its_short_name(state, settings, command, written):
    state.written = written
    result = sanitize(state, command, settings)
    assert "srv-dc01" not in result.sanitized.lower()
    assert "ping host-" in result.sanitized
    restored = restore(state, result.sanitized, settings).text
    assert restored == command if written else restored.lower() == command.lower()


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
    result = sanitize(state, 'post' 'gres://app:Sup3rSecret@db01.contoso.ru:5432/crm', settings)  # secret-scan:allow -- synthetic test fixture
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


def test_logins_before_an_escaped_at_in_urls_keep_their_own_labels(state, settings):
    """Найдено в раунде 5 (P2): в строке Perl «https://ivanov\\@git…» вход брался с «\\», ключ входа — часть после
    последней «\\» — выходил пустым, и все такие входы чата становились одной меткой: petrov восстанавливался как ivanov."""
    text = r'@urls = ("https://ivanov\@git.contoso.ru/a", "https://petrov\@git.contoso.ru/b");'
    result = sanitize(state, text, settings)
    assert result.sanitized == (
        r'@urls = ("https://<ACCOUNT_1>\@host-1.domain-1.example/a", "https://<ACCOUNT_2>\@host-1.domain-1.example/b");'
    )
    # Внутри ссылки с «\» восстановление ничего не подставляет (раздел 7): браузер ведёт её на узел <ACCOUNT_1>.
    assert restore(state, "входы <ACCOUNT_1> и <ACCOUNT_2>", settings).text == "входы ivanov и petrov"


def test_email_with_an_encoded_at_and_a_short_phone_are_the_same_entities(state, settings):
    """«ivanov%40contoso.ru» в адресе — тот же ящик, что ivanov@contoso.ru; «9031112233» — тот же номер, что «+7 (903) 111-22-33».
    Часть рядом с выданной подменой домена — имя ящика без «%40»."""
    assert sanitize(state, "почта ivanov@contoso.ru, тел. +7 (903) 111-22-33", settings).sanitized == (
        "почта <EMAIL_1>, тел. <PHONE_1>"
    )
    assert sanitize(state, "GET /?email=Ivanov%40contoso.ru&tel=9031112233", settings).sanitized == (
        "GET /?email=<EMAIL_1>&tel=<PHONE_1>"
    )
    sanitize(state, "Сервер srv-dc01.contoso.ru", settings)
    assert sanitize(state, "GET /?email=petrov%40domain-1.example", settings).sanitized == (
        "GET /?email=<ACCOUNT_1>%40domain-1.example"
    )
    assert {e.key for e in state.entities.values() if e.type is T.ACCOUNT} == {"petrov"}
    assert restore(state, "?email=<ACCOUNT_1>%40domain-1.example", settings).text == "?email=petrov%40contoso.ru"


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


@pytest.mark.parametrize("text, record", [
    ("почта ivanov@srv.contoso.ru", T.EMAIL), ("узел srv.contoso.ru", T.HOST), ("домен contoso.ru", T.DOMAIN),
], ids=["email", "host", "domain"])
@pytest.mark.parametrize("policy", [Policy.BLOCK, Policy.HIDE])
def test_rule_off_whole_parts_keeps_the_stricter_policy_of_the_record(state, text, record, policy):
    """Второе ревью, Minor: выделение «contoso» не на целой части поглощало адрес или имя меткой своего типа — при
    EMAIL=BLOCK выдача не блокировалась, при «скрывать без восстановления» метка восстанавливалась целиком. Фрагмент
    берёт тип записи, если её политика строже (5.7, шаг 4)."""
    settings = Settings(policies=default_policies() | {record: policy})
    ops.mask(state, "contoso", T.TERM)
    result = sanitize(state, text, settings)
    entity = state.entities[result.spans[0].entity_id]
    assert entity.type is record and "contoso" not in result.sanitized
    assert [state.entities[s.entity_id].type for s in result.blocked] == ([record] if policy is Policy.BLOCK else [])
    assert (restore(state, result.sanitized, settings).text == text) is (policy is Policy.BLOCK)
    lenient = Settings(policies=default_policies() | {T.TERM: policy})      # правило строже — его метка, как прежде
    assert sanitize(state, text, lenient).sanitized == text.rsplit(" ", 1)[0] + " <TERM_1>"


@pytest.mark.parametrize("value, record", [
    ("+79161234567", T.PHONE), ("person@fabrikam.ru", T.EMAIL), ("10.1.2.5", T.IP),
], ids=["phone", "email", "ip"])
def test_secret_keeps_the_block_of_the_record_it_swallows(state, value, record):
    """Аудит 2026-10-21, P2: пароль, который слой 1 или 3 нашёл и как телефон, адрес e-mail или IP, получал <SECRET_1> —
    при политике «блокировать» у типа записи выдача не блокировалась. Фрагмент берёт тип со строже политикой (FR-3.3), и
    то же значение в следующих текстах — та же сущность; при обычной политике записи — <SECRET_1>, как прежде."""
    text = f"password={value}"
    blocked = Settings(policies=default_policies() | {record: Policy.BLOCK})
    result = sanitize(state, text, blocked)
    assert value not in result.sanitized and not result.deliverable
    assert [state.entities[s.entity_id].type for s in result.blocked] == [record]
    again = sanitize(state, f"{text}; повтор: {value}", blocked)
    assert {s.entity_id for s in again.spans} == {result.blocked[0].entity_id} and not again.deliverable
    # Политика записи снова обычная: та же строка — снова секрет, выдача разрешена, и метка не восстанавливается.
    masked = sanitize(state, text, Settings())
    assert masked.sanitized == "password=<SECRET_1>" and masked.deliverable
    assert restore(state, masked.sanitized, Settings()).text == masked.sanitized
    # Блокировка — по текущей политике: известный теперь и как секрет пароль снова блокирует выдачу.
    assert not sanitize(state, text, blocked).deliverable


@pytest.mark.parametrize("text", ["пароль: Abc+7 916 123-45-67xyz", "пароль: Abc+7 916 123-45-67"])
def test_phone_that_a_password_runs_into_is_hidden_whole(state, settings, text):
    """Аудит 2026-10-21: секрет слоя 2 кончался на «+7», а телефон после буквы слой 1 не искал — «<SECRET_1> 916
    123-45-67xyz», десять цифр номера открыты. Теперь номер найден, и пересечение с секретом — один фрагмент."""
    result = sanitize(state, text, settings)
    assert "916" not in result.sanitized and "45-67" not in result.sanitized


def test_infrastructure_value_keeps_the_block_of_a_name_found_by_layer_4(state):
    """Та же находка у других старшинств: домен слоя 3 поглощал организацию слоя 4, и ORG=BLOCK терялся."""
    settings = Settings(policies=default_policies() | {T.ORG: Policy.BLOCK})
    result = sanitize(state, "клиент contoso.ru", settings, Layers(cached=(Span(7, 17, T.ORG, "ner"),)))
    assert result.sanitized == "клиент <ORG_1>" and not result.deliverable
    assert sanitize(state, "клиент contoso.ru", Settings(), Layers(cached=(Span(7, 17, T.ORG, "ner"),))).deliverable


@pytest.mark.parametrize("policy", [Policy.BLOCK, Policy.HIDE])
def test_email_with_a_known_domain_of_a_stricter_policy_is_split(state, policy):
    """Находка 2026-10-21: домен, известный чату, при DOMAIN «блокировать» в ivanov@fabrikam.ru терялся под <EMAIL_1> —
    выдача не блокировалась, а при «скрывать без восстановления» домен восстанавливался вместе с адресом. Часть строже
    адреса держит свою политику: адрес делится, как рядом с выданной заменой (5.10), и домен — та же сущность."""
    settings = Settings(policies=default_policies() | {T.DOMAIN: policy})
    domain = sanitize(state, "домен fabrikam.ru", settings).spans[0].entity_id
    # Имя узла с частью «скрывать без восстановления» не восстанавливается целиком (раздел 7), имя входа — да.
    for text, expected, hidden in (
        ("почта ivanov@fabrikam.ru", "почта <ACCOUNT_1>@domain-1.example", "почта ivanov@domain-1.example"),
        (
            "почта ivanov@srv01.fabrikam.ru", "почта <ACCOUNT_1>@host-1.domain-1.example",
            "почта ivanov@host-1.domain-1.example",
        ),
    ):
        result = sanitize(state, text, settings)
        assert result.sanitized == expected
        assert [s.entity_id for s in result.blocked] == ([domain] if policy is Policy.BLOCK else [])
        assert sanitize(state, text, settings).sanitized == expected            # повторная очистка — то же
        assert sanitize(state, expected, settings).sanitized == expected        # повторная вставка ничего не меняет
        assert restore(state, expected, settings).text == (text if policy is Policy.BLOCK else hidden)
    # Политика домена обычная — адрес снова одна метка, как прежде.
    assert sanitize(state, "почта ivanov@fabrikam.ru", Settings()).sanitized == "почта <EMAIL_1>"


def test_opened_part_of_an_email_does_not_split_it(state):
    """Ревью 2026-10-21: домен из словаря «всегда скрывать» при DOMAIN «блокировать», открытый пользователем во всём
    чате, снова делил ivanov@fabrikam.ru и получал подмену — открытое значение скрыто, выдача невозможна. Открытая часть
    адрес не делит: он — по своим правилам, как без неё."""
    settings = Settings(
        always=(DictEntry(T.DOMAIN, "fabrikam.ru"),), policies=default_policies() | {T.DOMAIN: Policy.BLOCK},
    )
    assert sanitize(state, "почта ivanov@fabrikam.ru", settings).sanitized == "почта <ACCOUNT_1>@domain-1.example"
    ops.unmask(state, "fabrikam.ru")
    result = sanitize(state, "почта ivanov@fabrikam.ru", settings)
    assert result.sanitized == "почта <EMAIL_1>" and result.deliverable
    never = Settings(
        always=settings.always, never=frozenset({"fabrikam.ru"}), policies=settings.policies,
    )
    assert sanitize(state, "почта petrov@fabrikam.ru", never).sanitized == "почта <EMAIL_2>"


def test_known_person_in_an_email_login_keeps_the_stricter_person_policy(state):
    """Так же — известный чату человек в имени входа: часть получает тип своей находки (5.10)."""
    settings = Settings(policies=default_policies() | {T.PERSON: Policy.BLOCK})
    ops.mask(state, "Ivanov", T.PERSON)
    sanitize(state, "пишет Ivanov", settings)
    state.rules.clear()                 # дальше человек — известное значение чата, а не правило
    result = sanitize(state, "почта ivanov@fabrikam.ru", settings)
    assert result.sanitized == "почта <PERSON_1>@domain-1.example"
    assert [state.entities[s.entity_id].type for s in result.blocked] == [T.PERSON]


def test_host_name_with_a_known_domain_of_a_stricter_policy_is_blocked(state):
    """То же у имени узла: политику части держит подмена (resolve._name) — проверка, что так и есть."""
    settings = Settings(policies=default_policies() | {T.DOMAIN: Policy.BLOCK})
    sanitize(state, "домен fabrikam.ru", settings)
    result = sanitize(state, "узел srv01.fabrikam.ru", settings)
    assert result.sanitized == "узел host-1.domain-1.example"
    assert [state.entities[s.entity_id].type for s in result.blocked] == [T.DOMAIN]


def test_selection_of_an_email_with_a_stricter_known_domain_keeps_the_domain(state):
    """Правило, поглотившее адрес, не смягчает и часть строже себя: адрес делится, части в правиле — его тип, домен —
    свой; раньше выделение давало <DOMAIN_2> — метку домена на весь адрес."""
    settings = Settings(policies=default_policies() | {T.DOMAIN: Policy.BLOCK})
    sanitize(state, "домен fabrikam.ru", settings)
    ops.mask(state, "ivanov@fabrikam.ru", T.TERM)
    result = sanitize(state, "почта ivanov@fabrikam.ru", settings)
    assert result.sanitized == "почта <TERM_1>@domain-1.example"
    assert [state.entities[s.entity_id].type for s in result.blocked] == [T.DOMAIN]
    assert sanitize(state, "почта ivanov@fabrikam.ru", Settings()).sanitized == "почта <TERM_2>"     # адрес целиком


@pytest.mark.parametrize("text, value, found", [
    ("звонить +79161234567", "+79161234567", T.PHONE), ("почта ivanov@contoso.ru", "ivanov@contoso.ru", T.EMAIL),
    ("узел 10.1.2.5", "10.1.2.5", T.IP), ("пароль: Qwerty123!", "Qwerty123!", T.SECRET),
], ids=["phone", "email", "ip", "secret"])
def test_selection_does_not_soften_the_stricter_policy_of_the_found_value(state, text, value, found):
    """Выделение «+79161234567» с типом TERM при PHONE «блокировать» давало <TERM_1>, и выдача не блокировалась. Решение
    пользователя не смягчает политику находки того же значения: тип — у находки, если её политика строже (5.7, шаг 4);
    при той же политике — тип правила, как прежде. Открыть значение по-прежнему можно правилом «открыть» (FR-6.2)."""
    blocked = Settings(policies=default_policies() | {found: Policy.BLOCK})
    ops.mask(state, value, T.TERM)
    result = sanitize(state, text, blocked)
    assert value not in result.sanitized and [state.entities[s.entity_id].type for s in result.blocked] == [found]
    lenient = Settings(policies=default_policies() | {found: Policy.MASK})
    assert sanitize(state, text, lenient).sanitized == text.replace(value, "<TERM_1>")
    ops.unmask(state, value)
    assert sanitize(state, text, blocked).sanitized == text


@pytest.mark.parametrize("text, mask, found, expected", [
    ("звонить +79161234567 доб 12", ("+79161234567 доб", T.TERM), T.PHONE, "звонить <TERM_1> 12"),
    ("token=+79161234567abcdef", None, T.PHONE, "token=<SECRET_1>"),
], ids=["selection", "secret"])
def test_finding_inside_a_larger_fragment_keeps_its_block(state, text, mask, found, expected):
    """Фрагмент, внутри которого лежит находка строже его, терял её запрет: выделение «+79161234567 доб» с типом TERM или
    пароль с телефоном внутри при PHONE «блокировать» выдавались. Тип фрагмента не меняется — находка покрывает лишь часть
    значения, — но её тип записан у фрагмента (held), и блокировка — по нынешней политике: смена политики очистки не
    требует. Значение, открытое правилом «открыть», ничего не держит, как и вне фрагмента."""
    if mask:
        ops.mask(state, *mask)
    blocked = Settings(policies=default_policies() | {found: Policy.BLOCK})
    result = sanitize(state, text, blocked)
    [span] = result.spans
    assert result.sanitized == expected and span.held == (found,)
    assert result.blocked == [span] and not result.deliverable
    lenient = sanitize(state, text, Settings())
    assert lenient.sanitized == expected and lenient.spans[0].held == (found,) and lenient.deliverable
    ops.unmask(state, "+79161234567")
    assert sanitize(state, text, blocked).deliverable


def test_whole_host_name_selected_over_a_blocked_known_domain_stays_blocked(state):
    """Выделение всего имени узла с типом TERM при известном чату домене и DOMAIN «блокировать»: имя — запись, которую
    правило поглотило, и фрагмент берёт тип записи строже (5.7, шаг 4); домен держит выдачу."""
    settings = Settings(policies=default_policies() | {T.DOMAIN: Policy.BLOCK})
    sanitize(state, "домен fabrikam.ru", settings)
    ops.mask(state, "srv01.fabrikam.ru", T.TERM)
    result = sanitize(state, "узел srv01.fabrikam.ru", settings)
    assert result.sanitized == "узел host-1.domain-1.example" and not result.deliverable


def test_pasted_surrogate_of_a_blocked_entity_blocks_like_its_original(state):
    """Замены чата во входном тексте не заменяются снова (FR-5.9), и текст с выданной заменой сущности «блокировать»
    выдавался, хотя тот же текст с оригиналом — нет. Вставленная замена держит политику своей сущности, у имени узла — и
    его частей, по нынешней политике; сущность, значение которой открыто, — нет."""
    sanitize(state, "узел srv01.fabrikam.ru", Settings())       # имя выдано, пока у домена обычная политика
    blocked = Settings(policies=default_policies() | {T.DOMAIN: Policy.BLOCK})
    for text in ("почта ivanov@domain-1.example", "узел host-1.domain-1.example", "домен domain-1.example"):
        result = sanitize(state, text, blocked)
        [notice] = result.blocked_surrogates
        assert notice.code == "surrogate_in_input" and T.DOMAIN in notice.held and not result.deliverable, text
        assert sanitize(state, text, Settings()).deliverable
    assert [n.held for n in sanitize(state, "узел host-1.domain-1.example", blocked).notices] == [(T.HOST, T.DOMAIN)]
    ops.unmask(state, "fabrikam.ru")
    assert sanitize(state, "домен domain-1.example", blocked).deliverable


def test_selection_of_a_short_host_name_keeps_the_stricter_host_policy(state):
    """Короткое имя узла правило тоже не смягчает: resolve._name давал ему метку правила и после того, как объединение
    оставило HOST. Часть полного имени — так же: исключение владельца 15.10.2026 (5.7, шаг 4) — о строении имени, и
    <TERM_1>.domain-1.example при HOST=BLOCK не блокировал выдачу."""
    settings = Settings(policies=default_policies() | {T.HOST: Policy.BLOCK})
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    ops.mask(state, "srv01", T.TERM)
    result = sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    assert result.sanitized == "узел host-1.domain-1.example и host-1"
    assert [state.entities[s.entity_id].type for s in result.blocked] == [T.HOST, T.HOST]
    # Политика HOST не строже — часть получает метку правила, как прежде.
    assert sanitize(state, "узел srv01.contoso.ru и srv01", Settings()).sanitized == "узел <TERM_1>.domain-1.example и <TERM_1>"


@pytest.mark.parametrize("own, part", [(T.HOST, "srv01"), (T.DOMAIN, "contoso.ru")], ids=["host", "domain"])
@pytest.mark.parametrize("policy", [Policy.BLOCK, Policy.HIDE])
def test_retyped_part_of_a_dotted_name_keeps_the_stricter_policy_of_its_own_type(state, own, part, policy):
    """Смена типа части srv01 на TERM при HOST «блокировать» давала <TERM_1>.domain-1.example — выдача не блокировалась, а
    при «скрывать без восстановления» часть восстанавливалась. Часть, которой правило дало мягче политику, остаётся своего
    типа: HOST у части слева, DOMAIN у домена (resolve._manual); правило не мягче — метка, как прежде."""
    text, expected = "узел srv01.contoso.ru", "узел host-1.domain-1.example"
    settings = Settings(policies=default_policies() | {own: policy})
    sanitize(state, text, settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == part).id, T.TERM)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected
    assert result.deliverable is (policy is Policy.HIDE)
    assert (restore(state, expected, settings).text == text) is (policy is Policy.BLOCK)
    assert "<TERM_1>" in sanitize(state, text, Settings(policies=default_policies() | {own: policy, T.TERM: policy})).sanitized


@pytest.mark.parametrize("email", [Policy.MASK, Policy.BLOCK])
def test_rule_parts_of_a_split_record_keep_their_own_types(state, email):
    """Рядом с выданной заменой поглощённая запись делится (5.10), и каждая часть, задетая правилом, получает тип своего
    правила, а не самого длинного: «ivanov» (PERSON) и «fabrikam» (TERM) в ivanov@host-1.fabrikam.ru. Адрес строже своих
    частей не делится: при EMAIL=BLOCK части держали бы только свои политики, и выдача не блокировалась (5.10)."""
    settings = Settings(policies=default_policies() | {T.EMAIL: email, T.TERM: Policy.HIDE})
    sanitize(state, "узел srv01.contoso.ru", settings)
    ops.mask(state, "fabrikam", T.TERM)
    ops.mask(state, "ivanov", T.PERSON)
    result = sanitize(state, "почта ivanov@host-1.fabrikam.ru", settings)
    if email is Policy.BLOCK:
        assert result.sanitized == "почта <EMAIL_1>"
        assert [state.entities[s.entity_id].type for s in result.blocked] == [T.EMAIL]
        return
    assert result.sanitized == "почта <PERSON_1>@host-1.<TERM_1>" and result.deliverable
    assert restore(state, result.sanitized, settings).text == "почта ivanov@srv01.<TERM_1>"


@pytest.mark.parametrize("text, split, original", [
    ("Писал с petrov@domain-1.example", "Писал с <ACCOUNT_1>@domain-1.example", "Писал с petrov@contoso.ru"),
    ("почта petrov@srv02.domain-1.example", "почта <ACCOUNT_1>@host-2.domain-1.example", "почта petrov@srv02.contoso.ru"),
    (
        "почта postmaster@srv02.domain-1.example", "почта postmaster@host-2.domain-1.example",
        "почта postmaster@srv02.contoso.ru",
    ),
], ids=["login", "login-and-part", "role-mailbox-and-part"])
@pytest.mark.parametrize("policy", [Policy.MASK, Policy.HIDE, Policy.BLOCK])
def test_email_next_to_a_replacement_keeps_the_email_policy(state, text, split, original, policy):
    """Ревью раунда 5, P2: адрес рядом с выданной заменой делился (5.10), и его части держали политики ACCOUNT и HOST, а
    не EMAIL: при «скрывать без восстановления» <ACCOUNT_1>@domain-1.example восстанавливался в адрес целиком, при
    «блокировать» выдача не блокировалась. Адрес строже своих частей — одна метка EMAIL, и её значение — адрес с
    оригиналом замены, а не с подменой: так он восстанавливается и после смены политики, и сам адрес в тексте — та же
    метка. При обычной политике адрес делится, как прежде."""
    settings = Settings(policies=default_policies() | {T.EMAIL: policy})
    sanitize(state, "Сервер srv-dc01.contoso.ru", settings)
    result = sanitize(state, text, settings)
    expected = split if policy is Policy.MASK else text.rsplit(" ", 1)[0] + " <EMAIL_1>"
    assert result.sanitized == expected
    assert [state.entities[s.entity_id].type for s in result.blocked] == ([T.EMAIL] if policy is Policy.BLOCK else [])
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, expected, settings).sanitized == expected        # повторная вставка ничего не меняет
    assert sanitize(state, text, settings).sanitized == expected            # повторная очистка — тоже
    assert (len(state.entities), len(state.surrogates)) == counts
    restored = restore(state, expected, settings)
    assert restored.text == (expected if policy is Policy.HIDE else original)
    assert restore(state, expected, Settings()).text == original
    if policy is not Policy.MASK:
        assert sanitize(state, original, settings).sanitized == expected


@pytest.mark.parametrize("policies, text, expected", [
    (
        {T.EMAIL: Policy.HIDE, T.ACCOUNT: Policy.HIDE}, "Писал с petrov@domain-1.example",
        "Писал с <ACCOUNT_1>@domain-1.example",
    ),
    ({T.EMAIL: Policy.BLOCK}, "Ответ ушёл на postmaster@domain-1.example", "Ответ ушёл на postmaster@domain-1.example"),
    ({T.EMAIL: Policy.HIDE}, "Ответ ушёл на postmaster@domain-1.example", "Ответ ушёл на postmaster@domain-1.example"),
], ids=["parts-as-strict", "nothing-new-block", "nothing-new-hide"])
def test_email_next_to_a_replacement_is_split_when_its_parts_are_as_strict(state, policies, text, expected):
    """Обратная сторона: адрес, части которого не мягче его самого, делится, как прежде, а служебный ящик при выданном
    домене — та же замена, без новой сущности, и выдачу не блокирует."""
    settings = Settings(policies=default_policies() | policies)
    sanitize(state, "Сервер srv-dc01.contoso.ru", settings)
    before = len(state.entities)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    assert len(state.entities) == before + ("<ACCOUNT_1>" in expected)


def test_email_split_check_sees_the_type_a_retyped_part_gets(state):
    """Ревью раунда 6, P3: проверка, держат ли части адреса его политику, считала часть имени HOST, а часть, которой
    пользователь дал другой тип, получает метку этого типа. При EMAIL=HIDE, HOST=BLOCK и srv02 → TERM адрес делился на
    <ACCOUNT_1>@<TERM_1>.domain-1.example: ничто не блокировало, и ответ восстанавливал адрес целиком. Теперь правило
    мягче HOST часть и не получает (resolve._manual): она остаётся HOST и блокирует выдачу, а проверка видит тот же тип."""
    settings = Settings(policies=default_policies() | {T.EMAIL: Policy.HIDE, T.HOST: Policy.BLOCK})
    sanitize(state, "Сервер srv-dc01.contoso.ru", settings)
    ops.mask(state, "srv02", T.TERM)
    result = sanitize(state, "почта petrov@srv02.domain-1.example", settings)
    assert result.sanitized == "почта <ACCOUNT_1>@host-2.domain-1.example"
    assert [state.entities[s.entity_id].type for s in result.blocked] == [T.HOST]
    # Правило не мягче HOST — часть меткой правила, и проверка видит её тип: ACCOUNT и TERM не мягче EMAIL — адрес делится.
    strict = Settings(policies=default_policies() | {T.EMAIL: Policy.HIDE, T.ACCOUNT: Policy.HIDE, T.TERM: Policy.HIDE})
    assert sanitize(state, "почта petrov@srv02.domain-1.example", strict).sanitized == "почта <ACCOUNT_1>@<TERM_1>.domain-1.example"


@pytest.mark.parametrize("text, expected", [
    ("почта ivanov@host-1.fabrikam.ru", "почта <ACCOUNT_1>@host-1.domain-2.example"),
    ("почта ivanov@srv02.domain-1.example", "почта <EMAIL_1>"),
], ids=["domain-blocks", "no-domain"])
def test_email_next_to_a_replacement_is_split_when_a_part_blocks(state, text, expected):
    """Адрес не делится, только если ни одна его часть и так не блокирует выдачу: домен при DOMAIN=BLOCK блокирует её
    своей меткой, а «блокировать» строже «скрывать без восстановления». Часть имени перед заменой — не домен."""
    settings = Settings(policies=default_policies() | {T.EMAIL: Policy.HIDE, T.DOMAIN: Policy.BLOCK})
    sanitize(state, "узел srv01.contoso.ru", settings)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected
    blocked = [state.entities[s.entity_id].type for s in result.blocked]
    assert blocked == ([T.DOMAIN] if "domain-2" in expected else [])


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


@pytest.mark.parametrize("value, text, expected", [
    ("contoso.ru", "Проверь srv02.<TERM_1>", "Проверь host-1.<TERM_1>"),
    ("contoso.ru", "почта ivanov@<TERM_1>", "почта <ACCOUNT_1>@<TERM_1>"),
    ("deploy.sh", "Проверь srv02.<TERM_1>", "Проверь srv02.<TERM_1>"),
    ("setup.py", "Проверь srv02.<TERM_1>", "Проверь srv02.<TERM_1>"),
    ("deploy.sh", "почта ivanov@<TERM_1>", "почта ivanov@<TERM_1>"),
], ids=["domain", "domain-email", "script", "code", "script-email"])
def test_label_of_a_file_name_is_not_a_domain_next_to_names(state, settings, value, text, expected):
    """Второе ревью, Minor: метка, значение которой — имя файла с суффиксом-доменом (deploy.sh, setup.py), считалась
    меткой доменного имени — и в ссылке ответа, и здесь. Доменом её считают одинаково конвейер и восстановление
    (labels.domain_labels): только значение, которое слой 3 взял бы именем, — как srv02.deploy.sh в тексте он не скрывает."""
    ops.mask(state, value, T.TERM)
    assert sanitize(state, f"журнал {value}", settings).sanitized == "журнал <TERM_1>"
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable


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


@pytest.mark.parametrize("first", ["run", "person"])
def test_run_of_names_longer_than_a_name_neither_joins_a_person_nor_is_joined(state, first):
    """Наблюдение раунда 3 имён узлов, P3: «Иван Иван» словаря, слитое в «Иван Иван Иван Иван Иван» (5.7, шаг 2), задавало
    человеку значение для восстановления в пять слов (5.9: самое полное написание): позже найденное «Иван Иван»
    присоединялось к слиянию и восстанавливалось пятью словами, а слияние после «Иван Иван» подменяло значение человека.
    Слияние длиннее имени — не упоминание: оно восстанавливается как написано, человек — своим написанием."""
    settings = Settings(always=(DictEntry(T.PERSON, "Иван Иван"),))
    run, person = "Иван Иван Иван Иван Иван", "Пришёл Иван Иван."
    texts = (run, person) if first == "run" else (person, run)
    sanitized = {text: sanitize(state, text, settings).sanitized for text in texts}
    assert re.fullmatch(r"<PERSON_\d>", sanitized[run]) and re.fullmatch(r"Пришёл <PERSON_\d>\.", sanitized[person])
    assert sanitized[run] not in sanitized[person]
    for text in texts:
        assert restore(state, sanitized[text], settings).text == text
        assert sanitize(state, text, settings).sanitized == sanitized[text]


def test_run_of_overlapping_findings_up_to_four_words_is_one_person(state, settings):
    """Та же находка с другой стороны: слияние до четырёх слов — имя (5.7, шаг 3), и упоминание человека к нему
    присоединяется, а значение для восстановления — самое полное написание, как прежде (5.9)."""
    ner = Marks({"Иванов Иван": T.PERSON, "Иван Иванович": T.PERSON})
    assert sanitize(state, "Звонил Иванов Иван Иванович.", settings, Layers(ner=ner)).sanitized == "Звонил <PERSON_1>."
    later = sanitize(state, "Позже Иванов перезвонил", settings, Layers(ner=Marks({"Иванов": T.PERSON})))
    assert later.sanitized == "Позже <PERSON_1> перезвонил"
    assert restore(state, later.sanitized, settings).text == "Позже Иванов Иван Иванович перезвонил"


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


@pytest.mark.parametrize("text, expected", [
    ("SSL: *.contoso.ru и *.corp.contoso.local", "SSL: *.domain-1.example и *.host-1.domain-2.example"),
    ("Set-Cookie: sid=1; Domain=.contoso.ru; Path=/", "Set-Cookie: sid=1; Domain=.domain-1.example; Path=/"),
    ("no_proxy=localhost,.contoso.ru,.corp.local", "no_proxy=localhost,.domain-1.example,.domain-2.example"),
    ("все адреса @contoso.ru пересылать", "все адреса @domain-1.example пересылать"),
], ids=["wildcard", "cookie", "no-proxy", "mail-routing"])
def test_name_after_a_leading_dot_star_or_at_is_masked_and_restored(state, settings, text, expected):
    """Второе ревью, P1: имя после «*.», «.» и «@» без имени входа уходило в облако. Ведущий знак остаётся, имя — как
    любое имя с точкой; восстанавливается точно и как имя из запроса, повторная вставка ничего не меняет, известное имя
    в такой записи видит проверка утечек."""
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, expected, settings).sanitized == expected
    assert (len(state.entities), len(state.surrogates)) == counts
    restored = restore(state, expected, settings)
    assert restored.text == text and restored.counters["derived"] == 0
    assert leakcheck.check(text, state, settings)


def test_dotfiles_and_code_after_a_dot_or_at_keep_their_meaning(state, settings):
    """Та же находка с другой стороны: файлы на точку, «@» в CSS и Java, многоточие остаются как есть."""
    text = "cp .env.example .env.local; .gitignore, *.py, .NET; @media print {} @Override; Ну...ru"
    assert sanitize(state, text, settings).sanitized == text


def test_regex_inside_a_string_literal_is_masked_and_restored_with_its_escapes(state, settings):
    """Второе ревью, P3: выражение внутри строки JSON, Java, C# пишут через «\\\\.» («\\.» после раскрытия строки), и имя,
    адрес e-mail и IP в нём уходили в облако. Подмены пишутся тем же разделителем, восстановление возвращает его,
    повторная вставка ничего не меняет, известное имя в такой записи видит проверка утечек; путь Windows в JSON — путь."""
    text = (
        r'{"host": "^www\\.contoso\\.ru$", "node": "^srv01\\.contoso\\.ru$", "from": "^ivanov@contoso\\.ru$", '
        r'"allow": "^10\\.1\\.2\\.35$", "path": "C:\\Users\\petrov\\.android"}'
    )
    result = sanitize(state, text, settings)
    fake_ip = result.spans[-2].surrogate
    assert result.sanitized == (
        r'{"host": "^www\\.domain-1\\.example$", "node": "^host-1\\.domain-1\\.example$", "from": "^<EMAIL_1>$", '
        rf'"allow": "^{fake_ip}$", "path": "C:\\Users\\<ACCOUNT_1>\\.android"}}'
    )
    assert fake_ip.count("\\\\.") == 3 and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert (len(state.entities), len(state.surrogates)) == counts
    assert restore(state, result.sanitized, settings).text == text
    planted = r'"^Mail\\.Contoso\\.ru$"'
    assert [planted[leak.start:leak.end] for leak in leakcheck.check(planted, state, settings)] == [r"Contoso\\.ru"]
    # После знака выражения и между «\\b»: «\\» там восстановление читает началом адреса без схемы (раздел 7, шаг 1).
    bounded = sanitize(state, r'"\\bsrv01\\.contoso\\.ru\\b", ".*\\.msk\\.contoso\\.ru"', settings).sanitized
    assert bounded == r'"\\bhost-1\\.domain-1\\.example\\b", ".*\\.host-2\\.domain-1\\.example"'


def test_email_written_with_escaped_dots_is_masked_and_restored_with_them(state, settings):
    """Второе ревью, P2: в «^ivanov@contoso\\.ru$» скрывался только домен, а имя входа уходило в облако. Адрес через «\\.»
    — адрес; его значение — как написано, и метка восстанавливается с «\\.»: тот же адрес в прозе — своя метка со своим
    написанием. Повторная вставка ничего не меняет, известный адрес через «\\.» проверка утечек видит."""
    text = r'if address :regex "from" "^i\.ivanov@contoso\.ru$" и почта i.ivanov@contoso.ru'
    result = sanitize(state, text, settings)
    assert result.sanitized == r'if address :regex "from" "^<EMAIL_1>$" и почта <EMAIL_2>' and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert (len(state.entities), len(state.surrogates)) == counts
    assert restore(state, result.sanitized, settings).text == text
    planted = r"^I\.Ivanov@Contoso\.ru$"
    assert {planted[leak.start:leak.end] for leak in leakcheck.check(planted, state, settings)} == {planted[1:-1]}


@pytest.mark.parametrize("text, expected", [
    (r"^ivanov@domain-1\.example$", r"^<ACCOUNT_1>@domain-1\.example$"),
    (r"^ivanov@srv02\.domain-1\.example$", r"^<ACCOUNT_1>@host-2\.domain-1\.example$"),
], ids=["issued-domain", "part-before-issued"])
def test_email_with_escaped_dots_next_to_a_replacement_keeps_them(state, settings, text, expected):
    """Адрес через «\\.» рядом с выданной заменой делится, как через точку (5.10): имя входа — ACCOUNT, часть перед
    заменой — часть имени, и разделитель остаётся тем же."""
    sanitize(state, "узел srv01.contoso.ru", settings)
    result = sanitize(state, text, settings)
    assert result.sanitized == expected and result.deliverable
    assert sanitize(state, expected, settings).sanitized == expected
    assert restore(state, expected, settings).text == text.replace("domain-1", "contoso").replace("example", "ru")


def test_email_written_with_an_escaped_at_is_masked_and_restored_with_it(state, settings):
    """Ревью раунда 5, P3: в строке Perl и PHP «ivanov\\@contoso.ru» скрывался только домен, а имя входа уходило в облако.
    Адрес через «\\@» — адрес; значение — как написано, и метка восстанавливается с «\\@», как адрес через «\\.». Рядом с
    выданной заменой он делится, и «\\» остаётся перед «@». Повторная вставка ничего не меняет."""
    text = r'my $to = "ivanov\@contoso.ru"; # и почта ivanov@contoso.ru'
    result = sanitize(state, text, settings)
    assert result.sanitized == r'my $to = "<EMAIL_1>"; # и почта <EMAIL_2>' and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert (len(state.entities), len(state.surrogates)) == counts
    assert restore(state, result.sanitized, settings).text == text
    sanitize(state, "узел srv01.contoso.ru", settings)
    near = r'$cc = "petrov\@srv02.domain-1.example";'
    expected = r'$cc = "<ACCOUNT_1>\@host-2.domain-1.example";'
    assert sanitize(state, near, settings).sanitized == expected
    assert sanitize(state, expected, settings).sanitized == expected
    assert restore(state, expected, settings).text == r'$cc = "petrov\@srv02.contoso.ru";'


def test_ipv4_written_with_escaped_dots_is_one_address_with_the_same_separators(state, settings):
    """Второе ревью, P2: «^10\\.1\\.2\\.35$» не находился, а известный адрес в такой записи получал отдельную метку <IP_N>.
    Это тот же адрес — та же сущность и та же подмена, записанная через «\\.»; восстановление пишет оригинал с тем же
    разделителем, и производный адрес той же сети /24 — тоже. Повторная вставка ничего не меняет."""
    text = r"узел 10.1.2.35, правило ^10\.1\.2\.35$ и сеть 10\.1\.0\.0/16"
    result = sanitize(state, text, settings)
    plain, escaped, network = (span.surrogate for span in result.spans)
    assert escaped == plain.replace(".", "\\.") and network.endswith(r"\.0\.0/16") and "<IP_" not in result.sanitized
    assert len(state.entities) == 2 and result.deliverable
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, result.sanitized, settings).sanitized == result.sanitized
    assert (len(state.entities), len(state.surrogates)) == counts
    assert restore(state, result.sanitized, settings).text == text
    derived = escaped.rsplit("\\.", 1)[0] + r"\.36"
    assert restore(state, f"^{derived}$", settings).text == r"^10\.1\.2\.36$"


def test_known_ipv4_written_with_escaped_dots_is_caught_by_the_leak_check(state, settings):
    """Та же находка: известный адрес через «\\.» проверка утечек видит и по написанию, и в записи с нулями впереди."""
    sanitize(state, "узел 10.1.2.35", settings)
    planted = r"^10\.1\.2\.35$ и 010\.001\.002\.035"
    found = [planted[leak.start:leak.end] for leak in leakcheck.check(planted, state, settings)]
    assert found == [r"10\.1\.2\.35", r"010\.001\.002\.035"]


def test_opened_address_stays_open_written_with_escaped_dots(state):
    """Список «никогда не скрывать» открывает адрес в любой записи (5.7, шаг 5) — и через «\\.»."""
    text = r"allow ^10\.1\.2\.35$; deny 10\.1\.2\.36"
    result = sanitize(state, text, Settings(never=frozenset({"10.1.2.35"})))
    assert result.sanitized.startswith(r"allow ^10\.1\.2\.35$; deny 10\.") and result.sanitized != text


def test_documentation_address_written_with_escaped_dots_is_not_given_as_a_surrogate(state, settings):
    """Подмена не совпадает с адресом текста и в записи через «\\.»: иначе восстановление сделало бы из примера
    203\\.0\\.113\\.1 публичный адрес (6.2)."""
    text = r"пример ^203\.0\.113\.1$, узел 8.8.4.4"
    result = sanitize(state, text, settings)
    assert result.sanitized == r"пример ^203\.0\.113\.1$, узел 203.0.113.2"
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


def test_checked_strings_do_not_join_into_a_leak_across_their_boundary(state):
    """FINDINGS «`checked_leaks` находит «утечку» на стыке двух блоков»: строки проверяются одним проходом, но значение
    словаря, которое начинается в одной строке и кончается в следующей, — не утечка: такого текста провайдер не получит.
    В одной строке оно по-прежнему утечка."""
    from cleaner.core.pipeline import checked_leaks

    always = Settings(always=(DictEntry(T.PERSON, "Анна Смирнова"),))
    assert checked_leaks(["отчёт подготовила Анна", "Смирнова — бухгалтер"], state, always) == []
    assert len(checked_leaks(["отчёт", "подготовила Анна\n\nСмирнова"], state, always)) == 1


def test_known_number_in_another_notation_is_hidden(state, settings):
    """FINDINGS «Известный чату номер в другой записи не скрывается и не ловится проверкой утечек»: слой известных
    значений ищет номер чата по цифрам — в строке CSV, без кода страны, с другими разделителями, в ответе модели."""
    sanitize(state, "тел. +7 (903) 111-22-33, ИНН 7707083893, паспорт 4508 123456", settings)
    for text in ("Петров;9031112233;Москва", "903 111-22-33", "77 07 08 38 93", "серия и номер 4508123456"):
        result = sanitize(state, text, settings)
        assert not re.search(r"\d{2}", result.sanitized.replace("_1>", "").replace("_2>", "")), result.sanitized
        assert result.leaks == []
    answer = sanitize(state, "Перезвоните на 903-111-22-33", settings, detectors=(dictionary_layer,))
    assert answer.sanitized.startswith("Перезвоните на <PHONE_")
    unrelated = "счёт 12349031112233 от 12.03.2026 на 4508 руб."
    assert sanitize(state, unrelated, Settings(), detectors=(dictionary_layer,)).sanitized == unrelated


def test_dictionary_entry_in_all_cases_is_hidden_with_one_label_and_checked_for_leaks(state):
    """IDEAS «Словарь: падежные формы для людей, организаций и терминов»: запись с отметкой «искать во всех падежах»
    скрывает формы значения одной меткой при выключенном слое 4, и проверка утечек их видит."""
    person = dictionary_layer.entry(T.PERSON, "Смирнова Анна Петровна", (), True)
    always = Settings(always=(person, dictionary_layer.entry(T.TERM, "Проект Полярис", (), True)))
    result = sanitize(state, "Передайте Смирновой Анне Петровне отчёт по Проекту Полярис.", always)
    assert result.sanitized == "Передайте <PERSON_1> отчёт по <TERM_1>."
    assert sanitize(state, "Смирнова Анна Петровна", always).sanitized == "<PERSON_1>"
    [entity] = [e for e in state.entities.values() if e.type is T.PERSON]
    assert entity.id in [leak.entity_id for leak in leakcheck.check("письмо Смирновой Анне Петровне", state, always)]
    plain = Settings(always=(DictEntry(T.PERSON, "Смирнова Анна Петровна"),))
    fresh_state = type(state)(chat_id="plain", net_key=state.net_key)
    assert leakcheck.check("письмо Смирновой Анне Петровне", fresh_state, plain) == []
