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
], ids=["domain-after", "part-before", "foreign-label", "domain-after-org", "part-before-org", "part-before-name"])
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


def test_rule_inside_a_name_with_a_label_part_leaves_the_label(state, settings):
    """Правило пользователя поглощает фрагмент целиком (5.7): метка во фрагмент имени не входит и остаётся (FR-5.9)."""
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == "srv01").id, T.TERM)
    sanitize(state, "узел srv01.contoso.ru и srv01", settings)
    ops.mask(state, "fabrikam", T.TERM)
    assert sanitize(state, "Проверь <TERM_1>.fabrikam.ru", settings).sanitized == "Проверь <TERM_1>.<TERM_2>"


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
