import pytest

from cleaner.core import leakcheck
from cleaner.core.detect import infra
from cleaner.core.entities import ops
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import restore
from cleaner.core.types import ChatRule, DictEntry, Policy, Settings, default_policies
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
