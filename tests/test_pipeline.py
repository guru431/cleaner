import pytest

from cleaner.core import leakcheck
from cleaner.core.detect import infra
from cleaner.core.pipeline import sanitize
from cleaner.core.types import ChatRule, Policy, Settings, default_policies
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
