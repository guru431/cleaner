"""Исходящий запрос к облачной модели (раздел 10.1): собирается заново с текущими правилами чата."""
import pytest

from cleaner.core import pipeline
from cleaner.core.entities import ops
from cleaner.core.pipeline import (
    NotSendable, SanitizeResult, Turn, build_outgoing, probe_context, sanitize, system_prompt,
)
from cleaner.core.types import DictEntry, Policy, Settings, Span, default_policies
from cleaner.core.types import EntityType as T


def test_inputs_are_cleaned_again_with_current_rules(state, settings):
    text = "Проект «Ромашка» ведёт i.petrov@contoso.example"
    first = build_outgoing(state, [Turn("user", text)], settings, "p1", "m1").context
    assert "Ромашка" in first.messages[0].text
    ops.mask(state, "Ромашка", T.TERM)
    again = build_outgoing(state, [Turn("user", text)], settings, "p1", "m1").context
    assert "Ромашка" not in again.messages[0].text and "<TERM_1>" in again.messages[0].text
    assert again.messages[0].text.endswith("<EMAIL_1>")


def test_layer_4_findings_are_reused_without_the_model(state, settings):
    text = "Звонил Сидоров"
    cached = (Span(7, 14, T.PERSON, "ner", 0.9),)
    context = build_outgoing(state, [Turn("user", text, cached)], settings, "p1", "m1").context
    assert context.messages[0].text == "Звонил <PERSON_1>"


def test_original_in_an_answer_is_masked_in_the_next_request(state, settings):
    """FR-8.11: значение скрыли после ответа, в котором модель его повторила."""
    turns = [Turn("user", "Кто такой Сидоров?"), Turn("assistant", "Сидоров — сотрудник."), Turn("user", "А ещё?")]
    ops.mask(state, "Сидоров", T.PERSON)
    outgoing = build_outgoing(state, turns, settings, "p1", "m1")
    assert [m.text for m in outgoing.context.messages] == ["Кто такой <PERSON_1>?", "<PERSON_1> — сотрудник.", "А ещё?"]
    assert outgoing.sendable


def test_answer_is_not_searched_by_detectors_only_by_known_values(state, settings):
    """В ответе модели ищутся только известные значения: адрес, которого в чате не было, не новая сущность."""
    turns = [Turn("user", "Вопрос"), Turn("assistant", "Пример: admin@example.org"), Turn("user", "Дальше")]
    context = build_outgoing(state, turns, settings, "p1", "m1").context
    assert context.messages[1].text == "Пример: admin@example.org"
    assert not state.entities


def test_instruction_added_after_the_question_still_lets_it_go(state, settings):
    context = build_outgoing(state, [Turn("user", "Вопрос"), Turn("system", "Кратко")], settings, "p1", "m1").context
    assert context.system.endswith("Кратко") and [m.text for m in context.messages] == ["Вопрос"]


def test_instruction_goes_after_the_service_prompt(state, settings):
    turns = [Turn("system", "Отвечай кратко, автор — Сидоров", (Span(24, 31, T.PERSON, "ner"),)), Turn("user", "Вопрос")]
    context = build_outgoing(state, turns, settings, "p1", "m1").context
    assert context.system == system_prompt("angle") + "\n\nОтвечай кратко, автор — <PERSON_1>"
    assert [(m.role, m.text) for m in context.messages] == [("user", "Вопрос")]


def test_square_label_style_is_named_in_the_service_prompt():
    assert "[[PERSON_1]]" in system_prompt("square") and "<PERSON_1>" not in system_prompt("square")


def test_neighbouring_questions_are_joined_and_leading_answers_skipped(state, settings):
    turns = [Turn("assistant", "Старый ответ"), Turn("user", "Первый"), Turn("user", "Второй")]
    outgoing = build_outgoing(state, turns, settings, "p1", "m1")
    assert [(m.role, m.text) for m in outgoing.context.messages] == [("user", "Первый\n\nВторой")]
    assert outgoing.skipped == [0]


@pytest.mark.parametrize("turns", [[], [Turn("user", "Вопрос"), Turn("assistant", "Ответ")], [Turn("system", "Кратко")]])
def test_last_turn_must_be_a_question(state, settings, turns):
    with pytest.raises(NotSendable):
        build_outgoing(state, turns, settings, "p1", "m1")


def test_digest_changes_when_a_rule_is_added(state, settings):
    turns = [Turn("user", "Проект Ромашка")]
    before = build_outgoing(state, turns, settings, "p1", "m1").context.digest()
    assert build_outgoing(state, turns, settings, "p1", "m1").context.digest() == before
    assert build_outgoing(state, turns, settings, "p1", "m2").context.digest() != before
    ops.mask(state, "Ромашка", T.TERM)
    assert build_outgoing(state, turns, settings, "p1", "m1").context.digest() != before


def test_blocked_type_makes_the_request_unsendable(state):
    settings = Settings(policies={**default_policies(), T.EMAIL: Policy.BLOCK})
    outgoing = build_outgoing(state, [Turn("user", "почта a@contoso.example")], settings, "p1", "m1")
    assert outgoing.blocked == 1 and not outgoing.sendable


def test_pasted_surrogate_of_a_blocked_entity_blocks_the_request_but_not_in_an_answer(state):
    """Вставленная пользователем замена сущности «блокировать» держит отправку, как оригинал (FR-4.2). В ответе модели
    ищутся только оригиналы (FR-8.11): подмена там — эхо отправленного, и её сущность держит отправку своим входным
    текстом. Оригинал, скрытый в ответе внутри другой метки, держит её и там (held)."""
    sanitize(state, "домен fabrikam.ru", Settings())
    blocked = Settings(policies=default_policies() | {T.DOMAIN: Policy.BLOCK}, always=(DictEntry(T.TERM, "fabrikam.ru srv"),))
    answer = [Turn("user", "Вопрос"), Turn("assistant", "Ответ про domain-1.example"), Turn("user", "Ещё")]
    assert build_outgoing(state, answer, blocked, "p1", "m1").sendable
    pasted = [Turn("user", "Вопрос про domain-1.example")]
    assert build_outgoing(state, pasted, blocked, "p1", "m1").blocked == 1
    hidden = [Turn("user", "Вопрос"), Turn("assistant", "Ответ: fabrikam.ru srv"), Turn("user", "Ещё")]
    outgoing = build_outgoing(state, hidden, blocked, "p1", "m1")
    assert outgoing.context.messages[1].text == "Ответ: <TERM_1>" and outgoing.blocked == 1


def test_dictionary_value_in_an_answer_is_masked(state, settings):
    always = Settings(always=(DictEntry(T.TERM, "Ромашка"),))
    turns = [Turn("user", "Вопрос"), Turn("assistant", "Ответ: проект Ромашка"), Turn("user", "Ещё")]
    outgoing = build_outgoing(state, turns, always, "p1", "m1")
    assert outgoing.context.messages[1].text == "Ответ: проект <TERM_1>"
    assert outgoing.sendable


def test_leak_is_reported_with_its_message(state, settings, monkeypatch):
    """SEC-2: проверяется итоговый текст. Сбой очистки (здесь — подменённой) не уходит незамеченным."""
    sanitize(state, "почта a@contoso.example", settings)
    monkeypatch.setattr(pipeline, "sanitize", lambda state, text, *args, **kwargs: SanitizeResult(text, []))
    turns = [Turn("system", "Кратко"), Turn("user", "почта a@contoso.example")]
    outgoing = build_outgoing(state, turns, settings, "p1", "m1")
    assert [number for number, _ in outgoing.leaks] == [0] and not outgoing.sendable


def test_probe_context_has_no_user_data():
    context = probe_context("p1", "m1")
    assert (context.chat_id, context.system) == ("", "")
    assert [m.text for m in context.messages] == ["Ответь одним словом: готово"]
