import json

import pytest

from cleaner.core import surrogates
from cleaner.core.detect.base import DetectorError
from cleaner.core.detect.llm import SCHEMA, CompletionError, LlmLayer, chunks, parse_items
from cleaner.core.pipeline import Layers, sanitize
from cleaner.core.types import ChatState


class Completer:
    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def complete(self, messages, *, max_tokens, json_schema=None):
        self.requests.append((messages[-1]["content"], json_schema))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def items(*pairs):
    return json.dumps({"items": [{"text": text, "type": kind} for text, kind in pairs]}, ensure_ascii=False)


def test_chunks_overlap_and_cover_the_text():
    assert chunks("x" * 13000) == [(0, 6000), (5500, 11500), (11000, 13000)]
    assert chunks("короткий") == [(0, 8)] and chunks("") == []


def test_string_found_verbatim_is_masked_everywhere_in_the_original(state, settings):
    """AC-4.1: пароль без ключевого слова находит только слой 5."""
    llm = LlmLayer(Completer(items(("sunflower77", "SECRET"))))
    text = "a@x.example, на стикере sunflower77; повторю: sunflower77"
    result = sanitize(state, text, settings, Layers(llm=llm))
    assert result.sanitized == "<EMAIL_1>, на стикере <SECRET_1>; повторю: <SECRET_1>"


def test_strings_absent_from_the_text_are_dropped(state, settings):
    """AC-4.1, вторая часть; обзор плана 2+4, пункт 4: позиции находит код, а не модель."""
    answer = items(("Сидоров", "PERSON"), ("Иван Петров", "PERSON"), ("<EMAIL_1>", "EMAIL"), ("x", "TERM"))
    result = sanitize(state, "a@x.example, отвечает Сидоров", settings, Layers(llm=LlmLayer(Completer(answer))))
    assert result.sanitized == "<EMAIL_1>, отвечает <PERSON_1>"
    assert [s.source for s in result.model_spans] == ["llm"]


def test_answer_in_a_fence_or_after_reasoning_is_read():
    for raw in ("```json\n" + items(("Сидоров", "PERSON")) + "\n```", "<think>ищу</think>" + items(("Сидоров", "PERSON"))):
        assert parse_items(raw) == [("Сидоров", "PERSON")]
    with pytest.raises(ValueError):
        parse_items('{"найдено": []}')


def test_unknown_type_becomes_a_term(state, settings):
    llm = LlmLayer(Completer(items(("Заря", "PROJECT"))))
    assert sanitize(state, "проект Заря", settings, Layers(llm=llm)).sanitized == "проект <TERM_1>"


def test_truncated_answer_is_retried_in_halves_then_fails(state, settings):
    """Раздел 5.6, шаг 4; обзор плана 2+4, пункт 4."""
    length = CompletionError("length", "ответ локальной модели обрезан по длине")
    recovered = Completer(items(), length, items(), items())
    sanitize(state, "слово " * 1500, settings, Layers(llm=LlmLayer(recovered)))       # 9000 знаков — две части
    assert [len(chunk) for chunk, _ in recovered.requests] == [6000, 3500, 2000, 1750]
    other = ChatState(chat_id="other", net_key=bytes(32))
    with pytest.raises(DetectorError, match="обрезан"):
        sanitize(other, "слово " * 100, settings, Layers(llm=LlmLayer(Completer(length, length))))


def test_empty_answer_is_retried_in_halves_then_fails(state, settings):
    """Обзор плана 2+4, m-9: пустой ответ — как невалидный, а не отказ с первого раза."""
    empty = CompletionError("empty", "локальная модель вернула пустой ответ")
    recovered = Completer(empty, items(("Сидоров", "PERSON")), items(), items())
    result = sanitize(state, "отвечает Сидоров " * 400, settings, Layers(llm=LlmLayer(recovered)))   # 6800 знаков
    assert [len(chunk) for chunk, _ in recovered.requests] == [6000, 3250, 3000, 1300]
    assert "Сидоров" not in result.sanitized
    other = ChatState(chat_id="other", net_key=bytes(32))
    with pytest.raises(DetectorError, match="Слой 5: локальная модель вернула пустой ответ"):
        sanitize(other, "слово " * 100, settings, Layers(llm=LlmLayer(Completer(empty, empty))))


def test_garbage_is_retried_once_then_fails(state, settings):
    with pytest.raises(DetectorError, match="не разбирается"):
        sanitize(state, "текст", settings, Layers(llm=LlmLayer(Completer("не JSON", "опять не JSON"))))


def test_unavailable_model_fails_at_once(state, settings):
    completer = Completer(CompletionError("unavailable", "локальная модель недоступна"))
    with pytest.raises(DetectorError, match="Слой 5: локальная модель недоступна"):
        sanitize(state, "почта a@x.example", settings, Layers(llm=LlmLayer(completer)))
    assert len(completer.requests) == 1


def test_replacement_search_is_built_once_per_pass(state, monkeypatch):
    """FINDINGS P3 «На горячем пути слоя 5 для каждого кандидата модели заново с…»: поиск замен собирался на каждую
    строку модели и каждый раз проходил всю таблицу чата — 4 с на 120 000 знаков при 12 000 заменах."""
    built = []

    class Counted(surrogates.Finder):
        def __init__(self, *args, **kwargs):
            built.append(1)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(surrogates, "Finder", Counted)
    answer = items(*((f"слово{n}", "TERM") for n in range(30)))
    text = " ".join(f"слово{n}" for n in range(1200))      # две части
    LlmLayer(Completer(answer, answer)).find(text, text, state)
    assert built == [1]


def test_schema_is_sent_only_when_the_setting_says_so():
    first, second = Completer(items()), Completer(items())
    LlmLayer(first).find("текст", "текст", ChatState("c", bytes(32)))
    LlmLayer(second, send_schema=False).find("текст", "текст", ChatState("c", bytes(32)))
    assert first.requests[0][1] == SCHEMA and second.requests[0][1] is None
