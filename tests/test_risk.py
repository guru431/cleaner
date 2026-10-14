import json

import pytest

from cleaner.core import risk
from cleaner.core.detect.base import DetectorError
from cleaner.core.detect.llm import CompletionError


class Completer:
    def __init__(self, answer):
        self.answer, self.requests = answer, []

    def complete(self, messages, *, max_tokens, json_schema=None):
        self.requests.append(json_schema)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_guesses_keep_only_verbatim_clues_and_known_kinds():
    answer = json.dumps({"guesses": [
        {"kind": "org", "guess": "Ромашка", "clue": "производитель кормов из Тестовска"},
        {"kind": "person", "guess": "Петров", "clue": "нет такой цитаты"},
        {"kind": "weather", "guess": "дождь", "clue": ""},
        {"kind": "org", "guess": "ромашка", "clue": ""},
    ]}, ensure_ascii=False)
    completer = Completer(answer)
    guesses = risk.check(completer, "<ORG_1> — производитель кормов из Тестовска")
    assert guesses == [
        risk.Guess("org", "Ромашка", "производитель кормов из Тестовска"), risk.Guess("person", "Петров", ""),
    ]
    assert completer.requests == [risk.SCHEMA]
    assert risk.to_dict(guesses)["guesses"][1] == {"kind": "person", "guess": "Петров", "clue": ""}


def test_failures_name_the_check():
    with pytest.raises(DetectorError, match="Проверка остаточного риска: локальная модель недоступна"):
        risk.check(Completer(CompletionError("unavailable", "локальная модель недоступна")), "текст")
    with pytest.raises(DetectorError, match="не разбирается"):
        risk.check(Completer("не JSON"), "текст")
