"""Слой 4 с настоящими моделями: русские имена, английские имена и организации, без сети (NFR-2, AC-2.1)."""
import os
from pathlib import Path

import pytest

from cleaner.core.detect.base import DetectorError
from cleaner.core.detect.ner_models import NerModels
from cleaner.core.pipeline import Layers, sanitize
from cleaner.core.types import ChatState
from cleaner.core.types import EntityType as T

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def layer():
    patch = pytest.MonkeyPatch()
    patch.setenv("HF_HUB_OFFLINE", "1")
    patch.setenv("TRANSFORMERS_OFFLINE", "1")
    models_dir = Path(os.environ.get("CLEANER_MODELS_DIR", Path(__file__).resolve().parents[1] / "models"))
    try:
        yield NerModels(models_dir).layer()
    except DetectorError as exc:
        pytest.fail(f"{exc} (каталог {models_dir})")
    finally:
        patch.undo()


def test_russian_names_are_found(layer, no_network):
    text = "Иванов Иван Иванович написал. Позвоните Иванову Ивану Ивановичу."
    found = [text[s.start:s.end] for s in layer.detect(text) if s.type is T.PERSON]
    assert any("Иванов" in value for value in found) and any("Иванову" in value for value in found), found


def test_english_name_and_organisation_are_found(layer, no_network):
    text = "Please contact John Smith from Contoso Pharmaceuticals about the invoice."
    found = {(text[s.start:s.end], s.type) for s in layer.detect(text)}
    assert ("John Smith", T.PERSON) in found and any(type_ is T.ORG for _, type_ in found), found


def test_common_words_are_not_organisations(layer, no_network):
    """GLiNER называет «банк» организацией с уверенностью около 0,77: строчные существительные отсеиваются."""
    text = "Счёт выставили из бухгалтерии, сверку прислал банк."
    assert [text[s.start:s.end] for s in layer.detect(text) if s.type is T.ORG] == []


def test_organisation_with_a_digit_is_not_an_address(layer, no_network):
    """GLiNER называет «1С» в этой фразе адресом («location address», около 0,49): без номера дома это не адрес."""
    text = "Копию отправили в Сбербанк и в 1С."
    assert [text[s.start:s.end] for s in layer.detect(text) if s.type is T.ADDRESS] == []


def test_password_taken_for_a_name_is_typed_by_layer_5(layer, no_network, state, settings, engines):
    """AC-4.1 на example: GLiNER называет «sunflower77» именем; со слоем 5 — SECRET, без него — скрыт как PERSON."""
    text = "Для общего ящика на стикере записано: sunflower77, отвечает Сидоров"
    without = sanitize(state, text, settings, Layers(ner=layer)).sanitized
    assert without == "Для общего ящика на стикере записано: <PERSON_1>, отвечает <PERSON_2>"
    engines.second.marks = {"sunflower77": T.SECRET}
    result = sanitize(ChatState(chat_id="second", net_key=bytes(32)), text, settings, Layers(ner=layer, llm=engines.second))
    assert result.sanitized == "Для общего ящика на стикере записано: <SECRET_1>, отвечает <PERSON_1>"


def test_three_cases_get_one_label_with_real_models(layer, no_network, state, settings):
    """AC-2.1 с настоящими моделями."""
    text = (
        "Иванов Иван Иванович написал. Позвоните Иванову Ивану Ивановичу. "
        "Нет Иванова Ивана Ивановича. Иванов ответит."
    )
    result = sanitize(state, text, settings, Layers(ner=layer))
    assert result.sanitized == "<PERSON_1> написал. Позвоните <PERSON_1>. Нет <PERSON_1>. <PERSON_1> ответит."
