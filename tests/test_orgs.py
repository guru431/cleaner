import pytest

from cleaner.core.detect import orgs
from cleaner.core.detect.base import DetectContext
from cleaner.core.pipeline import sanitize
from cleaner.core.types import EntityType as T
from cleaner.core.types import Settings

CTX = DetectContext(Settings())


@pytest.mark.parametrize("name", [
    "ООО «Ромашка»", 'АО "Вектор-Плюс"', "Общество с ограниченной ответственностью «Заря»",
    "ПАО „Север“", "ооо «Ромашка»", "Публичное акционерное общество «Кедр»",
])
def test_legal_form_with_a_quoted_name_is_an_organisation(name):
    text = f"Договор с {name} подписан"
    [span] = orgs.detect(text, CTX)
    assert (span.type, text[span.start:span.end]) == (T.ORG, name)


@pytest.mark.parametrize("name", ["ООО Ромашка", "ГАО «Ромашка»", "«Ромашка»", "АО"])
def test_no_form_or_no_quotes_is_left_alone(name):
    assert orgs.detect(f"Договор с {name} подписан", CTX) == []


def test_one_organisation_whatever_the_legal_form(state, settings):
    """Ключ ORG — без формы и кавычек (раздел 5.8)."""
    assert sanitize(state, "ООО «Ромашка» и АО «Ромашка»", settings).sanitized == "<ORG_1> и <ORG_1>"
