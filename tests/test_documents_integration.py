"""Docling на сгенерированных документах, без сети (NFR-2, AC-2.2 — часть, которую можно проверить без сервера)."""
import io
import os
from email.message import EmailMessage
from pathlib import Path

import pytest
from pdfgen import make_pdf

from cleaner.ingest.documents import Docling
from cleaner.ingest.extract import ExtractError, Extractor
from cleaner.models import DOCLING_DIR

pytestmark = pytest.mark.integration
CANARY = "petrov.check@kontora-test.ru"
LINE = f"Сотрудник Петров Иван, почта {CANARY}, узел srv-check-01."


@pytest.fixture(scope="module")
def docling():
    models_dir = Path(os.environ.get("CLEANER_MODELS_DIR", Path(__file__).resolve().parents[1] / "models"))
    if not (models_dir / DOCLING_DIR).is_dir():
        pytest.fail(f"нет моделей Docling в {models_dir}: python -m cleaner models download --only docling")
    return Docling(models_dir / DOCLING_DIR)


def office_files() -> dict[str, bytes]:
    from docx import Document
    from openpyxl import Workbook
    from pptx import Presentation

    doc = Document()
    doc.add_paragraph(LINE)
    docx = io.BytesIO()
    doc.save(docx)
    book = Workbook()
    book.active.append(["Сотрудник", "Почта"])
    book.active.append(["Петров Иван", CANARY])
    xlsx = io.BytesIO()
    book.save(xlsx)
    deck = Presentation()
    slide = deck.slides.add_slide(deck.slide_layouts[5])
    slide.shapes.title.text = LINE
    pptx = io.BytesIO()
    deck.save(pptx)
    mail = EmailMessage()
    mail["Subject"] = "Проверка"
    mail["From"] = CANARY
    mail.set_content(LINE)
    return {
        "docx": docx.getvalue(), "xlsx": xlsx.getvalue(), "pptx": pptx.getvalue(),
        "html": f"<html><body><p>{LINE}</p></body></html>".encode("utf-8"), "eml": mail.as_bytes(),
    }


@pytest.mark.parametrize("kind", ["docx", "xlsx", "pptx", "html", "eml"])
def test_office_mail_and_web_documents_convert_offline(docling, kind, no_network):
    assert CANARY in docling.convert(office_files()[kind], kind)


@pytest.mark.parametrize("kind", ["docx", "xlsx", "pptx"])
def test_size_check_lets_ordinary_office_files_through_to_docling(docling, kind, no_network):
    """Проверка размера до Docling не отклоняет обычный файл, сохранённый python-docx, openpyxl и python-pptx."""
    assert CANARY in Extractor(docling, lambda image, mime: "").extract(f"file.{kind}", office_files()[kind]).text


def test_spreadsheet_stays_a_table(docling, no_network):
    markdown = docling.convert(office_files()["xlsx"], "xlsx")
    assert "Петров Иван" in markdown and "|" in markdown          # FR-2.3: таблица остаётся таблицей


def test_pdf_pages_convert_offline(docling, no_network):
    pages = docling.pdf_pages(make_pdf([f"Contact {CANARY}.", "Second page."]), [1, 2])
    assert CANARY in pages[1] and "Second page." in pages[2]


def test_paragraph_continued_on_the_next_page_is_neither_lost_nor_repeated(docling, no_network):
    """Docling относит абзац, продолженный на следующей странице, к первой из них."""
    pages = docling.pdf_pages(make_pdf([f"Contact {CANARY}", "and his deputy"]), [1, 2])
    joined = "\n".join(pages.values())
    assert CANARY in joined and joined.count("and his deputy") == 1


def test_damaged_office_file_is_refused(docling, no_network):
    with pytest.raises(ExtractError):
        docling.convert(b"PK\x03\x04broken", "docx")
