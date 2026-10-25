"""Docling на сгенерированных документах, без сети (NFR-2, AC-2.2 — часть, которую можно проверить без сервера)."""
import io
import os
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest
from pdfgen import make_pdf

from cleaner.ingest.documents import Docling
from cleaner.ingest.extract import ExtractError, Extractor, _Text
from cleaner.models import DOCLING_DIR

# Находка «Layers 2 and 4 review round…»: предупреждение об устаревании — ошибка теста, кроме двух, которые Docling
# 2.131 выдаёт сам о своих полях: на каждом разборе PDF он сериализует настройки в ключ кэша конвейера (вычисляемое
# force_full_page_ocr настроек распознавания), а при сборке конвейера PDF читает generate_table_images. Cleaner
# ни то, ни другое не задаёт (do_ocr=False, картинок нет) — переходить не на что; новое устаревшее появится здесь.
DOCLING_OWN_DEPRECATIONS = (
    "ignore:`force_full_page_ocr` is deprecated:DeprecationWarning",
    "ignore:This field is deprecated. Use `generate_page_images=True`:DeprecationWarning",
)
# Предел 30 с из pytest.ini — не для этого модуля: первый тест импортирует docling и transformers, а на загруженной
# workstation холодный импорт шёл 33 с (25.10.2026), и pytest-timeout обрывал весь полный прогон.
pytestmark = [
    pytest.mark.integration, pytest.mark.filterwarnings("error::DeprecationWarning", *DOCLING_OWN_DEPRECATIONS),
    pytest.mark.timeout(120),
]
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


def test_hidden_sheets_are_left_out_by_docling_and_counted(docling, no_network):
    """Находка «Small gaps…»: скрытый лист Docling кладёт в невидимый слой — текста нет, предупреждение нужно."""
    from openpyxl import Workbook

    book = Workbook()
    book.active.append(["Сотрудник", "Петров Иван"])
    for state in ("hidden", "veryHidden"):
        sheet = book.create_sheet(state)
        sheet.append(["Почта", CANARY])
        sheet.sheet_state = state
    data = io.BytesIO()
    book.save(data)
    result = Extractor(docling, lambda image, mime: "").extract("book.xlsx", data.getvalue())
    assert ("Петров Иван" in result.text, CANARY in result.text, result.hidden_sheets) == (True, False, 2)


def text_estimate(data: bytes, kind: str) -> int:
    estimate = _Text(kind, max_chars=10**9)
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        for part in package.infolist():
            estimate.read(package, part)
    return estimate.chars


def rich_office_files() -> dict[str, bytes]:
    """Документ и презентация с тем, что Docling выводит, и с тем, чего не выводит (колонтитул, примечание,
    заметки, скрытый слайд и фигура, таблица на слайде)."""
    from docx import Document
    from pptx import Presentation
    from pptx.util import Inches

    doc = Document()
    doc.sections[0].header.paragraphs[0].text = f"Колонтитул {CANARY}"
    doc.add_heading("Отчёт о проверке", 1)
    run = doc.add_paragraph("Обычный абзац, ").add_run(LINE)
    run.bold = True
    doc.add_comment(run, text="Примечание рецензента", author="Рецензент")
    doc.add_paragraph("Первый пункт", style="List Bullet")
    table = doc.add_table(rows=3, cols=3)
    for index, cell in enumerate(table._cells):
        cell.text = f"ячейка {index}"
    table.cell(0, 0).merge(table.cell(0, 1))
    doc.add_table(rows=1, cols=1).cell(0, 0).text = "единственная ячейка"
    docx = io.BytesIO()
    doc.save(docx)

    deck = Presentation()
    first = deck.slides.add_slide(deck.slide_layouts[1])
    first.shapes.title.text = "Итоги квартала"
    first.placeholders[1].text = f"{LINE}\nВторой пункт"
    first.notes_slide.notes_text_frame.text = "Заметки докладчика"
    hidden = first.shapes.add_textbox(Inches(1), Inches(5), Inches(4), Inches(1))
    hidden.text_frame.text = "Скрытая надпись"
    hidden._element.nvSpPr.cNvPr.set("hidden", "1")
    group = first.shapes.add_group_shape()
    group.shapes.add_textbox(Inches(1), Inches(6), Inches(4), Inches(1)).text_frame.text = "Надпись в группе"
    second = deck.slides.add_slide(deck.slide_layouts[5])
    second.shapes.title.text = "Таблица"
    grid = second.shapes.add_table(2, 2, Inches(1), Inches(2), Inches(6), Inches(2)).table
    grid.cell(0, 0).text = "ячейка слайда"
    deck.slides.add_slide(deck.slide_layouts[5]).shapes.title.text = "Скрытый слайд"
    deck.slides[2]._element.set("show", "0")
    pptx = io.BytesIO()
    deck.save(pptx)
    return {"docx": docx.getvalue(), "pptx": pptx.getvalue()}


@pytest.mark.parametrize("kind", ["docx", "pptx"])
def test_text_estimate_is_below_the_docling_markdown(docling, kind, no_network):
    """Находка «Small gaps…»: оценка длины до Docling — снизу, иначе обычный файл получил бы отказ
    «текст заведомо длиннее»."""
    data = rich_office_files()[kind]
    markdown = "".join(docling.convert(data, kind).split())
    assert 0 < text_estimate(data, kind) <= len(markdown)


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


def test_scan_with_a_digital_header_keeps_both_the_header_and_the_recognised_page(docling, no_network):
    """Аудит 2026-10-21, находка 1, на настоящем Docling: страница — цифровой заголовок длиннее 20 знаков и
    растровое изображение на 74 % площади. Раньше в текст попадал один заголовок, а распознавание не вызывалось."""
    header = "Visible header for the financial report"
    calls = []

    def ocr(image, mime):
        calls.append((mime, image[:8]))
        return f"Balance sheet, contact {CANARY}"

    result = Extractor(docling, ocr).extract("report.pdf", make_pdf([(header, 600), "Plain second page of the report"]))
    assert calls == [("image/png", b"\x89PNG\r\n\x1a\n")]
    assert result.text.count(header) == 1 and CANARY in result.text and "Plain second page" in result.text
    assert (result.ocr_pages, result.unread_pages, result.doubtful_pages) == ((1,), (), ())


def test_scan_already_recognised_by_the_scanner_is_read_from_its_invisible_layer(docling, no_network):
    """Распознанный сканером PDF: растр на всю страницу и невидимый слой (3 Tr) поверх него. Его текст даёт Docling
    за секунды, распознавание (72 с на страницу) не вызывается."""
    body = "\n".join(f"Scanned line {n}: contact {CANARY}, invoice 2026-{n:03d}, total {n * 100} rub" for n in range(8))
    calls = []

    def ocr(image, mime):
        calls.append(mime)
        return "recognised again"

    result = Extractor(docling, ocr).extract("scan.pdf", make_pdf([("", 600, body)], invisible=True))
    assert calls == [] and (result.ocr_pages, result.doubtful_pages) == ((), ())
    assert result.text.count(CANARY) == 8 and "Scanned line 7" in result.text


def test_damaged_office_file_is_refused(docling, no_network):
    with pytest.raises(ExtractError):
        docling.convert(b"PK\x03\x04broken", "docx")
