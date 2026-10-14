"""Проверка начала этапа 2: Docling разбирает документы без сети, укладывается в норму NFR-4 (раздел 19 спецификации).

  python scripts/checks/docling_check.py <каталог для моделей>
Сначала скачивает модели Docling в каталог (нужен интернет), потом разбирает документы при запрещённых соединениях.
"""
from __future__ import annotations

import io
import socket
import sys
import time
from email.message import EmailMessage
from pathlib import Path


def documents(pages: int = 1) -> dict[str, bytes]:
    from docx import Document
    from openpyxl import Workbook
    from pptx import Presentation

    line = "Сотрудник Петров Иван, почта petrov.check@kontora-test.ru, узел srv-check-01."
    doc = Document()
    for n in range(pages):
        doc.add_paragraph(f"{n + 1}. {line}")
        if pages > 1:
            doc.add_page_break()
    docx = io.BytesIO()
    doc.save(docx)
    book = Workbook()
    book.active.append(["Сотрудник", "Почта"])
    book.active.append(["Петров Иван", "petrov.check@kontora-test.ru"])
    xlsx = io.BytesIO()
    book.save(xlsx)
    deck = Presentation()
    slide = deck.slides.add_slide(deck.slide_layouts[5])
    slide.shapes.title.text = line
    pptx = io.BytesIO()
    deck.save(pptx)
    mail = EmailMessage()
    mail["Subject"] = "Проверка"
    mail["From"] = "petrov.check@kontora-test.ru"
    mail.set_content(line)
    return {
        "docx": docx.getvalue(), "xlsx": xlsx.getvalue(), "pptx": pptx.getvalue(),
        "html": f"<html><body><p>{line}</p></body></html>".encode("utf-8"), "eml": mail.as_bytes(),
    }


def main(models: Path) -> None:
    from docling.utils.model_downloader import download_models

    download_models(
        output_dir=models, with_layout=True, with_tableformer=True, with_code_formula=False,
        with_picture_classifier=False, with_rapidocr=False, with_easyocr=False,
    )

    def refuse(*args, **kwargs):
        raise OSError("сеть запрещена проверкой")

    socket.socket.connect = refuse
    socket.create_connection = refuse
    from docling.datamodel.accelerator_options import AcceleratorOptions
    from docling.datamodel.base_models import DocumentStream, InputFormat
    from docling.datamodel.pipeline_options import PdfPipelineOptions
    from docling.document_converter import DocumentConverter, PdfFormatOption

    options = PdfPipelineOptions(
        artifacts_path=models, do_ocr=False, do_table_structure=True,
        accelerator_options=AcceleratorOptions(num_threads=4, device="cpu"),
    )
    converter = DocumentConverter(format_options={InputFormat.PDF: PdfFormatOption(pipeline_options=options)})
    for kind, data in documents().items():
        started = time.perf_counter()
        result = converter.convert(DocumentStream(name=f"document.{kind}", stream=io.BytesIO(data)))
        markdown = result.document.export_to_markdown(escape_html=False, escape_underscores=False)
        ok = "petrov.check@kontora-test.ru" in markdown
        print(f"C: {kind}: {'OK' if ok else 'НЕТ ТЕКСТА'} за {time.perf_counter() - started:.1f} с")
    started = time.perf_counter()
    converter.convert(DocumentStream(name="document.docx", stream=io.BytesIO(documents(pages=50)["docx"])))
    print(f"C: DOCX на 50 страниц — {time.perf_counter() - started:.1f} с (норма NFR-4 — 180 с)")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
