"""Проверка начала этапа 2: Docling разбирает документы без сети, укладывается в норму NFR-4 (раздел 19 спецификации).

  python scripts/checks/docling_check.py [каталог моделей, по умолчанию models]
Модели и разбор — те же, что у службы: моделей Docling в каталоге нет — они скачиваются, как models download (нужен
интернет); документы разбирает ingest.documents.Docling при запрещённых соединениях.
"""
from __future__ import annotations

import io
import shutil
import socket
import sys
import time
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cleaner import models as model_files  # noqa: E402
from cleaner.ingest.documents import Docling  # noqa: E402


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
    [spec] = [spec for spec in model_files.SPECS if spec.directory == model_files.DOCLING_DIR]
    if not (models / spec.directory).is_dir():
        cache = model_files.prepare_download(models)
        try:
            model_files.install(models, spec)
        finally:
            shutil.rmtree(cache, ignore_errors=True)

    def refuse(*args, **kwargs):
        raise OSError("сеть запрещена проверкой")

    socket.socket.connect = refuse
    socket.create_connection = refuse
    docling = Docling(models / spec.directory)
    samples = documents()
    docling.convert(samples["html"], "html")          # загрузка Docling (до полуминуты) — вне замера
    for kind, data in samples.items():
        started = time.perf_counter()
        ok = "petrov.check@kontora-test.ru" in docling.convert(data, kind)
        print(f"C: {kind}: {'OK' if ok else 'НЕТ ТЕКСТА'} за {time.perf_counter() - started:.1f} с")
    started = time.perf_counter()
    docling.convert(documents(pages=50)["docx"], "docx")
    print(f"C: DOCX на 50 страниц — {time.perf_counter() - started:.1f} с (норма NFR-4 — 180 с)")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]) if len(sys.argv) == 2 else Path("models"))
