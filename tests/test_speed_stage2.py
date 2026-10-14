"""Замеры NFR-4 для этапа 2: запуск руками, с моделями из models/ (или $CLEANER_MODELS_DIR).

  .venv/Scripts/python.exe -m pytest tests/test_speed_stage2.py -m manual -s
Числа записываются в раздел 19 спецификации; на сервере — то же из установленного кода (задача 26).
"""
import io
import os
import time
from pathlib import Path

import pytest
from pdfgen import make_pdf

from cleaner.core.detect.ner_models import NerModels
from cleaner.core.pipeline import Layers, sanitize
from cleaner.core.types import ChatState, Settings
from cleaner.ingest.documents import Docling
from cleaner.models import DOCLING_DIR

pytestmark = [pytest.mark.manual, pytest.mark.timeout(900)]       # предел 30 с из pytest.ini — не для замеров
MODELS = Path(os.environ.get("CLEANER_MODELS_DIR", Path(__file__).resolve().parents[1] / "models"))
SAMPLE = (
    "Заявка от Петрова Ивана Сергеевича: на сервере srv-test-07 не открывается отчёт, почта petrov@kontora-test.ru. "
    "Иванова Мария Олеговна просит проверить доступ, адрес офиса — г. Тестовск, ул. Примерная, д. 5. "
    "Contact John Smith at Example Corp for details. "
)


def test_layers_1_to_4_on_100k_chars_fit_nfr_4():
    layer = NerModels(MODELS).layer()
    text = (SAMPLE * (100_000 // len(SAMPLE) + 1))[:100_000]
    started = time.perf_counter()
    sanitize(ChatState(chat_id="speed", net_key=bytes(32)), text, Settings(), Layers(ner=layer))
    elapsed = time.perf_counter() - started
    print(f"слои 1–4, 100 000 знаков: {elapsed:.1f} с")
    assert elapsed <= 60


def test_docling_on_50_pages_fits_nfr_4():
    from docx import Document

    docling = Docling(MODELS / DOCLING_DIR)
    doc = Document()
    for number in range(50):
        doc.add_paragraph(f"{number + 1}. {SAMPLE}")
        doc.add_page_break()
    buffer = io.BytesIO()
    doc.save(buffer)
    started = time.perf_counter()
    docling.convert(buffer.getvalue(), "docx")
    docx_seconds = time.perf_counter() - started
    started = time.perf_counter()
    docling.pdf_pages(make_pdf([f"Page {n}: Contact John Smith at Example Corp" for n in range(50)]), range(1, 51))
    pdf_seconds = time.perf_counter() - started
    print(f"Docling, 50 страниц: DOCX {docx_seconds:.1f} с, PDF {pdf_seconds:.1f} с")
    assert docx_seconds <= 180 and pdf_seconds <= 180
