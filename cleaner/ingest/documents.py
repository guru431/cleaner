"""Разбор документов Docling без обращения к сети (раздел 9): модели — из каталога models_dir/docling."""
from __future__ import annotations

import io
import logging
import sys
import threading
from collections.abc import Sequence
from pathlib import Path

from cleaner.ingest.extract import ExtractError

log = logging.getLogger("cleaner.ingest")

THREADS = 4
_FORMATS = {"pdf": "PDF", "docx": "DOCX", "xlsx": "XLSX", "pptx": "PPTX", "html": "HTML", "eml": "EMAIL", "msg": "EMAIL"}
# Текст как есть: без экранирования «<» и «_» (иначе логин ivanov_backup стал бы ivanov\_backup) и без заглушек картинок.
_EXPORT = {"escape_html": False, "escape_underscores": False, "image_placeholder": ""}


class Docling:
    def __init__(self, artifacts: Path):
        self.artifacts = artifacts
        self._converter = None
        self._lock = threading.Lock()        # загрузка один раз и разбор по одному: Docling потокобезопасности не обещает

    def _converter_once(self):
        if self._converter is None:
            if not self.artifacts.is_dir():
                raise ExtractError("Разбор документов недоступен: модели Docling не загружены (models download)")
            from docling.datamodel.accelerator_options import AcceleratorOptions
            from docling.datamodel.base_models import InputFormat
            from docling.datamodel.pipeline_options import PdfPipelineOptions
            from docling.document_converter import DocumentConverter, PdfFormatOption

            options = PdfPipelineOptions(
                artifacts_path=self.artifacts, do_ocr=False, do_table_structure=True,
                accelerator_options=AcceleratorOptions(num_threads=THREADS, device="cpu"),
            )
            pdf_options = {"pipeline_options": options}
            if sys.platform == "win32":
                # docling-parse #357: MinGW renderer TLS destructors corrupt the Windows heap, даже если convert
                # вернул успех. PDFium уже используется извлечением и не задействует этот renderer.
                # https://github.com/docling-project/docling-parse/issues/357
                from cleaner.ingest.windows_pdf import backend_class

                pdf_options["backend"] = backend_class()
            self._converter = DocumentConverter(
                allowed_formats=[InputFormat[name] for name in sorted(set(_FORMATS.values()))],
                format_options={InputFormat.PDF: PdfFormatOption(**pdf_options)},
            )
        return self._converter

    def _document(self, data: bytes, kind: str):
        with self._lock:
            converter = self._converter_once()          # каталог моделей проверяется до импорта Docling
            from docling.datamodel.base_models import DocumentStream

            # Имя потока — только вид файла: настоящее имя файла в библиотеку не передаётся.
            stream = DocumentStream(name=f"document.{kind}", stream=io.BytesIO(data))
            try:
                result = converter.convert(stream)
            except Exception as exc:
                log.error("разбор документа %s: %s", kind, type(exc).__name__)
                raise ExtractError("Файл повреждён или его не удалось разобрать") from None
            # raises_on_error=True допускает PARTIAL_SUCCESS. Текст библиотеки и errors могут содержать документ:
            # пользователю — постоянная причина, неполный фрагмент не превращается в готовый к передаче текст.
            status = getattr(result.status, "value", result.status)
            if status == "partial_success":
                raise ExtractError("Документ извлечён не полностью: загрузите исправленный файл или отдельные части")
            if status != "success":
                raise ExtractError("Файл повреждён или его не удалось разобрать")
            return result.document

    def convert(self, data: bytes, kind: str) -> str:
        return self._document(data, kind).export_to_markdown(**_EXPORT)

    def pdf_pages(self, data: bytes, pages: Sequence[int]) -> dict[int, str]:
        """Markdown страниц с текстом. Абзац, продолженный на следующей странице (даже через страницу-скан),
        Docling относит к первой: текст не теряется и не повторяется, но может встать перед распознанной страницей."""
        document = self._document(data, "pdf")
        from docling_core.types.doc import ContentLayer

        # PDFium и нативный renderer по-разному относят цифровой заголовок к BODY/FURNITURE. Колонтитулы PDF —
        # видимый текст документа: не теряем их при экспорте даже тогда, когда layout-модель считает их оформлением.
        layers = {ContentLayer.BODY, ContentLayer.FURNITURE}
        return {number: document.export_to_markdown(page_no=number, included_content_layers=layers, **_EXPORT)
                for number in pages}
