"""Текст из загруженного файла (раздел 9): вид по содержимому и расширению, разбор, распознавание сканов.

Сети здесь нет: распознавание страниц приходит вызываемым объектом (клиент шлюза — cleaner/local_llm.py).
"""
from __future__ import annotations

import io
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import PurePath
from typing import Protocol

from cleaner.core.detect.llm import CompletionError
from cleaner.ingest import textfiles

OCR_DPI = 200                       # страница A4 — около 1650×2340 точек, в пределах ocr-ru
_SCANNED_BELOW = 20                 # меньше стольких знаков в слое текста — страница считается сканом
_OCR_LIMIT = 20 * 1024 * 1024       # предел ocr-ru на одно изображение
_OCR_SIDE = 12_000                  # предел ocr-ru по стороне изображения, точек
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"      # контейнер OLE: MSG, старый Office и зашифрованный OOXML
_ENCRYPTED = "EncryptedPackage".encode("utf-16-le")   # поток зашифрованного OOXML в каталоге OLE
_RTF = b"{\\rtf"
_ZIP = b"PK\x03\x04"
_PNG = b"\x89PNG\r\n\x1a\n"
_JPEG = b"\xff\xd8\xff"
_TEXT_CONTROLS = b"\t\n\v\f\r\x1b"       # управляющие байты, которые бывают в тексте (ESC — цвета в журналах)
_OFFICE = frozenset({"docx", "xlsx", "pptx"})
_LEGACY = frozenset({"doc", "xls", "ppt"})
_MISMATCH = "Файл повреждён или его расширение не соответствует содержимому"
_LOCKED = "Файл защищён паролем: снимите защиту и загрузите его снова"
_LEGACY_REFUSED = "Старые форматы Office (.doc, .xls, .ppt) не поддерживаются: сохраните файл как .docx, .xlsx или .pptx"


class ExtractError(Exception):
    """Текст не извлечён. Сообщение показывается пользователю: в нём нет содержимого файла (FR-2.9)."""


@dataclass(frozen=True)
class Extracted:
    text: str
    kind: str                              # pdf | docx | xlsx | pptx | html | eml | msg | image | text
    pages: int = 0
    ocr_pages: tuple[int, ...] = ()        # страницы, текст которых получен распознаванием (FR-2.5)
    unread_pages: tuple[int, ...] = ()     # на них распознавание не нашло ни одного знака


class Documents(Protocol):
    """Разбор офисных документов, писем, HTML и PDF с текстом (cleaner/ingest/documents.py — Docling)."""

    def convert(self, data: bytes, kind: str) -> str: ...

    def pdf_pages(self, data: bytes, pages: Sequence[int]) -> dict[int, str]: ...


Ocr = Callable[[bytes, str], str]          # изображение, MIME -> Markdown страницы
Progress = Callable[[int, int], None]      # сделано, всего


def _pdf_signature(data: bytes, ext: str) -> bool:
    """«%PDF-» в начале файла. Читатели PDF терпят до 1024 байт мусора перед ним (заголовок MacBinary, ответ
    HTTP, сохранённый вместе с файлом), но журнал или заметка, где «%PDF-» просто упомянут, — текст: без
    расширения .pdf сдвинутая сигнатура засчитывается, только если перед ней двоичные байты, а не строки."""
    at = data.find(b"%PDF-", 0, 1024)
    if at <= 0:
        return at == 0
    return ext == "pdf" or any(byte < 0x20 and byte not in _TEXT_CONTROLS for byte in data[:at])


def detect_kind(filename: str, data: bytes) -> str:
    """Вид файла по сигнатуре и расширению. Имя файла используется только здесь и нигде не сохраняется."""
    ext = PurePath(filename).suffix.lower().lstrip(".")
    if not data:
        raise ExtractError("Файл пустой")
    if ext in _LEGACY:
        raise ExtractError(_LEGACY_REFUSED)
    if ext == "rtf" or data.lstrip()[:5] == _RTF:
        # Русские буквы RTF записывает кодами \'cf\'e5…: как текст его не прочитать ни человеку, ни слоям.
        raise ExtractError("Формат файла не поддерживается: RTF сохраните как .docx или .txt")
    pdf = _pdf_signature(data, ext)
    image = data.startswith((_PNG, _JPEG))
    if ext in _OFFICE:
        if data.startswith(_OLE):
            # Зашифрованный OOXML лежит в контейнере OLE, а не в ZIP; без потока EncryptedPackage это старый .doc.
            raise ExtractError(_LOCKED if _ENCRYPTED in data else _LEGACY_REFUSED)
        if not data.startswith(_ZIP):
            raise ExtractError(_MISMATCH)
        return ext
    if ext == "msg":
        if not data.startswith(_OLE):
            raise ExtractError(_MISMATCH)
        return "msg"
    if ext == "pdf" or pdf:
        if not pdf:
            raise ExtractError(_MISMATCH)
        return "pdf"
    if ext in ("png", "jpg", "jpeg") or image:
        if not image:
            raise ExtractError(_MISMATCH)
        return "image"
    if data.startswith((_ZIP, _OLE)):
        raise ExtractError("Формат файла не поддерживается")
    if ext in ("html", "htm"):
        return "html"
    if ext == "eml":
        return "eml"
    return "text"               # журналы, конфигурации, скрипты, CSV — любой текст (FR-2.2)


def _open_pdf(data: bytes):
    import pypdfium2 as pdfium
    import pypdfium2.raw as pdfium_c

    try:
        return pdfium.PdfDocument(data)
    except pdfium.PdfiumError as exc:
        if exc.err_code == pdfium_c.FPDF_ERR_PASSWORD:
            raise ExtractError(_LOCKED) from None
        raise ExtractError("PDF повреждён или не разбирается") from None


def _scanned_pages(data: bytes) -> list[bool]:
    """Страница — скан, если в её слое текста почти нет знаков, а изображение есть."""
    import pypdfium2.raw as pdfium_c

    pdf = _open_pdf(data)
    try:
        result = []
        for index in range(len(pdf)):
            page = pdf[index]
            text = page.get_textpage().get_text_range()
            has_image = any(True for _ in page.get_objects(filter=[pdfium_c.FPDF_PAGEOBJ_IMAGE], max_depth=2))
            result.append(len("".join(text.split())) < _SCANNED_BELOW and has_image)
        return result
    finally:
        pdf.close()


def _scale(width: float, height: float) -> float:
    """200 точек на дюйм, но не больше 12 000 точек по стороне — предел ocr-ru. Иначе страница огромного
    размера стала бы картинкой в гигабайты и упёрлась бы в предел памяти службы."""
    return min(OCR_DPI / 72, _OCR_SIDE / max(width, height, 1))


def _render(data: bytes, number: int) -> bytes:
    """Страница скана — PNG для ocr-ru."""
    pdf = _open_pdf(data)
    try:
        page = pdf[number - 1]
        image = page.render(scale=_scale(*page.get_size())).to_pil()
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()
    finally:
        pdf.close()


class Extractor:
    def __init__(self, documents: Documents, ocr: Ocr):
        self.documents = documents
        self.ocr = ocr

    def extract(self, filename: str, data: bytes, progress: Progress = lambda done, total: None) -> Extracted:
        kind = detect_kind(filename, data)
        if kind == "pdf":
            result = self._pdf(data, progress)
        elif kind == "image":
            result = self._image(data, progress)
        elif kind == "text":
            try:
                result = Extracted(textfiles.decode(data), "text")
            except textfiles.NotText as exc:
                raise ExtractError(f"Формат файла не поддерживается: {exc}") from None
        else:
            result = Extracted(self.documents.convert(data, kind), kind)
        if not result.text.strip():
            raise ExtractError("В файле не найден текст")
        return result

    def _page(self, image: bytes, mime: str, number: int) -> tuple[str, tuple[int, ...]]:
        if len(image) > _OCR_LIMIT:
            raise ExtractError("Изображение больше 20 МБ: распознавание его не примет")
        try:
            return self.ocr(image, mime), ()
        except CompletionError as exc:
            if exc.code == "ocr_empty":
                return "", (number,)
            raise ExtractError(f"Распознавание текста не выполнено: {exc}") from None

    def _image(self, data: bytes, progress: Progress) -> Extracted:
        progress(0, 1)
        text, unread = self._page(data, "image/png" if data.startswith(_PNG) else "image/jpeg", 1)
        progress(1, 1)
        return Extracted(text, "image", 1, (1,), unread)

    def _pdf(self, data: bytes, progress: Progress) -> Extracted:
        scanned = _scanned_pages(data)
        text_pages = [number for number, scan in enumerate(scanned, 1) if not scan]
        ocr_pages = [number for number, scan in enumerate(scanned, 1) if scan]
        texts = self.documents.pdf_pages(data, text_pages) if text_pages else {}
        unread: list[int] = []
        for done, number in enumerate(ocr_pages):
            progress(done, len(ocr_pages))
            text, missed = self._page(_render(data, number), "image/png", number)
            texts[number] = text
            unread += missed
        if ocr_pages:
            progress(len(ocr_pages), len(ocr_pages))
        pages = [texts.get(number, "").strip() for number in range(1, len(scanned) + 1)]
        return Extracted(
            "\n\n".join(page for page in pages if page), "pdf", len(scanned), tuple(ocr_pages), tuple(unread),
        )
