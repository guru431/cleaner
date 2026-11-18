"""Текст из загруженного файла (раздел 9): вид по содержимому и расширению, разбор, распознавание сканов.

Сети здесь нет: распознавание страниц приходит вызываемым объектом (клиент шлюза — cleaner/local_llm.py).
"""
from __future__ import annotations

import ctypes
import io
import math
import re
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import dataclass
from email import message_from_bytes
from email.message import Message
from pathlib import PurePath
from typing import Protocol
from xml.parsers import expat

from cleaner.core.detect.base import DetectorError
from cleaner.core.detect.llm import CompletionError
from cleaner.ingest import textfiles

OCR_DPI = 200                       # страница A4 — около 1650×2340 точек, в пределах ocr-ru
_SCANNED_BELOW = 20                 # меньше стольких знаков в слое текста — страница считается сканом
# Изображения покрывают не меньше этой доли страницы — на них может быть основное содержимое: скан с цифровым
# заголовком, частичный слой распознавания сканера. Такая страница распознаётся и при слое текста. Логотип, подпись,
# печать и фото в тексте занимают заметно меньше; лишнее распознавание дороже по времени, но не теряет текст.
_IMAGE_SHARE = 0.3
_PDF_FORM_DEPTH = 8                 # при достижении предела страницу проверяет OCR
# Не больше стольких пт² площади изображений на один непробельный знак слоя, лежащий в них, — слой покрывает
# изображения, страница уже распознана (сканер или ПО сканирования: невидимый слой поверх растра) или это бланк
# с подложкой, и распознавать её заново не нужно (ocr-ru — 72 с на страницу). Машинописная страница A4 (500 000 пт²)
# — 1500–3500 знаков, по знаку на 140–330 пт²; изображению на всю страницу нужно не меньше 335 знаков, 5–8 строк.
# Цифровой заголовок вне изображения не засчитывается, а штамп или номер поверх скана (десятки знаков) много ниже
# порога. Редкий скан почти без текста распознаётся заново — дольше, но без потери текста.
_LAYER_AREA = 1500
# Распознавание одной страницы в ocr-ru (замер аудита 09.11.2026 — около 72 с) — только для оценки при загрузке.
OCR_PAGE_SECONDS = 72
# Непробельные знаки слоя — оценка текста снизу: Markdown Docling добавляет пробелы и разметку, а колонтитулы
# (их Docling не выводит) занимают меньше, чем пробелы основного текста.
_PDF_TOO_LONG = "Документ слишком большой: его текст заведомо длиннее {} знаков. Разделите его на части"
_WORDS = re.compile(r"\w+")
_MARKDOWN_PREFIX = re.compile(r"^\s*(?:#{1,6}\s+|>\s*|[-+*]\s+)")
_MARKDOWN_INLINE = re.compile(r"(?<!\w)(\*\*|`|\*)([^\s*`][^*`]*?)(?<!\s)\1(?!\w)")
_OCR_DOWN = frozenset({"unavailable", "auth"})   # распознавание недоступно целиком, а не отказало на одной странице
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
# Пределы до Docling (замеры 15.10.2026 на машине разработки): openpyxl грузит книгу целиком, а Docling создаёт
# объект на каждую клетку области данных, пустую тоже. Плотная таблица — около 2,8 КБ памяти на ячейку
# (100 000 строк × 6 столбцов: +1,7 ГБ и 9,1 млн знаков текста), клетка объединения — 1,3 КБ, пустая
# оформленная ячейка — 380 байт, пустая клетка области — 210 байт. DOCX — 19–41 МБ памяти на 1 МБ XML
# (20 МБ XML, 1,2 МБ в ZIP: +0,8 ГБ, 12 млн знаков, 3 минуты), PPTX — 26; 32 МБ XML — меньше 500 000 знаков текста
# только при разметке больше 64 байт на знак, а оформление каждого слова отдельно даёт 30. Оценка текста DOCX
# и PPTX (_Text) отказывает такому документу за сотые доли секунды; 31 МБ XML с оформлением каждого знака
# (текст в пределе) она читает целиком за 1,8 с.
_UNPACKED = 512 * 1024 * 1024       # все части документа Office без сжатия, по каталогу ZIP: ZIP-бомба
_MARKUP = 32 * 1024 * 1024          # части XML без сжатия: их разбор и даёт рост памяти
_CELL_CHARS = 3                     # ячейка со значением — не меньше стольких знаков Markdown (замер: от 5,25)
_SHEET_AREA = 1_000_000             # клеток в областях листов вместе с пустыми: до 0,4 ГБ
_SHEET_MAX = (1_048_576, 16_384)    # строк и столбцов в листе Excel: край для «A:A» и «1:1»
_COORD = re.compile(r"\$?([A-Za-z]*)\$?([0-9]*)")
_SPLIT_TABLE = "Загрузите нужную часть таблицы отдельным файлом"
_HIDDEN_ONLY = ". Скрытые листы книги не извлекаются: покажите нужные листы в Excel и загрузите файл снова"
# Текст DOCX и PPTX, который Docling выводит всегда: корень основной части и пути до элемента текста от него.
_TEXT_PATHS = {
    "docx": ("document", re.compile(r"document/body(/sdt/sdtContent)*(/tbl/tr/tc)?/p(/hyperlink)?/r/t")),
    "pptx": ("sld", re.compile(r"sld/cSld/spTree(/grpSp)*/sp/txBody/p/(r|fld)/t")),
}
_SLIDE_CHROME = frozenset({"ftr", "dt", "sldNum"})     # колонтитул, дата и номер слайда Docling кладёт в FURNITURE
# Рисунки в каталогах media пакета Office: Docling их не распознаёт (do_ocr=False, заглушки картинок не выводятся).
_PICTURES = frozenset({"png", "jpg", "jpeg", "jfif", "gif", "bmp", "tif", "tiff", "webp", "emf", "wmf"})


class ExtractError(Exception):
    """Текст не извлечён. Сообщение показывается пользователю: в нём нет содержимого файла (FR-2.9)."""


class _PageRefused(ExtractError):
    """Распознавание отказало на этой странице, а не недоступно целиком: у изображения — отказ файла, у страницы скана
    PDF — страница без текста (Extracted.failed_pages)."""


@dataclass(frozen=True)
class Extracted:
    text: str
    kind: str                              # pdf | docx | xlsx | pptx | html | eml | msg | image | text
    pages: int = 0
    ocr_pages: tuple[int, ...] = ()        # страницы, текст которых получен распознаванием (FR-2.5)
    unread_pages: tuple[int, ...] = ()     # на них распознавание не нашло ни одного знака
    failed_pages: tuple[int, ...] = ()     # страницы скана PDF, распознавание которых отказало: их текста нет
    hidden_sheets: int = 0                 # скрытые листы книги: Docling кладёт их в невидимый слой, их текста нет
    doubtful_pages: tuple[int, ...] = ()   # крупное изображение не распознано: взят только слой текста страницы
    images: int = 0                        # встроенные изображения DOCX, XLSX и PPTX: их текст не распознаётся
    omitted_attachments: int = 0          # вложения письма: имена и содержимое не хранятся


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


class _OtherPart(Exception):
    """Часть пакета — не та, что ищется: у книги не лист и не каталог листов (общие строки, стили, рисунки),
    у документа и презентации не основной текст и не слайд. Дальше первого элемента она не читается."""


def _parse(package: zipfile.ZipFile, part: zipfile.ZipInfo, parser, enough: Callable[[], bool]) -> None:
    """Часть пакета потоком expat: распакованный XML целиком в памяти не держится, чтение останавливается, как
    только enough(). Часть, которая не читается, пропускается: такой файл не откроет и Docling, он откажет сам."""
    try:
        with package.open(part) as stream:
            while not enough() and (chunk := stream.read(1 << 20)):
                parser.Parse(chunk, False)
    except (_OtherPart, expat.ExpatError, ValueError, OverflowError, zipfile.BadZipFile, EOFError, NotImplementedError,
            RuntimeError, zlib.error):
        pass


def _point(ref: str, end: bool) -> tuple[int, int]:
    """«B12» -> (12, 2). У ссылки на столбец или строку целиком («A», «5») недостающее — начало или край листа."""
    match = _COORD.fullmatch(ref)
    letters, digits = match.groups() if match else ("", "")
    column = 0
    for letter in letters.upper():
        column = column * 26 + ord(letter) - 64
    row = int(digits) if digits else (_SHEET_MAX[0] if end else 1)
    return row, column or (_SHEET_MAX[1] if end else 1)


class _Cells:
    """Ячейки листов XLSX потоком expat (_parse): чтение останавливается, как только предел превышен.
    Строки и ячейки нумеруются, как у openpyxl (без атрибута r — следующая по счёту);
    объединения и ссылки диапазоном openpyxl заполняет объектами ячеек, а Docling обходит всю область данных
    листа — поэтому считается площадь области, а не число элементов <c>."""

    def __init__(self, max_chars: int):
        self.max_chars = max_chars
        self.shown = 0          # клетки, которые попадут в Markdown: со значением и под объединением, во всех листах
        self.area = 0                                       # клетки областей прочитанных листов
        self.box: tuple[int, int, int, int] | None = None   # область текущего листа: верх, лево, низ, право
        self.hidden = 0         # листы hidden и veryHidden из каталога книги (workbook.xml)

    def cells(self) -> int:
        if self.box is None:
            return self.area
        top, left, bottom, right = self.box
        return self.area + (bottom - top + 1) * (right - left + 1)

    def text_too_long(self) -> bool:
        return self.shown * _CELL_CHARS > self.max_chars

    def full(self) -> bool:
        return self.text_too_long() or self.cells() > _SHEET_AREA

    def read(self, package: zipfile.ZipFile, part: zipfile.ZipInfo) -> None:
        self.area, self.box = self.cells(), None
        self.depth = self.row_depth = self.cell_depth = self.row = self.column = 0
        self.has_value = self.book = False
        parser = expat.ParserCreate()
        parser.StartElementHandler, parser.EndElementHandler = self._start, self._end
        _parse(package, part, parser, self.full)

    def _cover(self, top: int, left: int, bottom: int, right: int) -> None:
        box = self.box or (top, left, bottom, right)
        self.box = (min(box[0], top), min(box[1], left), max(box[2], bottom), max(box[3], right))

    def _start(self, name: str, attrs: dict[str, str]) -> None:
        self.depth += 1
        local = name.rpartition(":")[2]
        if self.depth == 1 and local != "worksheet":
            if local != "workbook":
                raise _OtherPart
            self.book = True
        if self.book:
            # Состояние листа Docling сравнивает только с «visible»: всё прочее уходит в невидимый слой.
            if local == "sheet" and attrs.get("state", "visible") != "visible":
                self.hidden += 1
            return
        if self.row_depth and self.depth == self.row_depth + 1:      # openpyxl считает ячейкой любой элемент строки
            if "r" in attrs:
                row, self.column = _point(attrs["r"], False)
            else:
                row, self.column = self.row, self.column + 1
            self._cover(row, self.column, row, self.column)
            self.cell_depth, self.has_value = self.depth, False
        elif self.cell_depth and local in ("v", "is"):
            self.has_value = True
        elif local == "row":
            self.row = int(float(attrs["r"])) if "r" in attrs else self.row + 1     # «5.0» openpyxl тоже читает
            self.column, self.row_depth = 0, self.depth
        elif local in ("mergeCell", "hyperlink") and "ref" in attrs:
            first, _, last = attrs["ref"].partition(":")
            (top, left), (bottom, right) = _point(first, False), _point(last or first, True)
            self._cover(top, left, bottom, right)
            if local == "mergeCell":            # текст объединения Docling повторяет в каждой его клетке
                self.shown += (bottom - top + 1) * (right - left + 1)

    def _end(self, name: str) -> None:
        if self.depth == self.cell_depth:
            self.shown += self.has_value
            self.cell_depth = 0
        elif self.depth == self.row_depth:
            self.row_depth = 0
        self.depth -= 1


class _Text:
    """Длина текста DOCX и PPTX потоком expat (_parse) — оценка снизу длины Markdown Docling. Считаются знаки
    без пробельных и только там, откуда Docling выводит текст всегда (_TEXT_PATHS): абзацы тела, ячейки таблиц
    верхнего уровня, ссылки и элементы управления содержимым DOCX; фигуры и группы видимых слайдов PPTX.
    Не считаются колонтитулы, сноски, примечания, заметки и макеты (другие части пакета), надписи и ветви
    mc:AlternateContent (Word пишет надпись дважды), перенесённый текст и вставки в режиме исправлений, таблицы
    слайдов, скрытые слайды и фигуры, колонтитул, дата и номер слайда. Ячейки за краем сетки таблицы
    (w:tblGrid) Docling отбрасывает, а здесь они считаются: такие таблицы бывают только у файлов, собранных
    вручную."""

    def __init__(self, kind: str, max_chars: int):
        self.root, self.paths = _TEXT_PATHS[kind]
        self.max_chars = max_chars
        self.chars = 0

    def too_long(self) -> bool:
        return self.chars > self.max_chars

    def read(self, package: zipfile.ZipFile, part: zipfile.ZipInfo) -> None:
        self.path: list[str] = []
        self.skip = 0               # глубина элемента, текста под которым Docling не выводит
        self.counting = False
        parser = expat.ParserCreate()
        parser.buffer_text = True
        parser.StartElementHandler, parser.EndElementHandler = self._start, self._end
        parser.CharacterDataHandler = self._data
        _parse(package, part, parser, self.too_long)

    def _start(self, name: str, attrs: dict[str, str]) -> None:
        self.path.append(name.rpartition(":")[2])
        if self.skip:
            return
        depth, local = len(self.path), self.path[-1]
        if depth == 1:
            if local != self.root:
                raise _OtherPart
            if attrs.get("show") in ("0", "false"):         # скрытый слайд
                self.skip = 1
        elif local == "cNvPr" and attrs.get("hidden") in ("1", "true"):    # скрытая фигура слайда: p:sp/p:nvSpPr/p:cNvPr
            self.skip = depth - 2
        elif local == "ph" and attrs.get("type") in _SLIDE_CHROME:          # p:sp/p:nvSpPr/p:nvPr/p:ph
            self.skip = depth - 3
        elif local == "t":
            self.counting = self.paths.fullmatch("/".join(self.path)) is not None

    def _end(self, name: str) -> None:
        if len(self.path) == self.skip:
            self.skip = 0
        self.path.pop()
        self.counting = False

    def _data(self, data: str) -> None:
        if self.counting:
            self.chars += len("".join(data.split()))


def _is_markup(package: zipfile.ZipFile, part: zipfile.ZipInfo) -> bool:
    """Разметка — по содержимому, а не по имени: python-docx находит основную часть по связям, и переименованная
    (`word/document.bin`) обошла бы предел по расширению `.xml`. Часть, которую не прочесть, считается разметкой."""
    if part.is_dir() or part.file_size == 0:
        return False
    try:
        with package.open(part) as handle:
            head = handle.read(64)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError):
        return True
    return head.replace(b"\x00", b"").lstrip(b"\xef\xbb\xbf\xff\xfe \t\r\n").startswith(b"<")


def _check_package(data: bytes, kind: str, max_chars: int) -> tuple[int, int]:
    """Отказ до Docling, когда разбор не уместится в память службы (MemoryMax) или его текст всё равно будет
    отклонён: ZIP-бомба, слишком много XML, таблица с заведомо длинным текстом или огромной областью листов,
    документ или презентация с заведомо длинным текстом.
    ZIP, который не читается, остаётся Docling: он откажет с причиной «повреждён». Ответ — число скрытых
    листов книги (у DOCX и PPTX — 0) и число рисунков пакета, текст которых не распознаётся."""
    cells = _Cells(max_chars)
    try:
        package = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return 0, 0
    with package:
        parts = package.infolist()
        images = sum(
            1 for part in parts
            if "/media/" in f"/{part.filename}" and PurePath(part.filename).suffix.lower().lstrip(".") in _PICTURES
        )
        # Размеры — из каталога, без распаковки: больше заявленного zipfile не отдаст ни Docling, ни openpyxl (CRC).
        if sum(part.file_size for part in parts) > _UNPACKED:
            raise ExtractError(f"Документ слишком большой для разбора: без сжатия больше {_UNPACKED // 2**20} МБ")
        if kind == "xlsx":             # таблица — точнее, по ячейкам: причина отказа понятнее пользователю
            for part in parts:
                cells.read(package, part)      # каждая часть: лист может лежать под любым именем, путь — в связях книги
                if cells.text_too_long():
                    raise ExtractError(
                        f"Таблица слишком большая: её текст заведомо длиннее {max_chars} знаков. {_SPLIT_TABLE}"
                    )
                if cells.cells() > _SHEET_AREA:
                    raise ExtractError(
                        f"Таблица слишком большая для разбора: в областях данных листов больше {_SHEET_AREA} клеток. "
                        f"{_SPLIT_TABLE}"
                    )
        if sum(part.file_size for part in parts if _is_markup(package, part)) > _MARKUP:
            raise ExtractError(
                f"Документ слишком большой для разбора: его разметка без сжатия больше {_MARKUP // 2**20} МБ. "
                "Разделите его на части"
            )
        if kind in _TEXT_PATHS:        # после предела разметки: дольше всего читается XML без текста
            text = _Text(kind, max_chars)
            for part in parts:
                text.read(package, part)       # каждая часть, как у листов: основная может лежать под любым именем
                if text.too_long():
                    raise ExtractError(
                        f"Документ слишком большой: его текст заведомо длиннее {max_chars} знаков. Разделите его на части"
                    )
    return cells.hidden, images


def _open_pdf(data: bytes):
    import pypdfium2 as pdfium
    import pypdfium2.raw as pdfium_c

    try:
        return pdfium.PdfDocument(data)
    except pdfium.PdfiumError as exc:
        if exc.err_code == pdfium_c.FPDF_ERR_PASSWORD:
            raise ExtractError(_LOCKED) from None
        raise ExtractError("PDF повреждён или не разбирается") from None


_Box = tuple[float, float, float, float]       # лево, низ, право, верх в координатах страницы


def _images(page) -> tuple[bool, list[_Box], bool]:
    """Есть ли на странице изображения и их прямоугольники, обрезанные по CropBox. Границы объекта внутри
    Form XObject pdfium даёт в координатах формы — они переводятся в координаты страницы матрицами форм-родителей."""
    import pypdfium2 as pdfium
    import pypdfium2.raw as pdfium_c

    left, bottom, right, top = page.get_cropbox()
    found, boxes, truncated = False, [], False
    kinds = [pdfium_c.FPDF_PAGEOBJ_IMAGE, pdfium_c.FPDF_PAGEOBJ_FORM]
    for image in page.get_objects(filter=kinds, max_depth=_PDF_FORM_DEPTH):
        if image.type == pdfium_c.FPDF_PAGEOBJ_FORM:
            if image.level == _PDF_FORM_DEPTH - 1:
                truncated = True
            continue
        found = True
        try:
            box = image.get_bounds()
        except pdfium.PdfiumError:
            continue
        form = image.container
        while form is not None:
            box = form.get_matrix().on_rect(*box)
            form = form.container
        box = (max(box[0], left), max(box[1], bottom), min(box[2], right), min(box[3], top))
        if box[2] > box[0] and box[3] > box[1]:
            boxes.append(box)
    return found, boxes, truncated


def _layer_inside(textpage, boxes: list[_Box]) -> int:
    """Непробельные знаки слоя текста, середина которых лежит внутри какого-нибудь из изображений."""
    import pypdfium2.raw as pdfium_c

    inside = 0
    left, bottom, right, top = (ctypes.c_double() for _ in range(4))
    for index in range(textpage.count_chars()):
        code = pdfium_c.FPDFText_GetUnicode(textpage, index)
        if code > 0x10FFFF or chr(code).isspace():
            continue
        if not pdfium_c.FPDFText_GetCharBox(textpage, index, left, right, bottom, top):    # порядок в pdfium — лпнв
            continue
        x, y = (left.value + right.value) / 2, (bottom.value + top.value) / 2
        inside += any(box[0] <= x <= box[2] and box[1] <= y <= box[3] for box in boxes)
    return inside


def _page_kinds(data: bytes, pdf=None) -> list[tuple[str, bool, int]]:
    """Вид страницы, есть ли на ней изображения и непробельных знаков в её слое текста. scan — в слое текста почти нет
    знаков, а изображение есть: только распознавание; mixed — слой текста есть, но изображения покрывают заметную долю
    страницы, а слой их не покрывает (_LAYER_AREA): и слой, и распознавание; text — только слой текста."""
    owned = pdf is None
    if owned:
        pdf = _open_pdf(data)
    try:
        result = []
        for index in range(len(pdf)):
            with closing(pdf[index]) as page, closing(page.get_textpage()) as textpage:
                chars = len("".join(textpage.get_text_range().split()))
                found, boxes, truncated = _images(page)
                left, bottom, right, top = page.get_cropbox()
                area = (right - left) * (top - bottom)
                # Перекрытия не вычитаются — доля оценивается сверху; но площадь изображений не больше страницы: сжатие
                # MRC кладёт под слой распознавания два растра на всю страницу (фон и маску букв).
                covered = min(sum((box[2] - box[0]) * (box[3] - box[1]) for box in boxes), max(area, 0))
                if truncated:
                    kind = "mixed" if chars else "scan"
                elif chars < _SCANNED_BELOW:
                    kind = "scan" if found else "text"
                elif area <= 0 or covered < _IMAGE_SHARE * area:
                    kind = "text"
                else:
                    kind = "text" if _layer_inside(textpage, boxes) * _LAYER_AREA >= covered else "mixed"
                result.append((kind, found or truncated, chars))
        return result
    finally:
        if owned:
            pdf.close()


@dataclass(frozen=True)
class PdfEstimate:
    """Оценка PDF до разбора (_page_kinds — доли секунды, без Docling и распознавания)."""
    pages: int
    ocr_pages: int              # страницы, которые пойдут на распознавание: сканы, смешанные, при ocr_all — все
    layer_chars: int            # непробельные знаки слоя страниц, которые разберёт Docling: оценка текста снизу

    @property
    def minutes(self) -> int:
        return math.ceil(self.ocr_pages * OCR_PAGE_SECONDS / 60)

    def summary(self) -> str:
        if not self.ocr_pages:
            return f"страниц {self.pages}"
        return f"страниц {self.pages}, из них сканов {self.ocr_pages}, ≈{self.minutes} мин распознавания"

    def check(self, max_chars: int) -> None:
        """Отказ до Docling: текст заведомо длиннее предела, и элемент всё равно отклонили бы — после минут разбора."""
        if self.layer_chars > max_chars:
            raise ExtractError(_PDF_TOO_LONG.format(max_chars))


def _estimate(found: list[tuple[str, bool, int]], ocr_all: bool) -> PdfEstimate:
    ocr = sum(1 for kind, _, _ in found if ocr_all or kind != "text")
    return PdfEstimate(len(found), ocr, sum(chars for kind, _, chars in found if kind != "scan"))


def estimate_pdf(data: bytes, ocr_all: bool = False) -> PdfEstimate:
    """Оценка при загрузке (страниц, на распознавание, минут) — до постановки в очередь. ExtractError — PDF не открыть."""
    return _estimate(_page_kinds(data), ocr_all)


def _key(text: str) -> str:
    return " ".join(_MARKDOWN_INLINE.sub(r"\2", _MARKDOWN_PREFIX.sub("", text)).casefold().split())


def _alnum(text: str) -> str:
    return "".join(_WORDS.findall(text))


def _merge(recognised: str, layer: str) -> str:
    """При единственном совпадении букв и цифр в строке с числом берём её из цифрового слоя: OCR ошибается в разделителях."""
    if not layer.strip():
        return recognised.strip()
    ocr_lines = recognised.splitlines()
    ocr_keys = [_key(line) for line in ocr_lines]
    seen, seen_text = set(ocr_keys), " ".join(filter(None, ocr_keys))
    layer_lines = [(line, _key(line)) for line in layer.splitlines()]
    numeric = {key: _alnum(key) for _, key in layer_lines if any(ch.isdecimal() for ch in key)}
    counts = Counter(numeric[key] for _, key in layer_lines if key in numeric)
    by_alnum: dict[str, list[int]] = {}
    for index, key in enumerate(ocr_keys):
        by_alnum.setdefault(_alnum(key), []).append(index)
    extra = []
    for line, key in layer_lines:
        if not _WORDS.search(key) or key in seen:
            continue
        if key in numeric:
            plain = numeric[key]
            matching = by_alnum.get(plain, [])
            if len(matching) == 1 and counts[plain] == 1:
                ocr_lines[matching[0]] = line
                continue
        elif key in seen_text:
            continue
        extra.append(line)
    return "\n\n".join(part for lines in (ocr_lines, extra) if (part := "\n".join(lines).strip()))


def _scale(width: float, height: float) -> float:
    """200 точек на дюйм, но не больше 12 000 точек по стороне — предел ocr-ru. Иначе страница огромного
    размера стала бы картинкой в гигабайты и упёрлась бы в предел памяти службы."""
    return min(OCR_DPI / 72, _OCR_SIDE / max(width, height, 1))


def _render(pdf, number: int) -> bytes:
    """Страница скана — PNG для ocr-ru."""
    with closing(pdf[number - 1]) as page, closing(page.render(scale=_scale(*page.get_size()))) as bitmap, bitmap.to_pil() as image:
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()


def _is_email_attachment(part: Message) -> bool:
    content_type = part.get_content_type()
    disposition = part.get_content_disposition()
    return bool(
        disposition == "attachment" or part.get_filename()
        or content_type in ("message/rfc822", "text/rtf")
        or ((disposition == "inline" or part.get("Content-ID")) and content_type not in ("text/plain", "text/html"))
    )


def _empty_email_body(message: Message) -> None:
    for key in ("Content-Type", "Content-Disposition", "Content-Transfer-Encoding", "Content-ID"):
        del message[key]
    message.set_payload("")


def _eml_without_attachments(data: bytes) -> tuple[bytes, int]:
    """Считаем и убираем вложения до Docling: mailparser иначе читает и тело вложенного письма."""
    message = message_from_bytes(data)
    if _is_email_attachment(message):
        _empty_email_body(message)
        return message.as_bytes(), 1
    count = 0
    pending = [message]
    while pending:
        part = pending.pop()
        if not part.is_multipart():
            continue
        children = part.get_payload()
        kept = [child for child in children if not _is_email_attachment(child)]
        pending.extend(kept)
        if len(kept) == len(children):
            continue
        count += len(children) - len(kept)
        if kept:
            part.set_payload(kept)
        else:
            _empty_email_body(part)
    return (message.as_bytes() if count else data), count


def _msg_attachment_count(data: bytes) -> int:
    from olefile import OleFileIO

    # Тот же корневой каталог хранилищ вложений, что у oxmsg, без второго чтения всех потоков документа.
    with io.BytesIO(data) as stream, OleFileIO(stream) as container:
        return sum(
            len(path) == 1 and path[0].startswith("__attach_version1.0_#")
            for path in container.listdir(streams=False, storages=True)
        )


class Extractor:
    def __init__(self, documents: Documents, ocr: Ocr, max_chars: int = 500_000):
        self.documents = documents
        self.ocr = ocr
        self.max_chars = max_chars          # предел текста элемента (max_text_chars): длиннее служба не очистит

    def extract(
        self, filename: str, data: bytes, progress: Progress = lambda done, total: None, ocr_all: bool = False,
    ) -> Extracted:
        """ocr_all — распознать каждую страницу PDF, и со слоем текста тоже (выбор пользователя при загрузке)."""
        kind = detect_kind(filename, data)
        if kind == "pdf":
            result = self._pdf(data, progress, ocr_all)
        elif kind == "image":
            result = self._image(data, progress)
        elif kind == "text":
            try:
                result = Extracted(textfiles.decode(data), "text")
            except textfiles.NotText as exc:
                raise ExtractError(f"Формат файла не поддерживается: {exc}") from None
        else:
            hidden, images = _check_package(data, kind, self.max_chars) if kind in _OFFICE else (0, 0)
            attachments = 0
            if kind == "eml":
                data, attachments = _eml_without_attachments(data)
            text = self.documents.convert(data, kind)
            if kind == "msg":
                attachments = _msg_attachment_count(data)
            result = Extracted(text, kind, hidden_sheets=hidden, images=images, omitted_attachments=attachments)
        if not result.text.strip():
            raise ExtractError("В файле не найден текст" + (_HIDDEN_ONLY if result.hidden_sheets else ""))
        return result

    def _page(self, image: bytes, mime: str, number: int) -> tuple[str, tuple[int, ...]]:
        """_PageRefused — отказ этой страницы; недоступное целиком распознавание (_OCR_DOWN) — ExtractError."""
        if len(image) > _OCR_LIMIT:
            raise _PageRefused("Изображение больше 20 МБ: распознавание его не примет")
        try:
            return self.ocr(image, mime), ()
        except DetectorError as exc:
            raise ExtractError(f"Распознавание текста не выполнено: {exc}") from None
        except CompletionError as exc:
            if exc.code == "ocr_empty":
                return "", (number,)
            error = ExtractError if exc.code in _OCR_DOWN else _PageRefused
            raise error(f"Распознавание текста не выполнено: {exc}") from None

    def _image(self, data: bytes, progress: Progress) -> Extracted:
        progress(0, 1)
        text, unread = self._page(data, "image/png" if data.startswith(_PNG) else "image/jpeg", 1)
        progress(1, 1)
        return Extracted(text, "image", 1, (1,), unread)

    def _over_layer(self, pdf, number: int) -> tuple[str | None, bool]:
        """Распознавание страницы, у которой есть и слой текста. Отказ не прерывает разбор: слой остаётся, страница —
        сомнительной полноты. Ответ — текст (None — не распознано) и признак, что распознавание недоступно целиком."""
        image = _render(pdf, number)
        if len(image) > _OCR_LIMIT:
            return None, False
        try:
            return self.ocr(image, "image/png"), False
        except CompletionError as exc:
            return None, exc.code in _OCR_DOWN
        except DetectorError:           # ключ шлюза не задан или адрес отклонён (engines.client)
            return None, True

    def _too_long(self, texts: dict[int, str]) -> None:
        """Уже полученный текст страниц длиннее предела: дальше не распознавать — итог всё равно отклонили бы."""
        if sum(len(text.strip()) for text in texts.values()) > self.max_chars:
            raise ExtractError(_PDF_TOO_LONG.format(self.max_chars))

    def _pdf(self, data: bytes, progress: Progress, ocr_all: bool = False) -> Extracted:
        with _open_pdf(data) as pdf:
            return self._pdf_open(pdf, data, progress, ocr_all)

    def _pdf_open(self, pdf, data: bytes, progress: Progress, ocr_all: bool) -> Extracted:
        found = _page_kinds(data, pdf)
        _estimate(found, ocr_all).check(self.max_chars)
        kinds = [kind for kind, _, _ in found]
        if ocr_all:
            kinds = ["scan" if kind == "scan" else "mixed" for kind in kinds]
        text_pages = [number for number, kind in enumerate(kinds, 1) if kind != "scan"]
        ocr_pages = [number for number, kind in enumerate(kinds, 1) if kind != "text"]
        texts = self.documents.pdf_pages(data, text_pages) if text_pages else {}
        self._too_long(texts)
        unread: list[int] = []
        doubtful: list[int] = []
        failed: list[int] = []
        refused: _PageRefused | None = None
        blank: list[int] = []           # распознавание не дало текста: страница не из распознанных

        down = False            # недоступно целиком — у остальных страниц со слоем его не ждать (тайм-аут на каждой)
        for done, number in enumerate(ocr_pages):
            progress(done, len(ocr_pages))
            if kinds[number - 1] == "scan":
                # Отказ одной страницы (ответ обрезан, изображение не принято) не теряет распознанные: страница — в
                # failed_pages (решение владельца 25.10.2026). Недоступное целиком распознавание файл по-прежнему отклоняет.
                try:
                    texts[number], missed = self._page(_render(pdf, number), "image/png", number)
                except _PageRefused as exc:
                    failed.append(number)
                    blank.append(number)
                    refused = refused or exc
                    continue
                unread += missed
                self._too_long(texts)
                continue
            recognised, down = (None, True) if down else self._over_layer(pdf, number)
            if recognised is None or not recognised.strip():
                # Сомнительна только страница с изображением: без него (отметка «на всех страницах») пустой итог —
                # пустая страница, а отказ оставляет слой, как и без отметки.
                blank.append(number)
                if found[number - 1][1]:
                    doubtful.append(number)
            else:
                texts[number] = _merge(recognised, texts.get(number, ""))
                self._too_long(texts)
        if ocr_pages:
            progress(len(ocr_pages), len(ocr_pages))
        pages = [texts.get(number, "").strip() for number in range(1, len(kinds) + 1)]
        text = "\n\n".join(page for page in pages if page)
        if refused is not None and not text:
            raise ExtractError(str(refused))        # причина отказа полезнее, чем «в файле не найден текст»
        return Extracted(
            text, "pdf", len(kinds), tuple(number for number in ocr_pages if number not in blank), tuple(unread),
            doubtful_pages=tuple(doubtful), failed_pages=tuple(failed),
        )
