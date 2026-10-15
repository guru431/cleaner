"""Текст из загруженного файла (раздел 9): вид по содержимому и расширению, разбор, распознавание сканов.

Сети здесь нет: распознавание страниц приходит вызываемым объектом (клиент шлюза — cleaner/local_llm.py).
"""
from __future__ import annotations

import io
import re
import zipfile
import zlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import PurePath
from typing import Protocol
from xml.parsers import expat

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


class ExtractError(Exception):
    """Текст не извлечён. Сообщение показывается пользователю: в нём нет содержимого файла (FR-2.9)."""


@dataclass(frozen=True)
class Extracted:
    text: str
    kind: str                              # pdf | docx | xlsx | pptx | html | eml | msg | image | text
    pages: int = 0
    ocr_pages: tuple[int, ...] = ()        # страницы, текст которых получен распознаванием (FR-2.5)
    unread_pages: tuple[int, ...] = ()     # на них распознавание не нашло ни одного знака
    hidden_sheets: int = 0                 # скрытые листы книги: Docling кладёт их в невидимый слой, их текста нет


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


def _check_package(data: bytes, kind: str, max_chars: int) -> int:
    """Отказ до Docling, когда разбор не уместится в память службы (MemoryMax) или его текст всё равно будет
    отклонён: ZIP-бомба, слишком много XML, таблица с заведомо длинным текстом или огромной областью листов,
    документ или презентация с заведомо длинным текстом.
    ZIP, который не читается, остаётся Docling: он откажет с причиной «повреждён». Ответ — число скрытых
    листов книги (у DOCX и PPTX — 0)."""
    cells = _Cells(max_chars)
    try:
        package = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return 0
    with package:
        parts = package.infolist()
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
    return cells.hidden


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
    def __init__(self, documents: Documents, ocr: Ocr, max_chars: int = 500_000):
        self.documents = documents
        self.ocr = ocr
        self.max_chars = max_chars          # предел текста элемента (max_text_chars): длиннее служба не очистит

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
            hidden = _check_package(data, kind, self.max_chars) if kind in _OFFICE else 0
            result = Extracted(self.documents.convert(data, kind), kind, hidden_sheets=hidden)
        if not result.text.strip():
            raise ExtractError("В файле не найден текст" + (_HIDDEN_ONLY if result.hidden_sheets else ""))
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
