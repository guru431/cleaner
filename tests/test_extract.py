import io
import struct
import zipfile

import pytest
from pdfgen import make_pdf

from cleaner.core.detect.base import DetectorError
from cleaner.core.detect.llm import CompletionError
from cleaner.ingest.extract import ExtractError, Extractor, detect_kind, estimate_pdf

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16
# Зашифрованный OOXML — контейнер OLE с потоками EncryptionInfo и EncryptedPackage (имена в UTF-16LE).
ENCRYPTED = OLE + "EncryptionInfo".encode("utf-16-le") + b"\x00" * 8 + "EncryptedPackage".encode("utf-16-le")
RTF = rb"{\rtf1\ansi\ansicpg1251 \'cf\'e5\'f2\'f0\'ee\'e2}"
ZIP = b"PK\x03\x04" + b"\x00" * 16
TEXT_PAGE = "Contact petrov.test@kontora-test.ru for access"


class Documents:
    """Разбор для тестов: вместо Docling — заданный текст; запоминает, что просили."""

    def __init__(self):
        self.calls = []

    def convert(self, data, kind):
        self.calls.append(kind)
        return f"# {kind}\n\nпочта doc@x.example"

    def pdf_pages(self, data, pages):
        self.calls.append(("pdf", list(pages)))
        return {number: f"страница {number}: почта doc@x.example" for number in pages}


class Ocr:
    """Распознавание для тестов."""

    def __init__(self, text="Скан: почта scan@x.example", error=None):
        self.text, self.error, self.calls = text, error, []

    def __call__(self, image, mime):
        self.calls.append((mime, image[:8]))
        if self.error is not None:
            raise self.error
        return self.text


@pytest.mark.parametrize(("name", "data", "kind"), [
    ("отчёт.docx", ZIP, "docx"), ("table.XLSX", ZIP, "xlsx"), ("deck.pptx", ZIP, "pptx"),
    ("letter.msg", OLE, "msg"), ("letter.eml", b"From: a@x.example\n\nbody", "eml"),
    ("page.htm", b"<p>x</p>", "html"), ("scan.jpg", JPEG, "image"), ("photo", PNG, "image"),
    ("doc.pdf", b"%PDF-1.4\n", "pdf"), ("noext", b"%PDF-1.7\n", "pdf"),
    ("server.log", "журнал".encode("cp1251"), "text"), ("data.csv", b"a;b\n1;2\n", "text"), ("script", b"echo 1", "text"),
])
def test_kind_comes_from_the_content_and_the_extension(name, data, kind):
    assert detect_kind(name, data) == kind


@pytest.mark.parametrize(("name", "data", "kind"), [
    ("notes.txt", b"pdf check: the file must start with %PDF-1.7\n", "text"),
    ("upload.log", "Петров прислал файл без %PDF- в начале\n".encode("utf-8"), "text"),
    ("macbinary", b"\x00\x0breport.pdf" + b"\x00" * 116 + b"%PDF-1.4\n", "pdf"),
    ("saved.pdf", b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4\n", "pdf"),
])
def test_pdf_signature_counts_at_the_start_or_after_binary_junk(name, data, kind):
    """Обзор плана 2+4, m-3: текст, где в первом килобайте упомянут «%PDF-», — текст, а не повреждённый PDF."""
    assert detect_kind(name, data) == kind


@pytest.mark.parametrize(("name", "data", "reason"), [
    ("secret.docx", ENCRYPTED, "защищён паролем"),
    ("old.doc", OLE, "Старые форматы Office"),
    ("old-renamed.docx", OLE + "WordDocument".encode("utf-16-le"), "Старые форматы Office"),
    ("letter.rtf", RTF, "не поддерживается"), ("letter.txt", RTF, "не поддерживается"),
    ("fake.docx", b"not a zip", "не соответствует содержимому"),
    ("fake.pdf", ZIP, "не соответствует содержимому"),
    ("fake.png", b"GIF89a", "не соответствует содержимому"),
    ("archive.zip", ZIP, "не поддерживается"),
    ("empty.txt", b"", "пустой"),
])
def test_kinds_and_refusals(name, data, reason):
    """Обзор плана 2+4, пункт 2: защищённый, повреждённый и переименованный файл — понятная причина."""
    with pytest.raises(ExtractError, match=reason):
        detect_kind(name, data)


def test_office_mail_and_html_go_to_the_converter():
    documents, ocr = Documents(), Ocr()
    result = Extractor(documents, ocr).extract("letter.msg", OLE)
    assert (result.kind, result.text, documents.calls, ocr.calls) == ("msg", "# msg\n\nпочта doc@x.example", ["msg"], [])


def test_text_file_is_decoded():
    result = Extractor(Documents(), Ocr()).extract("server.log", "Сервер упал, звонил Петров".encode("cp1251"))
    assert (result.kind, result.text) == ("text", "Сервер упал, звонил Петров")


def test_binary_file_without_a_known_signature_is_refused():
    with pytest.raises(ExtractError, match="не поддерживается"):
        Extractor(Documents(), Ocr()).extract("blob.bin", bytes(range(256)) * 4)


def test_image_is_recognised_and_marked():
    ocr = Ocr()
    result = Extractor(Documents(), ocr).extract("scan.png", PNG)
    assert (result.kind, result.text, result.ocr_pages, ocr.calls[0][0]) == ("image", "Скан: почта scan@x.example", (1,), "image/png")


def test_pdf_text_pages_go_to_the_converter_and_scanned_pages_to_recognition():
    documents, ocr, progress = Documents(), Ocr(), []
    result = Extractor(documents, ocr).extract(
        "mixed.pdf", make_pdf([TEXT_PAGE, None]), lambda done, total: progress.append((done, total)),
    )
    assert documents.calls == [("pdf", [1])]
    assert [(mime, head) for mime, head in ocr.calls] == [("image/png", b"\x89PNG\r\n\x1a\n")]
    assert result.text == "страница 1: почта doc@x.example\n\nСкан: почта scan@x.example"
    assert (result.pages, result.ocr_pages, result.unread_pages, progress) == (2, (2,), (), [(0, 1), (1, 1)])


def test_page_without_recognised_signs_is_reported_and_not_fatal():
    ocr = Ocr(error=CompletionError("ocr_empty", "на странице не распознано ни одного знака"))
    result = Extractor(Documents(), ocr).extract("mixed.pdf", make_pdf([TEXT_PAGE, None]))
    assert (result.ocr_pages, result.unread_pages) == ((2,), (2,))


HEADER = "Visible header for the financial report"


class LayerDocuments(Documents):
    """Docling для страниц со слоем текста: Markdown — заголовок страницы."""

    def pdf_pages(self, data, pages):
        self.calls.append(("pdf", list(pages)))
        return {number: f"## {HEADER}" for number in pages}


def test_scan_with_a_digital_header_is_recognised_too():
    """Аудит 2026-10-21, находка 1: у скана с цифровым заголовком слой длиннее 20 знаков, и без распознавания
    оставался один заголовок. Изображение на 74 % страницы — распознаётся; заголовок, которого распознавание не
    нашло, не теряется."""
    documents, ocr = LayerDocuments(), Ocr(text="Balance: petrov@x.example")
    result = Extractor(documents, ocr).extract("report.pdf", make_pdf([(HEADER, 600)]))
    assert documents.calls == [("pdf", [1])] and len(ocr.calls) == 1
    assert result.text == f"Balance: petrov@x.example\n\n## {HEADER}"
    assert (result.ocr_pages, result.unread_pages, result.doubtful_pages) == ((1,), (), ())


def test_header_found_by_recognition_is_not_repeated():
    ocr = Ocr(text=f"# {HEADER.upper()}\n\nBalance: petrov@x.example")
    result = Extractor(LayerDocuments(), ocr).extract("report.pdf", make_pdf([(HEADER, 600)]))
    assert result.text == f"# {HEADER.upper()}\n\nBalance: petrov@x.example"


def test_image_inside_a_form_counts_at_its_size_on_the_page():
    """pdfium даёт границы изображения внутри Form XObject в координатах формы: форма, увеличенная вдвое, иначе
    показала бы 18 % страницы вместо 74 %."""
    ocr = Ocr()
    Extractor(LayerDocuments(), ocr).extract("report.pdf", make_pdf([(HEADER, 600)], form_scale=2))
    assert len(ocr.calls) == 1


def test_logo_on_a_text_page_is_not_recognised():
    ocr = Ocr()
    result = Extractor(LayerDocuments(), ocr).extract("letter.pdf", make_pdf([(HEADER, 200)]))
    assert (ocr.calls, result.ocr_pages, result.doubtful_pages, result.text) == ([], (), (), f"## {HEADER}")


# Тело страницы поверх изображения: восемь строк, 494 непробельных знака; порог для картинки 562×600 пт — 225.
BODY = "\n".join(f"Line {n}: invoice 2026-{n:03d} for Petrov Test, kontora-test.ru, total {n * 100} rub" for n in range(8))


@pytest.mark.parametrize("invisible", [True, False])
def test_page_whose_layer_covers_the_image_is_not_recognised_again(invisible):
    """Уже распознанный скан (невидимый слой поверх растра) и бланк с подложкой (видимый текст поверх картинки):
    слой покрывает изображение, распознавать страницу заново — 72 с без выигрыша. Заголовок вне картинки не мешает."""
    documents, ocr = LayerDocuments(), Ocr()
    result = Extractor(documents, ocr).extract("scan.pdf", make_pdf([(HEADER, 600, BODY)], invisible=invisible))
    assert (documents.calls, ocr.calls, result.ocr_pages, result.doubtful_pages) == ([("pdf", [1])], [], (), ())


def test_stamp_over_a_scan_does_not_count_as_its_layer():
    """Номер входящего поверх скана — десяток знаков внутри изображения на всю страницу: тело не распознано."""
    ocr = Ocr()
    result = Extractor(LayerDocuments(), ocr).extract("scan.pdf", make_pdf([(HEADER, 600, "Incoming No 17/2026")]))
    assert len(ocr.calls) == 1 and result.ocr_pages == (1,)


def test_user_can_ask_to_recognise_an_already_recognised_scan():
    """Слой распознавания сканера бывает плохим: отметка при загрузке распознаёт и такую страницу."""
    ocr = Ocr()
    result = Extractor(LayerDocuments(), ocr).extract(
        "scan.pdf", make_pdf([(HEADER, 600, BODY)], invisible=True), ocr_all=True,
    )
    assert len(ocr.calls) == 1 and result.ocr_pages == (1,)


@pytest.mark.parametrize("error", [
    CompletionError("unavailable", "локальная модель недоступна"), DetectorError("ключ шлюза не задан"),
])
def test_unavailable_recognition_keeps_the_layer_and_marks_the_pages_doubtful(error):
    """Страница со слоем текста не проваливает разбор из-за распознавания: слой остаётся, страница — сомнительной
    полноты. Недоступное распознавание не ждут на каждой следующей странице."""
    ocr = Ocr(error=error)
    result = Extractor(LayerDocuments(), ocr).extract("report.pdf", make_pdf([(HEADER, 600), TEXT_PAGE, (HEADER, 600)]))
    assert len(ocr.calls) == 1
    assert (result.ocr_pages, result.doubtful_pages) == ((), (1, 3))
    assert result.text == "\n\n".join([f"## {HEADER}"] * 3)


def test_page_refused_by_recognition_does_not_stop_the_next_one():
    """Отказ по одной странице (ответ обрезан) — сомнительна только она, следующую распознают."""
    class Truncated(Ocr):
        def __call__(self, image, mime):
            self.calls.append(mime)
            if len(self.calls) == 1:
                raise CompletionError("ocr_truncated", "обрезано")
            return "Balance"

    result = Extractor(LayerDocuments(), Truncated()).extract("report.pdf", make_pdf([(HEADER, 600), (HEADER, 600)]))
    assert (result.ocr_pages, result.doubtful_pages) == ((2,), (1,))


def test_user_can_ask_to_recognise_every_page():
    """Выбор при загрузке: распознаётся и страница с одним слоем текста, распознанное дополняет слой."""
    documents, ocr = LayerDocuments(), Ocr(text="Contact petrov.test@kontora-test.ru")
    result = Extractor(documents, ocr).extract("mixed.pdf", make_pdf([TEXT_PAGE, None]), ocr_all=True)
    assert documents.calls == [("pdf", [1])] and len(ocr.calls) == 2
    assert result.text == f"Contact petrov.test@kontora-test.ru\n\n## {HEADER}\n\nContact petrov.test@kontora-test.ru"
    assert result.ocr_pages == (1, 2)


@pytest.mark.parametrize("empty", ["", CompletionError("ocr_empty", "на странице не распознано ни одного знака")])
def test_blank_page_recognised_on_request_is_not_doubtful(empty):
    """Ревью 2026-10-21: при отметке «на всех страницах» пустой разделитель (ни слоя текста, ни изображений) с пустым
    итогом распознавания становился «сомнительным»: «изображение занимает большую часть страницы» — а изображения нет.
    Это пустая страница; распознаётся она всё равно — текст, переведённый в кривые, изображением не является."""
    class Blank(Ocr):
        def __call__(self, image, mime):
            self.calls.append(mime)
            if len(self.calls) == 2:
                if isinstance(empty, Exception):
                    raise empty
                return empty
            return "Balance"

    ocr = Blank()
    result = Extractor(LayerDocuments(), ocr).extract("report.pdf", make_pdf([TEXT_PAGE, "", (HEADER, 600)]), ocr_all=True)
    assert len(ocr.calls) == 3
    assert (result.ocr_pages, result.unread_pages, result.doubtful_pages) == ((1, 3), (), ())
    # Страница с изображением и пустым итогом по-прежнему сомнительна.
    ocr = Blank()
    result = Extractor(LayerDocuments(), ocr).extract("report.pdf", make_pdf([TEXT_PAGE, (HEADER, 600)]), ocr_all=True)
    assert (result.ocr_pages, result.doubtful_pages) == ((1,), (2,))


def test_pictures_of_office_files_are_counted():
    """Идея аудита 2026-10-21: рисунки DOCX, XLSX и PPTX Docling не распознаёт — их число идёт в предупреждение."""
    extract = Extractor(Documents(), Ocr()).extract
    assert extract("t.docx", docx(para("x"))).images == 1
    assert extract("t.pptx", pptx(slide(shape("x")))).images == 1
    assert extract("t.docx", package({"word/document.xml": DOCX.format(para("x"))})).images == 0


def test_scan_page_refused_by_recognition_is_left_out_and_the_rest_is_kept():
    """Ревью 24.10.2026, решение владельца 25.10.2026: отказ распознавания одной страницы скана (ответ обрезан, изображение
    не принято) терял весь файл, хотя остальные страницы распознаны. Страница — в failed_pages («извлечено частично»)."""
    class Truncated(Ocr):
        def __call__(self, image, mime):
            self.calls.append(mime)
            if len(self.calls) == 1:
                raise CompletionError("ocr_truncated", "обрезано")
            return "Скан: почта scan@x.example"

    result = Extractor(Documents(), Truncated()).extract("scan.pdf", make_pdf([None, TEXT_PAGE, None]))
    assert result.text == "страница 2: почта doc@x.example\n\nСкан: почта scan@x.example"
    assert (result.ocr_pages, result.unread_pages, result.failed_pages) == ((3,), (), (1,))


def test_pdf_with_a_layer_longer_than_the_limit_is_refused_before_docling():
    """Аудит 09.11.2026: PDF на 400 страниц разбирался Docling целиком (минуты под общим замком) и только потом
    отклонялся по длине. Слой текста (_page_kinds) знает длину заранее."""
    documents, ocr = Documents(), Ocr()
    data = make_pdf([TEXT_PAGE, TEXT_PAGE, TEXT_PAGE, None])          # 43 непробельных знака на странице
    with pytest.raises(ExtractError, match="заведомо длиннее 100 знаков"):
        Extractor(documents, ocr, max_chars=100).extract("long.pdf", data)
    assert documents.calls == [] and ocr.calls == []
    assert Extractor(documents, ocr, max_chars=200).extract("long.pdf", data).pages == 4


def test_recognition_stops_once_the_text_is_over_the_limit():
    ocr = Ocr(text="x" * 50)
    with pytest.raises(ExtractError, match="заведомо длиннее 80 знаков"):
        Extractor(Documents(), ocr, max_chars=80).extract("scan.pdf", make_pdf([None, None, None]))
    assert len(ocr.calls) == 2                       # третья страница (≈72 с) уже не распознаётся


def test_pdf_estimate_counts_pages_to_recognise_and_minutes():
    data = make_pdf([TEXT_PAGE, None, None])
    estimate = estimate_pdf(data)
    assert (estimate.pages, estimate.ocr_pages, estimate.minutes, estimate.layer_chars) == (3, 2, 3, 43)
    assert estimate.summary() == "страниц 3, из них сканов 2, ≈3 мин распознавания"
    assert estimate_pdf(data, ocr_all=True).ocr_pages == 3
    assert estimate_pdf(make_pdf([TEXT_PAGE])).summary() == "страниц 1"


@pytest.mark.parametrize("error", [
    CompletionError("unavailable", "локальная модель недоступна"), CompletionError("auth", "шлюз отклонил ключ (401)"),
    DetectorError("ключ шлюза не задан"),
])
def test_scan_page_fails_the_file_when_recognition_is_down(error):
    """Недоступное целиком распознавание — не отказ страницы: файл отказывает с причиной, а не отдаёт текст без сканов."""
    with pytest.raises((ExtractError, DetectorError)):
        Extractor(Documents(), Ocr(error=error)).extract("scan.pdf", make_pdf([TEXT_PAGE, None]))


def test_scan_whose_every_page_was_refused_fails_with_the_reason():
    """Текста не дала ни одна страница — причина отказа, а не «в файле не найден текст»."""
    ocr = Ocr(error=CompletionError("ocr_truncated", "распознанный текст страницы обрезан"))
    with pytest.raises(ExtractError, match="Распознавание текста не выполнено: распознанный текст страницы обрезан"):
        Extractor(Documents(), ocr).extract("scan.pdf", make_pdf([None, None]))


def test_recognition_failure_stops_extraction_with_a_reason():
    ocr = Ocr(error=CompletionError("unavailable", "локальная модель недоступна"))
    with pytest.raises(ExtractError, match="Распознавание текста не выполнено: локальная модель недоступна"):
        Extractor(Documents(), ocr).extract("scan.jpg", JPEG)


def test_password_protected_pdf_is_refused_with_a_reason(monkeypatch):
    """Обзор плана 2+4, пункт 2; AC-2.4."""
    import pypdfium2 as pdfium
    import pypdfium2.raw as pdfium_c

    def locked(*args, **kwargs):
        raise pdfium.PdfiumError("Failed to load document", err_code=pdfium_c.FPDF_ERR_PASSWORD)

    monkeypatch.setattr(pdfium, "PdfDocument", locked)
    with pytest.raises(ExtractError, match="защищён паролем"):
        Extractor(Documents(), Ocr()).extract("locked.pdf", make_pdf(["x"]))


def test_damaged_pdf_is_refused():
    with pytest.raises(ExtractError, match="PDF повреждён"):
        Extractor(Documents(), Ocr()).extract("broken.pdf", b"%PDF-1.4\nnot a pdf at all")


def test_file_without_text_is_refused():
    documents = Documents()
    documents.convert = lambda data, kind: "   "
    with pytest.raises(ExtractError, match="не найден текст"):
        Extractor(documents, Ocr()).extract("empty.docx", ZIP)


def test_large_image_is_refused_before_recognition():
    ocr = Ocr()
    with pytest.raises(ExtractError, match="больше 20 МБ"):
        Extractor(Documents(), ocr).extract("huge.png", PNG + b"\x00" * (20 * 1024 * 1024))
    assert ocr.calls == []


SHEET = '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{rows}</sheetData>{tail}</worksheet>'


def package(parts: dict[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in parts.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def book(rows: str, tail: str = "", name: str = "xl/worksheets/sheet1.xml") -> bytes:
    """Книга из одного листа; общие строки и картинка — части, которые проверка должна пропустить."""
    return package({
        "xl/sharedStrings.xml": '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>x</t></si></sst>',
        "xl/media/image1.png": PNG, name: SHEET.format(rows=rows, tail=tail),
    })


def declared(data: bytes, size: int) -> bytes:
    """Первый член ZIP заявлен в каталоге размером size, как у ZIP-бомбы; сжатых данных — байты."""
    raw = bytearray(data)
    struct.pack_into("<I", raw, raw.find(b"PK\x01\x02") + 24, size)
    return bytes(raw)


@pytest.mark.parametrize("name", ["bomb.docx", "bomb.pptx", "bomb.xlsx"])
def test_office_file_unpacking_past_the_limit_is_refused_before_docling(name):
    """Находка «A large XLSX can push the service past MemoryMax»: размер — по каталогу ZIP, без распаковки."""
    documents = Documents()
    with pytest.raises(ExtractError, match="больше 512 МБ"):
        Extractor(documents, Ocr()).extract(name, declared(package({"word/document.xml": "<w:document/>"}), 513 * 2**20))
    assert documents.calls == []


def test_markup_is_limited_separately_from_pictures():
    """Память Docling растёт с XML (DOCX — до 41 МБ на 1 МБ), а картинки большого документа почти не сжимаются."""
    documents = Documents()
    with pytest.raises(ExtractError, match="разметка без сжатия больше 32 МБ"):
        Extractor(documents, Ocr()).extract("big.docx", declared(package({"word/document.xml": "<w:document/>"}), 33 * 2**20))
    pictures = declared(package({"word/media/image1.png": PNG, "word/document.xml": "<w:document/>"}), 100 * 2**20)
    assert Extractor(documents, Ocr()).extract("photos.docx", pictures).kind == "docx"
    assert documents.calls == ["docx"]


def test_markup_under_another_name_counts_too():
    """Основную часть DOCX можно переименовать — python-docx найдёт её по связям; предел разметки — по содержимому."""
    renamed = declared(package({"word/document.bin": "<w:document/>"}), 33 * 2**20)
    with pytest.raises(ExtractError, match="разметка без сжатия больше 32 МБ"):
        Extractor(Documents(), Ocr()).extract("renamed.docx", renamed)


def test_spreadsheet_whose_text_must_exceed_the_limit_is_refused_before_docling():
    """Ячейка со значением — не меньше трёх знаков Markdown: 101 ячейка при пределе 300 знаков — отказ сразу."""
    from openpyxl import Workbook

    def xlsx(cells: int) -> bytes:
        workbook = Workbook()
        for index in range(cells):
            workbook.active.cell(row=index // 10 + 1, column=index % 10 + 1, value=index)
        buffer = io.BytesIO()
        workbook.save(buffer)
        return buffer.getvalue()

    documents = Documents()
    assert Extractor(documents, Ocr(), max_chars=300).extract("t.xlsx", xlsx(100)).kind == "xlsx"
    with pytest.raises(ExtractError, match="текст заведомо длиннее 300 знаков"):
        Extractor(documents, Ocr(), max_chars=300).extract("t.xlsx", xlsx(101))
    assert documents.calls == ["xlsx"]


def test_cells_without_coordinates_and_sheets_under_any_name_are_counted():
    """Как у openpyxl: строка и ячейка без атрибута r — следующие по счёту; лист ищется по корню, а не по имени."""
    rows = "<row>" + "<c><v>1</v></c>" * 51 + "</row>" + '<row><c t="inlineStr"><is><t>x</t></is></c><c s="1"/></row>'
    with pytest.raises(ExtractError, match="длиннее 150 знаков"):
        Extractor(Documents(), Ocr(), max_chars=150).extract("t.xlsx", book(rows, name="xl/data/custom.xml"))
    assert Extractor(Documents(), Ocr(), max_chars=156).extract("t.xlsx", book(rows)).kind == "xlsx"


@pytest.mark.parametrize(("rows", "tail", "reason"), [
    # Столбцы A:C объединены целиком — файл в килобайт, а Docling повторяет текст в 3 млн клеток (замер: +4,3 ГБ).
    ('<row r="1"><c r="A1" t="s"><v>0</v></c></row>', '<mergeCells><mergeCell ref="A1:C1048576"/></mergeCells>', "текст"),
    ('<row r="1"><c r="A1" t="s"><v>0</v></c></row>', '<mergeCells><mergeCell ref="A:C"/></mergeCells>', "текст"),
    # Две ячейки по углам: Docling создаёт объект на каждую клетку между ними (замер: 210 байт на клетку).
    ('<row r="1"><c r="A1"><v>1</v></c></row><row r="100000"><c r="K100000"><v>2</v></c></row>', "", "для разбора"),
    # То же без координат: строка после 99999-й — 100000-я, одиннадцатая ячейка — столбец K.
    ('<row r="1"><c><v>1</v></c></row><row r="99999"/><row>' + "<c/>" * 10 + "<c><v>2</v></c></row>", "", "для разбора"),
    ('<row r="1"><c r="A1"><v>1</v></c></row>', '<hyperlinks><hyperlink ref="A1:Z50000"/></hyperlinks>', "для разбора"),
])
def test_sheet_area_that_would_not_fit_in_memory_is_refused_before_docling(rows, tail, reason):
    documents = Documents()
    with pytest.raises(ExtractError, match=f"Таблица слишком большая.*{reason}"):
        Extractor(documents, Ocr()).extract("t.xlsx", book(rows, tail))
    assert documents.calls == []


def test_spreadsheet_within_the_limits_goes_to_docling():
    rows = '<row r="1"><c r="A1"><v>1</v></c></row><row r="1000"><c r="Z1000"><v>2</v></c></row>'
    merge = '<mergeCells><mergeCell ref="A2:Z2"/></mergeCells>'
    assert Extractor(Documents(), Ocr()).extract("t.xlsx", book(rows, merge)).kind == "xlsx"


def workbook(*states: str) -> bytes:
    """Книга openpyxl: первый лист видимый, у остальных — заданное состояние."""
    from openpyxl import Workbook

    result = Workbook()
    result.active.append(["Сотрудник", "Почта"])
    for number, state in enumerate(states, 2):
        sheet = result.create_sheet(f"Лист{number}")
        sheet.append(["Петров", "petrov@x.example"])
        sheet.sheet_state = state
    buffer = io.BytesIO()
    result.save(buffer)
    return buffer.getvalue()


def test_hidden_sheets_are_counted_for_the_review_notice():
    """Находка «Small gaps…»: Docling кладёт скрытые листы в невидимый слой, их текста в Markdown нет —
    число таких листов (не имена: это данные пользователя) идёт в результат для предупреждения."""
    extract = Extractor(Documents(), Ocr()).extract
    assert extract("t.xlsx", workbook("hidden", "veryHidden", "visible")).hidden_sheets == 2
    assert extract("t.xlsx", workbook("visible")).hidden_sheets == 0


def test_book_whose_text_is_only_on_hidden_sheets_is_refused_with_the_reason():
    documents = Documents()
    documents.convert = lambda data, kind: ""             # видимый лист пуст, данные — на скрытом
    with pytest.raises(ExtractError, match="не найден текст. Скрытые листы книги не извлекаются"):
        Extractor(documents, Ocr()).extract("t.xlsx", workbook("hidden"))
    with pytest.raises(ExtractError, match="не найден текст$"):
        Extractor(documents, Ocr()).extract("t.xlsx", workbook())


DOCX = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"><w:body>{}</w:body></w:document>')


def para(text: str) -> str:
    return f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"


def docx(body: str, **parts: str) -> bytes:
    """Документ; картинка — часть, которую проверка должна пропустить."""
    return package({"word/media/image1.png": PNG, "word/document.xml": DOCX.format(body), **parts})


def shape(text: str, hidden: str = "", ph: str = "") -> str:
    """Фигура с текстом в обычном фрагменте и в поле (номер слайда, дата)."""
    return (f'<p:sp><p:nvSpPr><p:cNvPr id="2" name="x"{hidden}/><p:cNvSpPr/><p:nvPr>{ph}</p:nvPr></p:nvSpPr><p:spPr/>'
            f"<p:txBody><a:bodyPr/><a:p><a:r><a:t>{text}</a:t></a:r><a:fld><a:t>{text}</a:t></a:fld></a:p></p:txBody></p:sp>")


def slide(shapes: str, attrs: str = "", root: str = "sld") -> str:
    return (f'<p:{root} xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            f'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"{attrs}>'
            f"<p:cSld><p:spTree>{shapes}</p:spTree></p:cSld></p:{root}>")


def pptx(*slides: str) -> bytes:
    return package({"ppt/media/image1.png": PNG} | {f"ppt/slides/slide{n}.xml": s for n, s in enumerate(slides, 1)})


def counted_docx(chars: int) -> bytes:
    """Текст, который Docling выводит всегда: абзацы, ячейки таблиц, ссылки, элементы управления содержимым."""
    return docx(
        para("x" * 100) + f"<w:tbl><w:tr><w:tc>{para('я' * 100)}</w:tc></w:tr></w:tbl>"
        + f'<w:p><w:hyperlink><w:r><w:t xml:space="preserve">{"y" * 50}  </w:t></w:r></w:hyperlink></w:p>'
        + f"<w:sdt><w:sdtContent>{para('z' * (chars - 250))}</w:sdtContent></w:sdt>"
    )


def counted_pptx(chars: int) -> bytes:
    return pptx(slide(shape("x" * 50)), slide(f"<p:grpSp>{shape('y' * (chars // 2 - 50))}</p:grpSp>"))


@pytest.mark.parametrize(("name", "make"), [("t.docx", counted_docx), ("t.pptx", counted_pptx)])
def test_document_whose_text_must_exceed_the_limit_is_refused_before_docling(name, make):
    """Находка «Small gaps…»: DOCX на 1,2 МБ (20 МБ XML) держал Docling 194 с и всё равно не прошёл предел
    длины. Знаки текстовых элементов без пробелов — оценка снизу: длиннее предела — отказ сразу."""
    documents = Documents()
    assert Extractor(documents, Ocr(), max_chars=300).extract(name, make(300)).kind == name[2:]
    with pytest.raises(ExtractError, match="Документ слишком большой: его текст заведомо длиннее 300 знаков"):
        Extractor(documents, Ocr(), max_chars=300).extract(name, make(302))
    assert documents.calls == [name[2:]]


X = "x" * 400
TEXT_BOX = f"<w:p><w:r><w:drawing><wps:txbx xmlns:wps='s'><w:txbxContent>{para(X)}</w:txbxContent></wps:txbx></w:drawing></w:r></w:p>"


@pytest.mark.parametrize(("name", "data"), [
    ("spaces.docx", docx(f'<w:p><w:r><w:t xml:space="preserve">{" " * 400}x</w:t></w:r></w:p>')),
    # Word пишет надпись дважды — в mc:Choice и в mc:Fallback; Docling читает одну ветвь.
    ("box.docx", docx(f"<mc:AlternateContent><mc:Choice Requires='wps'>{TEXT_BOX}</mc:Choice>"
                      f"<mc:Fallback>{TEXT_BOX}</mc:Fallback></mc:AlternateContent>")),
    ("moved.docx", docx(f"<w:p><w:moveFrom><w:r><w:t>{X}</w:t></w:r></w:moveFrom></w:p>")),
    ("header.docx", docx(para("x"), **{"word/header1.xml": f'<w:hdr xmlns:w="w">{para(X)}</w:hdr>'})),
    ("hidden-slide.pptx", pptx(slide(shape(X), ' show="0"'))),
    ("hidden-shape.pptx", pptx(
        slide(shape(X, hidden=' hidden="true"')),
        slide(f'<p:grpSp><p:nvGrpSpPr><p:cNvPr id="3" name="g" hidden="1"/></p:nvGrpSpPr>{shape(X)}</p:grpSp>'),
    )),
    ("footer.pptx", pptx(slide(shape(X, ph='<p:ph type="ftr"/>')))),
    ("layout.pptx", pptx(slide(shape(X), root="sldLayout"), slide(shape(X), root="notes"))),
], ids=lambda value: value if isinstance(value, str) else "")
def test_text_docling_leaves_out_is_not_counted(name, data):
    """Обратная сторона: текст, которого в Markdown Docling нет (пробелы, копия надписи, перенесённое, колонтитул,
    скрытый слайд или фигура, нижний колонтитул слайда, макет), к пределу не идёт."""
    documents = Documents()
    assert Extractor(documents, Ocr(), max_chars=300).extract(name, data).kind == name.rpartition(".")[2]


def test_huge_page_is_rendered_within_the_recognition_limit():
    """Обзор плана 2+4, m-5: страница огромного размера не рисуется картинкой в гигабайты — не больше, чем примет ocr-ru."""
    from cleaner.ingest.extract import OCR_DPI, _scale

    assert _scale(612, 792) == OCR_DPI / 72                      # A4 и Letter — как прежде, 200 точек на дюйм
    assert 100_000 * _scale(100_000, 50_000) <= 12_000
