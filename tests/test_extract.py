import pytest
from pdfgen import make_pdf

from cleaner.core.detect.llm import CompletionError
from cleaner.ingest.extract import ExtractError, Extractor, detect_kind

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


def test_huge_page_is_rendered_within_the_recognition_limit():
    """Обзор плана 2+4, m-5: страница огромного размера не рисуется картинкой в гигабайты — не больше, чем примет ocr-ru."""
    from cleaner.ingest.extract import OCR_DPI, _scale

    assert _scale(612, 792) == OCR_DPI / 72                      # A4 и Letter — как прежде, 200 точек на дюйм
    assert 100_000 * _scale(100_000, 50_000) <= 12_000
