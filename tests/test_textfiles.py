import codecs

import pytest

from cleaner.ingest import textfiles

TEXT = "Сервер srv-01 недоступен. Ответственный: Петров, ошибка 0x80070005.\r\nПовтор через 5 минут.\r\n"


@pytest.mark.parametrize(
    "data",
    [TEXT.encode("utf-8"), TEXT.encode("utf-8-sig"), codecs.BOM_UTF16_LE + TEXT.encode("utf-16-le"),
     codecs.BOM_UTF16_BE + TEXT.encode("utf-16-be")],
    ids=["utf-8", "utf-8-bom", "utf-16-le-bom", "utf-16-be-bom"],
)
def test_unicode_files(data):
    assert textfiles.decode(data) == TEXT


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be"])
def test_utf16_without_bom_is_recognised(codec):
    """Обзор плана 2+4, пункт 3: выгрузка PowerShell без метки порядка байтов."""
    assert textfiles.decode(TEXT.encode(codec)) == TEXT
    assert textfiles.decode("Get-Service | Out-File log.txt\r\n".encode(codec)) == "Get-Service | Out-File log.txt\r\n"


@pytest.mark.parametrize("codec", ["cp1251", "cp866"])
def test_single_byte_russian_encodings_are_told_apart(codec):
    """Обзор плана 2+4, пункт 3: журнал Windows-1251 и вывод консоли в CP866."""
    assert textfiles.decode(TEXT.encode(codec)) == TEXT


def test_ascii_line_is_not_mistaken_for_utf16():
    assert textfiles.decode(b"-" * 40 + b"\n") == "-" * 40 + "\n"


def test_binary_file_is_not_text():
    with pytest.raises(textfiles.NotText):
        textfiles.decode(bytes(range(256)) * 4)


LOG = "2026-10-14 10:00 Пользователь Петров Иван вошёл в систему\n" * 50


def test_utf8_cut_inside_a_character_keeps_the_text_readable():
    """Обзор плана 2+4, I-1: журнал, обрезанный по числу байтов, — не повод читать его как Windows-1251."""
    data = LOG.encode("utf-8")
    cut = next(data[:n] for n in range(len(data) - 40, len(data)) if not _utf8(data[:n]))
    assert textfiles.decode(cut) == cut[:-1].decode("utf-8", "ignore")


def test_one_line_in_another_encoding_does_not_garble_the_rest():
    """Обзор плана 2+4, I-1: строка в Windows-1251 посреди журнала в UTF-8."""
    data = LOG.encode("utf-8") + "ошибка службы Сидоров\n".encode("cp1251") + LOG.encode("utf-8")
    assert textfiles.decode(data) == LOG + "ошибка службы Сидоров\n" + LOG


def _utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True
