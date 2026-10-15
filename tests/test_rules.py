import pytest

from cleaner.core.detect import rules
from cleaner.core.detect.base import DetectContext
from cleaner.core.types import EntityType as T
from cleaner.core.types import Settings

CTX = DetectContext(Settings())


def found(text: str) -> set[tuple[T, str]]:
    return {(span.type, text[span.start:span.end]) for span in rules.detect(text, CTX)}


def types(text: str) -> set[T]:
    return {type_ for type_, _ in found(text)}


def test_email_without_trailing_dot():
    assert (T.EMAIL, "i.ivanov@corp.example") in found("Пишите на i.ivanov@corp.example.")


def test_phone_in_two_notations():
    result = found("Тел. +7 (916) 123-45-67, запасной 89161234567")
    assert (T.PHONE, "+7 (916) 123-45-67") in result
    assert (T.PHONE, "89161234567") in result


def test_local_phone_needs_a_context_word():
    assert (T.PHONE, "(495) 123-45-67") in found("телефон (495) 123-45-67")
    assert T.PHONE not in types("код (495) 123-45-67")


def test_inn_with_correct_checksum_needs_no_context():
    assert (T.INN, "7707083893") in found("Контрагент 7707083893 оплатил")


def test_number_with_wrong_checksum_is_not_inn():
    assert T.INN not in types("Заказ 500100732258 отправлен")


def test_snils_ogrn_and_card():
    result = found("СНИЛС 112-233-445 95, ОГРН 1027700132195, карта 4111 1111 1111 1111")
    assert (T.SNILS, "112-233-445 95") in result
    assert (T.OGRN, "1027700132195") in result
    assert (T.CARD, "4111 1111 1111 1111") in result
    assert T.CARD not in types("карта 4111 1111 1111 1112")


def test_bank_account_is_confirmed_by_a_bik_nearby():
    assert (T.BANK_ACCOUNT, "40702810200000000001") in found(
        "Перевод на 40702810200000000001, БИК 044525225"
    )
    assert T.BANK_ACCOUNT not in types("Номер 40702810200000000001 в журнале")


def test_iban():
    assert (T.BANK_ACCOUNT, "GB82 WEST 1234 5698 7654 32") in found("IBAN GB82 WEST 1234 5698 7654 32")


def test_kpp_and_passport_need_context():
    assert (T.KPP, "770701001") in found("КПП 770701001")
    assert T.KPP not in types("строка 770701001")
    assert (T.PASSPORT, "45 08 123456") in found("паспорт 45 08 123456")
    assert (T.PASSPORT, "4508 номер 123456") in found("серия 4508 номер 123456")


def test_numbers_next_to_a_comma_are_checked():
    """Обзор 1А, P1: запятая рядом с номером (CSV) не должна прятать его от проверки."""
    result = found("ИНН,КПП\nООО Ромашка,7707083893,770701001\nОГРН,1027700132195,\nСНИЛС,11223344595,")
    assert (T.INN, "7707083893") in result
    assert (T.KPP, "770701001") in result
    assert (T.OGRN, "1027700132195") in result
    assert (T.SNILS, "11223344595") in result


def test_phone_with_any_grouping_of_ten_digits():
    """Обзор 1А, P1: код города из четырёх цифр и группы 2-2-2."""
    assert (T.PHONE, "8 (4852) 12-34-56") in found("тел. 8 (4852) 12-34-56")
    assert (T.PHONE, "+7 916 1234567") in found("звоните +7 916 1234567")


def test_lone_eight_before_a_date_is_not_a_phone():
    assert T.PHONE not in types("pid 8 2024-10-14 12:00:01 запуск")


@pytest.mark.parametrize("text", ["8-916-123-45-67", "+7 (916) 123 45 67", "8 (34396) 5-12-34", "89161234567"])
def test_phone_groups_after_the_code(text):
    """Одна цифра в группе — только в местном номере после кода в скобках."""
    assert (T.PHONE, text) in found("тел. " + text)


def test_list_of_numbers_after_an_eight_is_not_a_phone():
    """FINDINGS P2 «false … PHONE, CARD …»: у телефона после «8» код от трёх цифр и группы от двух."""
    assert T.PHONE not in types("Счёт по сетам: 8 10 12 9 11 7 15")
    assert T.PHONE not in types("Счёт по сетам: 8 10 12 19 11 17 15")
    assert T.PHONE not in types("Счёт по сетам: 8 10 12 9\n11 7 15")


def test_phone_does_not_cross_a_line_break():
    assert T.PHONE not in types("Итого строк: 8\n916 123 45 67 — код заказа")
    assert T.PHONE not in types("Итого: +7\n916 123 45 67")
    assert T.PHONE not in types("Телефонов в справочнике: 495\n123 45 67")


def test_card_next_to_an_expiry_date_a_cvv_or_another_group():
    """Обзор 1А, P1: хвост после номера или группа перед ним не должны срывать проверку Луна."""
    assert (T.CARD, "4111 1111 1111 1111") in found("карта 4111 1111 1111 1111 12/27")
    assert (T.CARD, "4111 1111 1111 1111") in found("карта 4111 1111 1111 1111 123")
    assert (T.CARD, "4111 1111 1111 1111") in found("от 2024 4111 1111 1111 1111")
    assert (T.CARD, "4111 1111 1111 1111") in found("4111 1111 1111 1111 12/27 123")


def test_card_window_inside_a_list_of_four_digit_numbers_needs_card_words():
    """FINDINGS P2: в списке портов окно «1521 3306 5432 6379» проходит проверку Луна случайно."""
    assert T.CARD not in types("порты: 1433 1521 3306 5432 6379")
    assert T.CARD not in types("порты: 1521 3306 5432 6379 1433")
    assert (T.CARD, "4111 1111 1111 1111") in found("по карте 3306 4111 1111 1111 1111")
    assert (T.CARD, "4111 1111 1111 1111") in found("Visa 4111 1111 1111 1111 3306")


@pytest.mark.parametrize("card", ["5859 - 0413 - 9685 - 9907", "5859.0413.9685.9907", "5859/0413/9685/9907"])
def test_card_groups_after_a_spaced_dash_a_dot_or_a_slash(card):
    """FINDINGS P3 «valid numbers in spaced notations…»."""
    assert (T.CARD, card) in found("оплата " + card)


@pytest.mark.parametrize(
    "text, type_, value",
    [
        ("Держи ИНН: 28 49 15 49 35.", T.INN, "28 49 15 49 35"),
        ("ИНН 52 50 96 69 28 77, КПП 770701001", T.INN, "52 50 96 69 28 77"),
        ("наш ИНН: № 28\u20114915\u20114935", T.INN, "28\u20114915\u20114935"),
        ("ИНН ( 52 - 5096692877 )", T.INN, "52 - 5096692877"),
        ("ИНН 52/50/966/928/77", T.INN, "52/50/966/928/77"),
        ("СНИЛС 96 18 44 77 86 1", T.SNILS, "96 18 44 77 86 1"),
    ],
)
def test_grouped_inn_and_snils_next_to_their_word(text, type_, value):
    assert (type_, value) in found(text)


def test_passport_next_to_an_inn_is_not_an_inn():
    """Серия и номер паспорта, 4-6 или 2-2-6, проходят проверку ИНН в одном случае из десяти."""
    for passport in ("2849 154935", "28 49 154935"):
        result = found(f"Паспорт {passport}, ИНН 7707083893")
        assert (T.PASSPORT, passport) in result
        assert (T.INN, passport) not in result


@pytest.mark.parametrize("value", ["10.10.100.101", "2026-01-01 02", "01.01.2026 06"])
def test_address_or_date_next_to_an_inn_is_not_an_inn(value):
    """Цифры адреса и даты со временем проходят проверку ИНН, а в реквизитах слово «ИНН» рядом."""
    assert (T.INN, value) not in found(f"ИНН 7707083893, сервер и выписка: {value}:00")


def test_snils_with_spaced_dashes_or_dots():
    assert (T.SNILS, "961 - 844 - 778 61") in found("номер 961 - 844 - 778 61")
    assert (T.SNILS, "961.844.778.61") in found("номер 961.844.778.61")


@pytest.mark.parametrize(
    "text",
    ["заказ 28 49 15 49 35", "ряды 96 18 44 77 86 1", "сборка 2.849.154.935", "узел 192.168.100.65",
     "встреча 12.10.2026", "архив 2024/10/14", "диапазон 2019 - 2024"],
)
def test_grouped_look_alikes_stay_open(text):
    """Пары цифр, версия и IP проходят контрольную сумму ИНН или СНИЛС, но без слова рядом это не номера."""
    assert found(text) == set()


def test_card_is_not_cut_out_of_a_longer_digit_group():
    assert T.CARD not in types("счёт 40702810200000000001")


def test_passport_number_after_the_number_sign():
    assert (T.PASSPORT, "4508 №123456") in found("Паспорт 4508 №123456")


def test_birthdate_needs_context_and_a_real_date():
    assert (T.BIRTHDATE, "01.02.1980") in found("Дата рождения: 01.02.1980")
    assert (T.BIRTHDATE, "01.02.1980") in found("Иванов, 01.02.1980 г.р.")
    assert T.BIRTHDATE not in types("Встреча 01.02.2026")
    assert T.BIRTHDATE not in types("31.02.1980 г.р.")


def test_birthdate_with_a_two_digit_year():
    """FINDINGS P3 «false positives that damage the text, and smaller recall gaps»: «д.р. 01.02.90»."""
    assert (T.BIRTHDATE, "01.02.90") in found("Петров П. П., д.р. 01.02.90")
    assert (T.BIRTHDATE, "29.02.00") in found("д.р. 29.02.00")
    assert T.BIRTHDATE not in types("д.р. 31.02.90")
    assert T.BIRTHDATE not in types("Встреча 01.02.26")
    assert T.BIRTHDATE not in types("Проект родился в 2019, версия 1.2.10")


def test_card_grouped_four_six_five():
    """Тот же обзор: «карты 4-6-5 не находятся» — не воспроизвелось, проверка остаётся."""
    assert (T.CARD, "3717 860313 72159") in found("оплата 3717 860313 72159")


def test_login_in_a_url_is_an_account_not_an_email():
    """Обзор пакета исправлений 1А, P1: «схема://ivanov@хост» — вход, и его скрывают."""
    for text, login in (
        ("git clone https://ivanov@git.contoso.ru/team/repo.git", "ivanov"),
        ("ssh://ivanov@srv-db01.contoso.ru:22", "ivanov"),
        ("ftp://petrov@files.contoso.ru", "petrov"),
    ):
        assert found(text) == {(T.ACCOUNT, login)}, text


def test_address_in_url_parameters_is_an_email_and_url_credentials_are_not():
    assert found("https://portal.contoso.ru?mail=ivanov@contoso.ru") == {(T.EMAIL, "ivanov@contoso.ru")}
    assert found("REDACTED_DB_URL_CREDENTIALSdb01.contoso.ru:5432/app") == set()


def test_standard_and_service_logins_in_a_url_are_not_masked():
    """Финальный обзор 1В: «ssh://git@…» и «ssh://root@…» не выдают человека (раздел 5.4)."""
    for text in (
        "ssh://git@gitlab.contoso.ru/team/repo.git",
        "ssh://root@srv-db01.contoso.ru",
        "ftp://anonymous@files.contoso.ru",
        "https://oauth2@git.contoso.ru/team/repo.git",
    ):
        assert found(text) == set(), text


def test_login_before_a_url_password_is_masked():
    """FINDINGS P1 «Logins and hosts in URLs…»: в «схема://логин:пароль@хост» логин оставался открытым."""
    assert found("REDACTED_DB_URL_CREDENTIALSdb01.contoso.ru/app") == {(T.ACCOUNT, "petrov")}
    assert found("REDACTED_DB_URL_CREDENTIALSdb01.contoso.ru:5432/app") == set()


@pytest.mark.parametrize(
    "text, login",
    [
        ("mongodb://petrov:Qwerty123!@db01.contoso.ru/app", "petrov"),
        ("mongodb://petrov:Pa$$w0rd$@db01.contoso.ru/app", "petrov"),
        ("redis://petrov:YWJjZGVm==@cache.contoso.ru", "petrov"),
        ("https://petrov:abc=def@git.contoso.ru", "petrov"),
        ("ftp://petrov:@files.contoso.ru", "petrov"),
        ("ssh://ivanov@srv-db01", "ivanov"),
    ],
)
def test_url_login_is_masked_whatever_the_password_and_host(text, login):
    """Обзор партии P1: вход в адресе находится сам, а не через шаблон e-mail."""
    assert (T.ACCOUNT, login) in found(text), text


def test_placeholder_logins_in_a_url_are_not_masked():
    for text in ("https://имя:пароль@host.contoso.ru/", "https://login:password@host.contoso.ru/",
                 "https://username:secret@host.contoso.ru/"):
        assert T.ACCOUNT not in types(text), text
