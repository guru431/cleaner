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


def test_card_next_to_an_expiry_date_a_cvv_or_another_group():
    """Обзор 1А, P1: хвост после номера или группа перед ним не должны срывать проверку Луна."""
    assert (T.CARD, "4111 1111 1111 1111") in found("карта 4111 1111 1111 1111 12/27")
    assert (T.CARD, "4111 1111 1111 1111") in found("карта 4111 1111 1111 1111 123")
    assert (T.CARD, "4111 1111 1111 1111") in found("от 2024 4111 1111 1111 1111")


def test_card_is_not_cut_out_of_a_longer_digit_group():
    assert T.CARD not in types("счёт 40702810200000000001")


def test_passport_number_after_the_number_sign():
    assert (T.PASSPORT, "4508 №123456") in found("Паспорт 4508 №123456")


def test_birthdate_needs_context_and_a_real_date():
    assert (T.BIRTHDATE, "01.02.1980") in found("Дата рождения: 01.02.1980")
    assert (T.BIRTHDATE, "01.02.1980") in found("Иванов, 01.02.1980 г.р.")
    assert T.BIRTHDATE not in types("Встреча 01.02.2026")
    assert T.BIRTHDATE not in types("31.02.1980 г.р.")


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
