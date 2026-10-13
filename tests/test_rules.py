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


def test_birthdate_needs_context_and_a_real_date():
    assert (T.BIRTHDATE, "01.02.1980") in found("Дата рождения: 01.02.1980")
    assert (T.BIRTHDATE, "01.02.1980") in found("Иванов, 01.02.1980 г.р.")
    assert T.BIRTHDATE not in types("Встреча 01.02.2026")
    assert T.BIRTHDATE not in types("31.02.1980 г.р.")
