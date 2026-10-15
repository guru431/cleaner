import pytest

from cleaner.core import validators


@pytest.mark.parametrize("number", ["7707083893", "500100732259"])
def test_inn_accepts_numbers_with_correct_check_digits(number):
    assert validators.inn(number)


@pytest.mark.parametrize("number", ["7707083894", "500100732258", "0000000000", "12345"])
def test_inn_rejects_wrong_check_digits_zeros_and_wrong_length(number):
    assert not validators.inn(number)


def test_snils():
    assert validators.snils("11223344595")
    assert not validators.snils("11223344596")


def test_ogrn_of_13_and_15_digits():
    assert validators.ogrn("1027700132195")
    assert validators.ogrn("304500116000157")
    assert not validators.ogrn("1027700132196")


def test_luhn():
    assert validators.luhn("4111111111111111")
    assert not validators.luhn("4111111111111112")


def test_bank_account_key_depends_on_bik():
    assert validators.bank_account("40702810200000000001", "044525225")
    assert not validators.bank_account("40702810300000000001", "044525225")


def test_iban_ignores_spaces_and_rejects_non_ascii_without_raising():
    assert validators.iban("GB82 WEST 1234 5698 7654 32")
    assert not validators.iban("GB82 WEST 1234 5698 7654 33")
    assert not validators.iban("ЯЯ82 WEST 1234 5698 7654 32")
