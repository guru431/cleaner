"""Контрольные суммы номеров. Все функции, кроме iban, принимают строку из одних цифр."""
from __future__ import annotations

_INN10 = (2, 4, 10, 3, 5, 9, 4, 6, 8)
_INN12_FIRST = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
_INN12_SECOND = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
_ACCOUNT_WEIGHTS = (7, 1, 3) * 8


def _all_zero(digits: str) -> bool:
    return set(digits) <= {"0"}


def luhn(digits: str) -> bool:
    if _all_zero(digits):
        return False
    total = 0
    for position, char in enumerate(reversed(digits)):
        digit = int(char)
        if position % 2 == 1:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0


def _weighted(digits: str, weights: tuple[int, ...]) -> int:
    return sum(int(d) * w for d, w in zip(digits, weights)) % 11 % 10


def inn(digits: str) -> bool:
    if _all_zero(digits):
        return False
    if len(digits) == 10:
        return _weighted(digits, _INN10) == int(digits[9])
    if len(digits) == 12:
        return (
            _weighted(digits, _INN12_FIRST) == int(digits[10])
            and _weighted(digits, _INN12_SECOND) == int(digits[11])
        )
    return False


def snils(digits: str) -> bool:
    if len(digits) != 11 or _all_zero(digits):
        return False
    total = sum(int(d) * w for d, w in zip(digits[:9], range(9, 0, -1)))
    return total % 101 % 100 == int(digits[9:])


def ogrn(digits: str) -> bool:
    if _all_zero(digits):
        return False
    if len(digits) == 13:
        return int(digits[:12]) % 11 % 10 == int(digits[12])
    if len(digits) == 15:
        return int(digits[:14]) % 13 % 10 == int(digits[14])
    return False


def bank_account(account: str, bik: str) -> bool:
    """Ключ расчётного счёта: три последние цифры БИК и 20 цифр счёта."""
    if len(account) != 20 or len(bik) != 9:
        return False
    digits = bik[-3:] + account
    return sum(int(d) * w % 10 for d, w in zip(digits, _ACCOUNT_WEIGHTS)) % 10 == 0


def iban(value: str) -> bool:
    compact = value.replace(" ", "").upper()
    if not (15 <= len(compact) <= 34 and compact.isascii() and compact.isalnum()):
        return False
    if not (compact[:2].isalpha() and compact[2:4].isdigit()):
        return False
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(char, 36)) for char in rearranged)) % 97 == 1
