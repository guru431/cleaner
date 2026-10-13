"""Слой 1: шаблоны с проверками и контекстными словами."""
from __future__ import annotations

import re
from collections.abc import Callable
from datetime import date

from cleaner.core import validators
from cleaner.core.detect.base import DetectContext
from cleaner.core.types import EntityType, Span

name = "rules"

_BEFORE = 40
_AFTER = 15

_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PHONE_RU = re.compile(r"(?<![\w+])(?:\+7|8)[\s(-]{0,3}\d{3}[\s)-]{0,3}\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)")
_PHONE_INTL = re.compile(
    r"(?<![\w+])\+\d{1,3}[\s(-]{0,2}\d{2,4}[\s)-]{0,2}\d{2,4}(?:[\s-]?\d{2,4}){1,3}(?!\d)"
)
_PHONE_LOCAL = re.compile(r"(?<![\w+])\(?\d{3}\)?[\s-]{0,2}\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)")
_CARD = re.compile(r"(?<![\w-])(?:\d{13,19}|\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?)(?![\w-])")
_NUMBER = re.compile(r"(?<![\w.,])\d{9,20}(?!\w|[.,]\d)")
_SNILS = re.compile(r"(?<![\w-])\d{3}-\d{3}-\d{3}[ -]\d{2}(?!\d)")
_BIK = re.compile(r"(?<!\d)04\d{7}(?!\d)")
_IBAN = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])"
)
_PASSPORT = re.compile(r"(?<![\w-])\d{2} ?\d{2} ?\d{6}(?![\w-])")
_PASSPORT_WORDS = re.compile(
    r"сери[яи]\s*(\d{2}\s?\d{2})\s*,?\s*(?:номер|№|n)\s*(\d{6})(?!\d)", re.IGNORECASE
)
_DATE = re.compile(
    r"(?<![\w.])(?:(\d{1,2})[./-](\d{1,2})[./-](\d{4})|(\d{4})-(\d{2})-(\d{2}))(?!\w|\.\d)"
)

_PHONE_WORDS = ("тел", "моб", "phone", "tel.", "tel:", "звон", "номер")
_ACCOUNT_WORDS = ("счёт", "счет", "р/с", "к/с", "account")
_PASSPORT_CONTEXT = ("паспорт", "серия", "выдан")
_BIRTH_WORDS = ("дата рождения", "д.р.", "г.р.", "родил", "born", "dob", "date of birth", "birthday")

Add = Callable[..., None]


def _near(text: str, start: int, end: int, words: tuple[str, ...]) -> bool:
    around = (text[max(0, start - _BEFORE):start] + " " + text[end:end + _AFTER]).lower()
    return any(word in around for word in words)


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _valid_date(m: re.Match[str]) -> bool:
    if m.group(1):
        day, month, year = m.group(1), m.group(2), m.group(3)
    else:
        day, month, year = m.group(6), m.group(5), m.group(4)
    try:
        date(int(year), int(month), int(day))
    except ValueError:
        return False
    return True


def _number(text: str, m: re.Match[str], add: Add) -> None:
    digits, start, end = m.group(), m.start(), m.end()
    if len(digits) in (10, 12) and validators.inn(digits):
        add(start, end, EntityType.INN, True)
    elif len(digits) == 11 and validators.snils(digits):
        add(start, end, EntityType.SNILS, True)
    elif len(digits) in (13, 15) and validators.ogrn(digits):
        add(start, end, EntityType.OGRN, True)
    elif len(digits) == 20:
        window = text[max(0, start - 300):end + 300]
        if any(validators.bank_account(digits, bik.group()) for bik in _BIK.finditer(window)):
            add(start, end, EntityType.BANK_ACCOUNT, True)
        elif _near(text, start, end, _ACCOUNT_WORDS):
            add(start, end, EntityType.BANK_ACCOUNT)
    elif len(digits) == 9 and _near(text, start, end, ("кпп",)):
        add(start, end, EntityType.KPP)
    elif len(digits) == 16 and _near(text, start, end, ("полис", "омс")):
        add(start, end, EntityType.OMS)


def detect(text: str, ctx: DetectContext) -> list[Span]:
    spans: list[Span] = []

    def add(start: int, end: int, type_: EntityType, validated: bool = False) -> None:
        spans.append(Span(start, end, type_, name, validated=validated))

    for m in _EMAIL.finditer(text):
        add(m.start(), m.end(), EntityType.EMAIL, True)
    for pattern in (_PHONE_RU, _PHONE_INTL):
        for m in pattern.finditer(text):
            if 8 <= len(_digits(m.group())) <= 15:
                add(m.start(), m.end(), EntityType.PHONE)
    for m in _PHONE_LOCAL.finditer(text):
        if _near(text, m.start(), m.end(), _PHONE_WORDS):
            add(m.start(), m.end(), EntityType.PHONE)
    for m in _CARD.finditer(text):
        digits = _digits(m.group())
        if 13 <= len(digits) <= 19 and validators.luhn(digits):
            add(m.start(), m.end(), EntityType.CARD, True)
    for m in _SNILS.finditer(text):
        if validators.snils(_digits(m.group())):
            add(m.start(), m.end(), EntityType.SNILS, True)
    for m in _NUMBER.finditer(text):
        _number(text, m, add)
    for m in _IBAN.finditer(text):
        if validators.iban(m.group()):
            add(m.start(), m.end(), EntityType.BANK_ACCOUNT, True)
    for m in _PASSPORT.finditer(text):
        if _near(text, m.start(), m.end(), _PASSPORT_CONTEXT):
            add(m.start(), m.end(), EntityType.PASSPORT)
    for m in _PASSPORT_WORDS.finditer(text):
        add(m.start(1), m.end(2), EntityType.PASSPORT)
    for m in _DATE.finditer(text):
        if _valid_date(m) and _near(text, m.start(), m.end(), _BIRTH_WORDS):
            add(m.start(), m.end(), EntityType.BIRTHDATE)
    return spans
