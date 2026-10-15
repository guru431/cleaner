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
# «схема://» прямо перед «…@хост»: то, что до «@», — пользователь адреса, а не e-mail. Знаки «?#=»
# в нём значат, что это уже параметры адреса («?mail=ivanov@contoso.ru»), — тогда это e-mail.
_USERINFO_BEFORE = re.compile(r"[a-z][a-z0-9+.-]{0,31}://(?P<user>[^\s/@]*)$", re.IGNORECASE)
_NOT_USERINFO = re.compile(r"[?#=]")
# Вход в адресе: «схема://логин@хост» и «схема://логин:пароль@хост». Ищется сам, а не через шаблон
# e-mail: пароль бывает с «!$#=», хост — без точки. Пароль найдёт слой секретов, хост — слой 3.
_URL_LOGIN = re.compile(
    r"\b[a-z][a-z0-9+.-]{0,31}://(?P<login>[^\s/?#@:]*)(?::[^\s/@]*)?@(?=[\w\[])", re.IGNORECASE
)
# Служебные входы и подстановки человека не выдают: ssh://git@…, https://login:password@…
# Список свой, не общий список стандартных учётных записей: тот правило «ДОМЕН\логин» использует
# и для доменов, и «SA\petrov» перестал бы скрываться.
_URL_SERVICE_LOGINS = frozenset({
    "git", "anonymous", "ftp", "oauth2", "postgres", "mysql", "ubuntu", "ec2-user", "app", "user", "sa",
    "x-access-token", "x-oauth-basic", "gitlab-ci-token", "login", "username", "name", "имя", "логин",
    "пользователь",
})
_IPV4_DOMAIN = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
# +7 или 8 и ровно десять цифр с любыми разделителями в одной строке: «8 (4852) 12-34-56», «+7 916 1234567».
# Перевод строки телефон не переходит: «8» в конце строки и число на следующей — разные значения.
_PHONE_RU = re.compile(r"(?<![\w+])(?:\+7|8)(?:(?:[^\S\r\n]|[()-]){0,3}\d){10}(?!\d)")
# «8 2024-10-14 12:00» — дата в журнале, а не телефон.
_DATE_INSIDE = re.compile(r"(?:19|20)\d\d-[01]\d-[0-3]\d")
_PHONE_INTL = re.compile(
    r"(?<![\w+])\+\d{1,3}(?:[^\S\r\n]|[(-]){0,2}\d{2,4}(?:[^\S\r\n]|[)-]){0,2}\d{2,4}"
    r"(?:(?:[^\S\r\n]|-)?\d{2,4}){1,3}(?!\d)"
)
_PHONE_LOCAL = re.compile(
    r"(?<![\w+])\(?\d{3}\)?(?:[^\S\r\n]|-){0,2}\d{3}(?:[^\S\r\n]|-)?\d{2}(?:[^\S\r\n]|-)?\d{2}(?!\d)"
)
# Группы цифр через одиночный пробел или дефис; номер карты ищется окнами внутри такой цепочки,
# потому что рядом бывают срок действия, CVV или чужая группа («от 2024 4111 1111 1111 1111»).
_DIGIT_RUN = re.compile(r"(?<![\w-])\d+(?:[ -]\d+)*(?![\w-])")
_DIGIT_GROUP = re.compile(r"\d+")
# Окно номера карты среди других четырёхзначных групп — список (порты, коды), а не карта: в нём каждое
# десятое окно проходит проверку Луна. Такое окно принимается только при словах о карте рядом.
_CARD_WORDS = re.compile(r"карт|кредитк|card|visa|master|maestro|amex|cvv|cvc|\bмир\b", re.IGNORECASE)
_YEAR = re.compile(r"(?:19|20)\d\d")
# Запятая рядом с номером — разделитель CSV, а не десятичная дробь: отсеивают контрольные разряды.
_NUMBER = re.compile(r"(?<![\w.])\d{9,20}(?!\w|\.\d)")
_SNILS = re.compile(r"(?<![\w-])\d{3}-\d{3}-\d{3}[ -]\d{2}(?!\d)")
_BIK = re.compile(r"(?<!\d)04\d{7}(?!\d)")
_IBAN = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])"
)
_PASSPORT = re.compile(r"(?<![\w-])\d{2} ?\d{2} ?(?:№ ?)?\d{6}(?![\w-])")
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


def _phone_groups(value: str) -> bool:
    """После +7/8 код от трёх цифр и группы от двух: «8 10 12 9 11 7 15» — счёт, а не телефон.

    Группа из одной цифры бывает в местном номере после пятизначного кода в скобках: «8 (34396) 5-12-34».
    """
    groups = _DIGIT_GROUP.findall(value[2:] if value.startswith("+") else value[1:])
    return len(groups[0]) >= 3 and ("(" in value or min(len(group) for group in groups) >= 2)


def _listed(groups: list[tuple[int, int, str]], first: int, last: int) -> bool:
    """Стоит ли окно из нескольких групп среди других четырёхзначных групп цепочки, кроме года («от 2024 …»)."""
    if first == last:
        return False                                    # 13–19 цифр слитно — номер сам по себе
    neighbours = [groups[i][2] for i in (first - 1, last + 1) if 0 <= i < len(groups)]
    return any(len(group) == 4 and not _YEAR.fullmatch(group) for group in neighbours)


def _card_shape(parts: list[str]) -> bool:
    """Похожа ли последовательность групп на запись номера карты."""
    if len(parts) == 1:
        return True                                     # 13–19 цифр подряд
    if [len(part) for part in parts] in ([4, 6, 4], [4, 6, 5]):
        return True                                     # American Express, Diners Club
    return all(len(part) == 4 for part in parts[:-1]) and 1 <= len(parts[-1]) <= 4


def _extendable(parts: list[str]) -> bool:
    """Может ли окно стать номером карты, если дописать к нему группы: все группы по 4 цифры или 4-6."""
    return all(len(part) == 4 for part in parts) or [len(part) for part in parts] == [4, 6]


def _cards(text: str, m: re.Match[str], add: Add) -> None:
    """Все окна подряд идущих групп, которые выглядят как номер карты и проходят проверку Луна.

    Окно перестаёт расти, как только номером карты стать уже не может: иначе цепочка коротких
    чисел («8 8 8 …») перебирала бы по девятнадцать окон на каждую группу.
    """
    groups = [(g.start() + m.start(), g.end() + m.start(), g.group()) for g in _DIGIT_GROUP.finditer(m.group())]
    for first in range(len(groups)):
        digits = ""
        for last in range(first, len(groups)):
            digits += groups[last][2]
            if len(digits) > 19:
                break
            parts = [group[2] for group in groups[first:last + 1]]
            if (
                len(digits) >= 13 and _card_shape(parts) and validators.luhn(digits)
                and (not _listed(groups, first, last) or _CARD_WORDS.search(
                    text[max(0, m.start() - _BEFORE):m.start()] + " " + text[m.end():m.end() + _AFTER]
                ))
            ):
                add(groups[first][0], groups[last][1], EntityType.CARD, True)
            if not _extendable(parts):
                break


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
        local, _, domain = m.group().rpartition("@")
        url = _USERINFO_BEFORE.search(text[max(0, m.start() - 300):m.start()])
        if url and not _NOT_USERINFO.search(url.group("user") + local):
            continue        # пользователь адреса, а не e-mail: вход — правило _URL_LOGIN ниже
        if _IPV4_DOMAIN.fullmatch(domain):
            add(m.start(), m.start() + len(local), EntityType.ACCOUNT)     # вход вида ivanov@10.1.2.5
            continue
        add(m.start(), m.end(), EntityType.EMAIL, True)
    skip = ctx.builtin.builtin_accounts | _URL_SERVICE_LOGINS
    for m in _URL_LOGIN.finditer(text):
        login = m.group("login")
        if login and login.lower() not in skip:
            add(m.start("login"), m.end("login"), EntityType.ACCOUNT)
    for pattern in (_PHONE_RU, _PHONE_INTL):
        for m in pattern.finditer(text):
            if pattern is _PHONE_RU and not _phone_groups(m.group()):
                continue
            if 8 <= len(_digits(m.group())) <= 15 and not _DATE_INSIDE.search(m.group()):
                add(m.start(), m.end(), EntityType.PHONE)
    for m in _PHONE_LOCAL.finditer(text):
        if _near(text, m.start(), m.end(), _PHONE_WORDS):
            add(m.start(), m.end(), EntityType.PHONE)
    for m in _DIGIT_RUN.finditer(text):
        _cards(text, m, add)
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
