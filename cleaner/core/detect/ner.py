"""Слой 4: модели распознавания имён (раздел 5.5). Здесь — разбор находок; сами модели — в ner_models.py."""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from cleaner.core.detect.base import DetectContext
from cleaner.core.entities.names import animate, common_nouns
from cleaner.core.types import EntityType, Span

name = "ner"
THRESHOLD = 0.25          # низкий порог — в пользу полноты (раздел 5.5)

# Метка модели -> категория. Метки, которых здесь нет (EMAIL, PHONE, INN, SNILS, OMS, CREDIT_CARD, PASSPORT,
# IP_ADDRESS, URL), надёжнее находят слои 1–3: находки модели по ним отбрасываются.
_CATEGORY = {
    "FIRST_NAME": "person", "LAST_NAME": "person", "MIDDLE_NAME": "person", "name": "person",
    "organization": "org",
    "location address": "address",
    "STREET": "street", "HOUSE": "street",
    "COUNTRY": "place", "REGION": "place", "DISTRICT": "place", "CITY": "place",
    # Номера документов без своего типа в ТЗ и без правила в слоях 1–3.
    "DRIVER_LICENSE": "document", "MILITARY_ID": "document", "BIRTH_CERTIFICATE": "document",
}
# Адреса GLiNER («location address») здесь нет: это часть адреса наравне с частями русской модели (_addresses).
_TYPES = {"person": EntityType.PERSON, "org": EntityType.ORG, "document": EntityType.PASSPORT}
# Между частями одного почтового адреса — запятые, точки, пробелы и служебные слова.
ADDRESS_GAP = re.compile(
    r"(?:[\s,.:№-]|\b(?:г|гор|город|ул|улица|пр|просп|проспект|пер|переулок|ш|шоссе|наб|набережная|б-р|бульвар|"
    r"пл|площадь|д|дом|корп|к|стр|строение|кв|квартира|оф|офис|обл|область|р-н|район|пос|пгт|с|дер|мкр)\b)*",
    re.IGNORECASE,
)
_ADDRESS_GAP_MAX = 40
# Адрес GLiNER — адрес и без улицы: открытые наборы размечают адресом и место («в Москве», «на Мойке»), и правило
# русской модели «город сам не скрывается» снизило бы полноту «Организаций и почтовых адресов» на hivetrace с 0,886
# до 0,858. Кроме находки с числом, которое не похоже на дом: «location address» GLiNER называет и «1С». Дом — число
# отдельным словом («Ленина 5», «10 Downing St»), от двух цифр («12к1»; номер документа тоже остаётся скрытым — слои 1–3
# без контекста его не находят) или слово улицы рядом с номером («ул. Мира 5А»).
_HOUSE = re.compile(
    r"\d{2}|(?<![^\W\d_])\d(?![^\W\d_])"
    r"|\b(?:ул|улиц\w*|пр|просп|пр-т|проспект\w*|пер|переул\w*|ш|шоссе|наб|набережн\w*|б-р|бульвар\w*|пл|площад\w*"
    r"|проезд\w*|тупик\w*|алле[яиюе]|мкр|микрорайон\w*|street|st|avenue|ave|road|rd|lane|ln|boulevard|blvd|drive|dr)\b",
    re.IGNORECASE,
)
_WORD = re.compile(r"\S+")
# Строчные буквы вплотную к цифрам — пароль: «sunflower77», «Qwerty2024». Не серия документа «АА1234567» и не логин
# или имя через подчёркивание («ivanov_test», «ИВАНОВА_МАРИЯ»): слой 5 их пропускает, а без находки слоя 4 они
# открыты (замер слоёв 1–5 на открытых наборах: три номера документов и одно имя).
_IDENTIFIER = re.compile(r"[a-zа-яё]{3}\d")


@dataclass(frozen=True)
class Found:
    """Находка одной модели: позиции в тексте, метка модели как есть, уверенность."""

    start: int
    end: int
    label: str
    score: float


class Tagger(Protocol):
    def tag(self, text: str) -> list[Found]: ...


def windows(text: str, size: int = 200, overlap: int = 40) -> list[tuple[int, int]]:
    """Окна по size слов с перекрытием overlap: модель с пределом около 512 токенов видит весь текст."""
    words = [m.span() for m in _WORD.finditer(text)]
    out: list[tuple[int, int]] = []
    index = 0
    while index < len(words):
        chunk = words[index:index + size]
        out.append((chunk[0][0], chunk[-1][1]))
        if index + size >= len(words):
            break
        index += size - overlap
    return out


def _joined(found: list[Found]) -> list[Found]:
    """Обрывки одной сущности (модель начинает её заново посреди слова) и повторы из перекрытых окон — одна находка."""
    out: list[Found] = []
    for item in sorted(found, key=lambda f: (f.start, f.end)):
        last = out[-1] if out else None
        if last is not None and _CATEGORY[last.label] == _CATEGORY[item.label] and item.start <= last.end:
            out[-1] = Found(last.start, max(last.end, item.end), last.label, max(last.score, item.score))
        else:
            out.append(item)
    return out


def _common_words(text: str, found: Found) -> bool:
    """Организация из обычных слов: GLiNER при пороге 0,25 так называет «банк», «бухгалтерии», «отдел кадров».

    Строчная находка ORG из одних существительных отбрасывается (находок ORG на hivetrace — 152 вместо 318,
    на jayguard — 787 вместо 1329; полнота классов QA-3 на трёх открытых наборах не меняется). Заглавная буква,
    цифра, прилагательное или слово не из словаря находку оставляют: в чатах строчными пишут и имена, и улицы
    («алексей с новослободской 7»), и названия («автосити»).
    Порог для одной метки не годится: «Краснодар» в адресе модель тоже называет организацией с уверенностью 0,26–0,68.
    """
    value = text[found.start:found.end]
    return (
        _CATEGORY[found.label] == "org" and value == value.lower() and not any(c.isdigit() for c in value)
        and common_nouns(value)
    )


# Не организации, хотя GLiNER при пороге 0,25 называет их так, заглавными и без названия рядом: номера документов
# и реестры, страховки, налоги и режимы налогообложения, ЖКХ, а также организационно-правовая форма сама по себе
# («ИП», «ООО»; форма с названием в кавычках — правило orgs.py, формы — те же, что там). На открытых наборах это
# самый частый шум ORG. Государственные органы (ФНС, ПФР, МВД, ГИБДД, МФЦ) — организации и сюда не входят: их
# открывает словарь «никогда не скрывать» (раздел 5.5 ТЗ), а не модель.
# Сверх этого замер 15.10.2026 на тех же наборах нашёл: документ с обычным словом («полис ОМС», «ИНН юрлица»),
# экзамены, анализы и происшествия, слова ИТ, страны, обычное существительное с заглавной буквы («Банк ответил»,
# «Сервер упал»). Только целой находкой: «Банк «Восток»», «Правительство РФ», «фонд ОМС» остаются. «Система» и
# «Центр» сюда не входят: бывают названиями (АФК «Система»).
_NOT_ORGANISATIONS = frozenset({
    "снилс", "инн", "кпп", "огрн", "огрнип", "бик", "окпо", "оквэд", "октмо", "окато", "егрюл", "егрип", "егрн",
    "птс", "стс", "ву", "эцп", "кэп", "укэп", "фио", "паспорт", "тс", "пдн",
    "омс", "дмс", "осаго", "каско", "полис омс", "полис дмс", "полис осаго", "полис каско",
    "инн юрлица", "инн физлица", "инн организации", "огрн организации", "юрлицо", "юрлица", "физлицо", "физлица",
    "ндс", "ндфл", "усн", "енвд", "псн", "осно", "есхн", "нпд", "енс", "енп", "аусн", "жкх", "жку",
    "егэ", "огэ", "гиа", "дтп", "орз", "орви", "узи", "мрт", "пцр", "бцж",
    "ии", "ai", "it", "ит", "hr", "pr", "smm", "crm", "llm", "jwt", "смс", "sms", "тз", "пк",
    "сша", "рф", "оаэ", "вов", "сво",
    "банк", "bank", "сервер", "компания", "организация", "фирма", "офис", "филиал", "отдел", "бухгалтерия",
    "администрация", "магазин", "налоговая",
    "ооо", "оао", "зао", "пао", "нао", "ао", "ип", "фгуп", "фгбу", "фгбоу", "гуп", "муп", "гбу", "мбу", "ано", "нко",
    "тоо", "тсж", "снт", "общество с ограниченной ответственностью", "акционерное общество",
    "публичное акционерное общество", "непубличное акционерное общество", "закрытое акционерное общество",
    "открытое акционерное общество", "llc", "ltd", "inc", "gmbh", "jsc", "plc",
})
_EDGE = " \t\r\n.,;:!?\"'«»„“”()"


def _not_organisation(text: str, found: Found) -> bool:
    return _CATEGORY[found.label] == "org" and text[found.start:found.end].strip(_EDGE).lower() in _NOT_ORGANISATIONS


# Перед началом предложения — конец предыдущего («.», «!», «?», «…») или перевод строки; между ними — пробелы,
# кавычки, скобки, тире и знаки списка. Точка после слова до четырёх букв — сокращение («проф. Лебедь», «исп. Берёза»).
_OPENERS = "\"'«„“([—–-•*"
_SENTENCE_END = ".!?…"
_ABBREVIATION = 4
_LETTERS = re.compile(r"[^\W\d_]+")
_RUSSIAN_PERSON = frozenset({"FIRST_NAME", "LAST_NAME", "MIDDLE_NAME"})


def _abbreviation(text: str, dot: int) -> bool:
    start = dot
    while start > 0 and dot - start <= _ABBREVIATION and text[start - 1].isalpha():
        start -= 1
    return text[dot] == "." and 0 < dot - start <= _ABBREVIATION


def _sentence_start(text: str, start: int) -> bool:
    position = start
    while position > 0 and (text[position - 1].isspace() or text[position - 1] in _OPENERS):
        position -= 1
    return position == 0 or "\n" in text[position:start] or (
        text[position - 1] in _SENTENCE_END and not _abbreviation(text, position - 1)
    )


def _sentence_noun(text: str, found: Found, russian: bytearray) -> bool:
    """Человек GLiNER — одно неодушевлённое нарицательное существительное словаря в начале предложения («Копию
    отправил Петров»): заглавная буква там ничего не говорит. Имя, фамилия и отчество по словарю (раздел 5.9) и
    существительное, у которого есть одушевлённый разбор, остаются: фамилии «Волк», «Кузнец», «Ворона» — тоже
    существительные. Находку русской модели на том же месте (russian — знаки, занятые её людьми) правило не трогает.
    Цена — фамилия из неодушевлённого существительного («Берёза») в начале предложения, которую нашёл только GLiNER,
    остаётся открытой, а слово о человеке («Клиент», «Директор») там остаётся человеком."""
    value = text[found.start:found.end]
    return (
        found.label == "name" and _LETTERS.fullmatch(value) is not None and _sentence_start(text, found.start)
        and common_nouns(value) and not animate(value.lower()) and russian.find(1, found.start, found.end) < 0
    )


def identifier(text: str, span: Span) -> bool:
    """PERSON или ORG, похожий на пароль («sunflower77»); слово берётся целиком — модель может пометить «sunflower»
    внутри «sunflower77»."""
    start, end = span.start, span.end
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        start -= 1
    while end < len(text) and (text[end].isalnum() or text[end] == "_"):
        end += 1
    return span.type in (EntityType.PERSON, EntityType.ORG) and _IDENTIFIER.search(text, start, end) is not None


def _street(text: str, part: Found) -> bool:
    """Часть, с которой соседние части становятся адресом: улица или дом русской модели, адрес GLiNER (см. _HOUSE)."""
    if _CATEGORY[part.label] != "address":
        return _CATEGORY[part.label] == "street"
    value = text[part.start:part.end]
    return not any(c.isdigit() for c in value) or _HOUSE.search(value) is not None


def _addresses(text: str, parts: list[Found]) -> list[tuple[int, int, float]]:
    """Части адреса подряд — один ADDRESS, если среди них есть улица или дом: город или страна сами не скрываются.
    Адрес GLiNER рядом с частями русской модели входит в тот же ADDRESS: двумя находками запятая между ними
    оставалась открытой."""
    groups: list[list[Found]] = []
    for part in sorted(parts, key=lambda f: f.start):
        gap = text[groups[-1][-1].end:part.start] if groups else ""
        if groups and len(gap) <= _ADDRESS_GAP_MAX and ADDRESS_GAP.fullmatch(gap):
            groups[-1].append(part)
        else:
            groups.append([part])
    return [
        (group[0].start, max(p.end for p in group), max(p.score for p in group))
        for group in groups if any(_street(text, p) for p in group)
    ]


class NerLayer:
    """Обе модели проходят по всему тексту, находки складываются (раздел 5.5)."""

    name = name

    def __init__(self, taggers: Sequence[Tagger]):
        self.taggers = tuple(taggers)

    def detect(self, text: str, ctx: DetectContext | None = None) -> list[Span]:
        found: list[Found] = []
        for tagger in self.taggers:
            found += [f for f in _joined([
                f for f in tagger.tag(text) if f.label in _CATEGORY and f.score >= THRESHOLD and f.end > f.start
            ]) if not _common_words(text, f) and not _not_organisation(text, f)]
        russian = bytearray(len(text))          # картой, а не перебором: находок на длинном тексте тысячи
        for f in found:
            if f.label in _RUSSIAN_PERSON:
                russian[f.start:f.end] = b"\x01" * (f.end - f.start)
        found = [f for f in found if not _sentence_noun(text, f, russian)]
        spans = [
            Span(f.start, f.end, _TYPES[_CATEGORY[f.label]], name, f.score)
            for f in found if _CATEGORY[f.label] in _TYPES
        ]
        places = [f for f in found if _CATEGORY[f.label] in ("street", "place", "address")]
        spans += [Span(start, end, EntityType.ADDRESS, name, score) for start, end, score in _addresses(text, places)]
        return spans
