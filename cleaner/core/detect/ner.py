"""Слой 4: модели распознавания имён (раздел 5.5). Здесь — разбор находок; сами модели — в ner_models.py."""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from cleaner.core.detect.base import DetectContext
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
_TYPES = {"person": EntityType.PERSON, "org": EntityType.ORG, "address": EntityType.ADDRESS, "document": EntityType.PASSPORT}
# Между частями одного почтового адреса — запятые, точки, пробелы и служебные слова.
ADDRESS_GAP = re.compile(
    r"(?:[\s,.:№-]|\b(?:г|гор|город|ул|улица|пр|просп|проспект|пер|переулок|ш|шоссе|наб|набережная|б-р|бульвар|"
    r"пл|площадь|д|дом|корп|к|стр|строение|кв|квартира|оф|офис|обл|область|р-н|район|пос|пгт|с|дер|мкр)\b)*",
    re.IGNORECASE,
)
_ADDRESS_GAP_MAX = 40
_WORD = re.compile(r"\S+")


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


def _addresses(text: str, parts: list[Found]) -> list[tuple[int, int, float]]:
    """Части адреса подряд — один ADDRESS, если среди них есть улица или дом: город или страна сами не скрываются."""
    groups: list[list[Found]] = []
    for part in sorted(parts, key=lambda f: f.start):
        gap = text[groups[-1][-1].end:part.start] if groups else ""
        if groups and len(gap) <= _ADDRESS_GAP_MAX and ADDRESS_GAP.fullmatch(gap):
            groups[-1].append(part)
        else:
            groups.append([part])
    return [
        (group[0].start, max(p.end for p in group), max(p.score for p in group))
        for group in groups if any(_CATEGORY[p.label] == "street" for p in group)
    ]


class NerLayer:
    """Обе модели проходят по всему тексту, находки складываются (раздел 5.5)."""

    name = name

    def __init__(self, taggers: Sequence[Tagger]):
        self.taggers = tuple(taggers)

    def detect(self, text: str, ctx: DetectContext | None = None) -> list[Span]:
        found: list[Found] = []
        for tagger in self.taggers:
            found += _joined([
                f for f in tagger.tag(text) if f.label in _CATEGORY and f.score >= THRESHOLD and f.end > f.start
            ])
        spans = [
            Span(f.start, f.end, _TYPES[_CATEGORY[f.label]], name, f.score)
            for f in found if _CATEGORY[f.label] in _TYPES
        ]
        places = [f for f in found if _CATEGORY[f.label] in ("street", "place")]
        spans += [Span(start, end, EntityType.ADDRESS, name, score) for start, end, score in _addresses(text, places)]
        return spans
