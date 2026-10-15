"""Меры качества (ТЗ, раздел 9, QA-2): полнота по сущностям, точность, лишние замены среди версий, кодов ошибок
и общеизвестных доменов."""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from cleaner.core.detect.base import load_builtin
from cleaner.core.types import EntityType

T = EntityType


@dataclass(frozen=True)
class GoldSpan:
    start: int
    end: int
    type: EntityType
    entity: int            # номер сущности в примере: защищена, только если скрыты все её упоминания
    origin: str = ""       # dictionary — значение из словаря организации (класс QA-3 «Словарь организации»)


@dataclass(frozen=True)
class Example:
    text: str
    spans: tuple[GoldSpan, ...]


Predicted = tuple[int, int, EntityType]
Predict = Callable[[str], list[Predicted]]

# Классы QA-3: название, отбор сущности (тип, происхождение), целевая полнота; None — цель не задана, значение измеряется.
CLASSES: tuple[tuple[str, Callable[[EntityType, str], bool], float | None], ...] = (
    ("Жёсткий формат и контрольная сумма", lambda t, o: t in {T.EMAIL, T.IP, T.MAC, T.INN, T.SNILS, T.OGRN, T.CARD}, 0.99),
    ("Секреты", lambda t, o: t is T.SECRET, 0.99),
    ("Словарь организации", lambda t, o: o == "dictionary", 1.00),
    ("ФИО", lambda t, o: t is T.PERSON, 0.90),
    ("Организации и почтовые адреса", lambda t, o: t in {T.ORG, T.ADDRESS}, 0.80),
    ("Хосты и учётные записи", lambda t, o: t in {T.HOST, T.ACCOUNT}, None),
)
_VERSION = re.compile(r"(?<![\w.])v?\d+\.\d+(?:\.\d+)?(?![\w.])")          # 2.4, 10.0.19045 — но не IPv4
_ERROR = re.compile(
    r"(?<![\w-])(?:0x[0-9A-Fa-f]{4,8}|[A-Z]{2,10}-\d{3,6}|(?:HTTP|код|code|error|ошибка)\s+\d{3,5})(?![\w-])",
    re.IGNORECASE,
)
_DOTTED = re.compile(r"(?<![\w.-])[\w-]+(?:\.[\w-]+)+(?![\w-])")


@dataclass
class Report:
    entities: Counter = field(default_factory=Counter)           # тип -> сущностей в эталоне
    protected: Counter = field(default_factory=Counter)          # тип -> скрытых целиком
    classes: dict[str, list[int]] = field(default_factory=dict)  # класс QA-3 -> [скрыто, всего]
    found: Counter = field(default_factory=Counter)              # тип найденного -> фрагментов
    correct: Counter = field(default_factory=Counter)            # тип найденного -> задевших эталон
    candidates: int = 0           # версий, кодов ошибок и общеизвестных доменов вне эталонной разметки
    overmasked: int = 0           # из них заменено


def covered(start: int, end: int, ranges: Sequence[tuple[int, int]]) -> bool:
    """Фрагмент [start, end) целиком закрыт объединением найденных."""
    position = start
    for s, e in sorted(ranges):
        if s > position:
            break
        position = max(position, e)
        if position >= end:
            return True
    return position >= end


def _overlaps(start: int, end: int, ranges: Sequence[tuple[int, int]]) -> bool:
    return any(s < end and start < e for s, e in ranges)


def _candidates(text: str) -> list[tuple[int, int]]:
    domains = load_builtin().well_known_domains
    found = [m.span() for m in _VERSION.finditer(text)] + [m.span() for m in _ERROR.finditer(text)]
    for m in _DOTTED.finditer(text):
        name = m.group().lower()
        if any(name == domain or name.endswith("." + domain) for domain in domains):
            found.append(m.span())
    return found


def evaluate(examples: Sequence[Example], predict: Predict) -> Report:
    report = Report()
    for example in examples:
        predicted = predict(example.text)
        ranges = [(start, end) for start, end, _ in predicted]
        gold = [(span.start, span.end) for span in example.spans]
        by_entity: dict[int, list[GoldSpan]] = {}
        for span in example.spans:
            by_entity.setdefault(span.entity, []).append(span)
        for mentions in by_entity.values():
            first = mentions[0]
            hidden = all(covered(m.start, m.end, ranges) for m in mentions)
            report.entities[first.type] += 1
            report.protected[first.type] += hidden
            for title, belongs, _ in CLASSES:
                if belongs(first.type, first.origin):
                    counts = report.classes.setdefault(title, [0, 0])
                    counts[0] += hidden
                    counts[1] += 1
        for start, end, type_ in predicted:
            report.found[type_] += 1
            report.correct[type_] += _overlaps(start, end, gold)
        for start, end in _candidates(example.text):
            if not _overlaps(start, end, gold):
                report.candidates += 1
                report.overmasked += _overlaps(start, end, ranges)
    return report


def recall_by_class(report: Report) -> dict[str, float]:
    return {title: hidden / total for title, (hidden, total) in report.classes.items() if total}
