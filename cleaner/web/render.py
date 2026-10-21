"""Готовый HTML текстов с выделением. Единственное место, где разметка собирается из строк; содержимое экранируется."""
from __future__ import annotations

import bisect
from collections import Counter

from markupsafe import Markup, escape

from cleaner.core.leakcheck import Leak
from cleaner.core.match import find_forms
from cleaner.core.restore import Segment
from cleaner.core.types import ChatState
from cleaner.core.types import EntityType as T
from cleaner.storage.repo import Item

TYPE_NAMES = {
    T.PERSON: "Человек", T.ORG: "Организация", T.ADDRESS: "Адрес", T.EMAIL: "Почта", T.PHONE: "Телефон",
    T.BIRTHDATE: "Дата рождения", T.PASSPORT: "Паспорт", T.INN: "ИНН", T.SNILS: "СНИЛС", T.OGRN: "ОГРН",
    T.KPP: "КПП", T.OMS: "Полис ОМС", T.CARD: "Карта", T.BANK_ACCOUNT: "Банковский счёт", T.SECRET: "Секрет",
    T.ACCOUNT: "Учётная запись", T.IP: "IP-адрес", T.MAC: "MAC-адрес", T.HOST: "Узел", T.DOMAIN: "Домен",
    T.SID: "SID", T.DN: "DN", T.TERM: "Термин",
}

SEGMENT_NAMES = {
    "restored": "восстановлено",
    "altered": "восстановлено из искажённой записи",
    "derived": "выведено",
    "unknown": "неизвестная метка",
    "kept_by_policy": "не восстанавливается по политике",
    "foreign_link": "посторонняя ссылка",
}

# Кто нашёл фрагмент (spans[*].sources) — в порядке слоёв; так их называют экран проверки и его фильтры.
SOURCE_NAMES = {
    "manual": "вручную — решение пользователя в этом чате",
    "rules": "слой 1 — правила",
    "secrets": "слой 2 — секреты",
    "infra": "слой 3 — инфраструктура",
    "dict": "слой 3 — словарь организации, шаблоны, известные значения чата",
    "ner": "слой 4 — модели распознавания имён",
    "llm": "слой 5 — локальная модель",
}

Mark = tuple[int, int, dict[str, str]]     # начало, конец, атрибуты <mark>; имена атрибутов — только из этого модуля


def highlight(text: str, marks: list[Mark]) -> Markup:
    """Текст с участками <mark>. Участок, задевший предыдущий, пропускается: текст не теряется и не дублируется."""
    pieces: list[Markup] = []
    position = 0
    for start, end, attrs in sorted(marks, key=lambda mark: (mark[0], -mark[1])):
        if start < position or end <= start:
            continue
        rendered = "".join(f' {name}="{escape(value)}"' for name, value in attrs.items())
        pieces += [escape(text[position:start]), Markup(f"<mark{rendered}>"), escape(text[start:end]), Markup("</mark>")]
        position = end
    pieces.append(escape(text[position:]))
    return Markup("").join(pieces)


def _entity_mark(start: int, end: int, span: dict, state: ChatState, blocked: frozenset[str] = frozenset()) -> Mark:
    entity = state.entities.get(span["entity_id"])
    code = entity.type.value if entity else "X"
    name = TYPE_NAMES[entity.type] if entity else "?"
    classes = f"t-{code}" + (" blocked" if span["entity_id"] in blocked else "")
    return start, end, {"class": classes, "data-entity": span["entity_id"], "title": f"{name}: {span['surrogate']}"}


def original_marks(item: Item, state: ChatState) -> list[Mark]:
    """Заменённые фрагменты оригинала: цвет по типу, id сущности для парной подсветки (FR-6.1)."""
    return [_entity_mark(span["start"], span["end"], span, state) for span in item.spans]


def sanitized_marks(
    item: Item, state: ChatState, leaks: list[Leak], blocked: frozenset[str] = frozenset()
) -> list[Mark]:
    """Те же фрагменты в очищенном тексте (со сдвигом на разницу длин) и оригиналы, найденные проверкой утечек."""
    marks: list[Mark] = []
    shift = 0
    for span in sorted(item.spans, key=lambda s: s["start"]):
        start = span["start"] + shift
        marks.append(_entity_mark(start, start + len(span["surrogate"]), span, state, blocked))
        shift += len(span["surrogate"]) - (span["end"] - span["start"])
    marks += [(leak.start, leak.end, {"class": "leak", "title": "Оригинал в очищенном тексте"}) for leak in leaks]
    return marks


OPENED = "Открыто по решению пользователя"


def opened_marks(text: str, state: ChatState, marks: list[Mark]) -> list[Mark]:
    """Значения, с которых пользователь снял замену (правила unmask чата): без метки их видно только по счётчику. Поиск
    — как у проверки утечек (целыми словами); вхождение, которое задевает другую метку панели (часть замены
    «domain-1.example» при открытом «domain»), не выделяется — иначе highlight пропустил бы ту метку. В атрибутах —
    только подпись, без значения."""
    values = {rule.value for rule in state.rules if rule.action == "unmask"}
    if not values:
        return []
    taken = sorted((start, end) for start, end, _ in marks)
    starts, reach = [start for start, _ in taken], []
    for _, end in taken:
        reach.append(max(end, reach[-1]) if reach else end)        # самый дальний конец меток, начатых не позже
    result: list[Mark] = []
    for start, end, _ in find_forms(text, [(value, "letters", None) for value in values]):
        i = bisect.bisect_left(starts, end) - 1
        if i < 0 or reach[i] <= start:
            result.append((start, end, {"class": "opened", "title": OPENED}))
    return result


def leak_marks(leaks: list[Leak]) -> list[Mark]:
    """Оригиналы, найденные проверкой утечек в исходящем тексте (FR-8.7)."""
    return [(leak.start, leak.end, {"class": "leak", "title": "Оригинал в исходящем тексте"}) for leak in leaks]


def restored_marks(segments: list[Segment]) -> list[Mark]:
    return [(s.start, s.end, {"class": f"r-{s.kind}", "title": SEGMENT_NAMES.get(s.kind, s.kind)}) for s in segments]


def surrogates_by_entity(state: ChatState) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for text, surrogate in state.surrogates.items():
        result.setdefault(surrogate.entity_id, []).append(text)
    return result


def summary(item: Item, state: ChatState) -> list[tuple[str, int]]:
    """Число замен по типам (FR-6.7), самые частые первыми."""
    counts = Counter(state.entities[s["entity_id"]].type for s in item.spans if s["entity_id"] in state.entities)
    ordered = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0].value))
    return [(TYPE_NAMES[type_], count) for type_, count in ordered]
