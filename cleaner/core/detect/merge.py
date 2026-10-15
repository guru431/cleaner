"""Объединение фрагментов разных слоёв."""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from cleaner.core.detect.base import DetectContext
from cleaner.core.entities import hostmap, netmap
from cleaner.core.types import EntityType, Policy, Span


@dataclass(frozen=True)
class MergedSpan:
    start: int
    end: int
    type: EntityType
    sources: tuple[str, ...]


def _rank(span: Span) -> int:
    """Старшинство типа при пересечении: чем меньше, тем старше (FR-3.3)."""
    if span.source == "manual":
        return 0
    if span.type is EntityType.SECRET:
        return 1
    if span.validated:
        return 2
    if span.source == "ner":
        return 4
    if span.source == "llm":
        return 5
    return 3


# Шаг 3 (раздел 5.7): части имени рядом — фамилия, имя, отчество, инициалы — один PERSON.
_NAME_GAP = re.compile(r"[ \t]+")
_INITIAL_GAP = re.compile(r"\.[ \t]*")
_LONE_LETTER = re.compile(r"(?<![^\W\d_])[^\W\d_]$")
_INITIALS_AFTER = re.compile(r"[ \t]+([А-ЯЁA-Z]\.(?:[ \t]?[А-ЯЁA-Z]\.)?)")
_INITIALS_BEFORE = re.compile(r"(?<![^\W\d_])([А-ЯЁA-Z]\.(?:[ \t]?[А-ЯЁA-Z]\.)?)[ \t]*$")


def _adjacent(text: str, previous: MergedSpan, span: MergedSpan) -> bool:
    """Между частями — только пробелы; «точка с пробелом» — только после инициала («И. Иванов»), а не в конце предложения."""
    gap = text[previous.end:span.start]
    if not gap or _NAME_GAP.fullmatch(gap):
        return True
    return bool(_INITIAL_GAP.fullmatch(gap)) and _LONE_LETTER.search(text, previous.start, previous.end) is not None


def _with_initials(text: str, span: MergedSpan, floor: int, ceiling: int) -> MergedSpan:
    """Инициалы перед именем и после него — часть упоминания; соседние фрагменты не задеваются."""
    start, end = span.start, span.end
    after = _INITIALS_AFTER.match(text, end, ceiling)
    if after:
        end = after.end(1)
    before = _INITIALS_BEFORE.search(text, floor, start)
    if before:
        start = before.start(1)
    return MergedSpan(start, end, span.type, span.sources)


def _join_names(text: str, spans: list[MergedSpan]) -> list[MergedSpan]:
    out: list[MergedSpan] = []
    for index, span in enumerate(spans):
        if span.type is EntityType.PERSON:
            ceiling = spans[index + 1].start if index + 1 < len(spans) else len(text)
            span = _with_initials(text, span, out[-1].end if out else 0, ceiling)
            previous = out[-1] if out else None
            if previous is not None and previous.type is EntityType.PERSON and _adjacent(text, previous, span):
                sources = tuple(dict.fromkeys(previous.sources + span.sources))
                out[-1] = MergedSpan(previous.start, span.end, EntityType.PERSON, sources)
                continue
        out.append(span)
    return out


_DOTTED_NAME = re.compile(r"[\w-]+(?:\.[\w-]+)+")
_NAME_TYPES = (EntityType.HOST, EntityType.DOMAIN)


def _name_kept(text: str, group: list[Span], start: int, end: int) -> EntityType | None:
    """Тип имени узла или домена, если правила пользователя в нём легли на целые части (раздел 6.4: каждая часть
    слева и домен). Такое правило имя не поглощает: часть получит его тип при подмене (resolve._name)."""
    name = next((
        s for s in group if s.source != "manual" and s.type in _NAME_TYPES and (s.start, s.end) == (start, end)
    ), None)
    if name is None or not _DOTTED_NAME.fullmatch(text, start, end):
        return None
    left, registrable = hostmap.parts(text[start:end])
    edges, position = {(end - len(registrable), end)}, start
    for label in left:
        edges.add((position, position + len(label)))
        position += len(label) + 1
    return name.type if all((s.start, s.end) in edges for s in group if s.source == "manual") else None


def merge(text: str, spans: Iterable[Span], ctx: DetectContext) -> list[MergedSpan]:
    policies = ctx.settings.policies
    active = sorted(
        (s for s in spans if s.end > s.start and policies.get(s.type, Policy.MASK) is not Policy.OFF),
        key=lambda s: (s.start, -s.end),
    )
    groups: list[list[Span]] = []
    reach = -1
    for span in active:
        if groups and span.start < reach:
            groups[-1].append(span)
            reach = max(reach, span.end)
        else:
            groups.append([span])
            reach = span.end
    merged: list[MergedSpan] = []
    opened: set[str] | None = None      # адреса списков исключений в каноническом виде — при первом адресе текста
    for group in groups:
        start, end = group[0].start, max(s.end for s in group)
        sources = tuple(dict.fromkeys(s.source for s in group))
        value = text[start:end].lower()
        senior = min(group, key=lambda s: (_rank(s), s.start - s.end))
        # Списки исключений действуют только на точное значение и не отменяют решение пользователя. Адрес — то же
        # значение в любой записи: «2a00:1450:4010::65» в тексте и «2a00:1450:4010:0:0:0:0:65» в списке, «10.1.2.5» и
        # «010.001.002.005», «10.1.2.0» и «10.1.2.0/24» (длину /24 и больше слой 3 во фрагмент не берёт).
        if "manual" not in sources:
            if value in ctx.settings.never or value in ctx.unmask:
                continue
            if senior.type is EntityType.IP:
                if opened is None:
                    opened = netmap.addresses(ctx.settings.never | ctx.unmask)
                if netmap.canonical_forms(value) & opened:
                    continue
        type_ = (senior.source == "manual" and _name_kept(text, group, start, end)) or senior.type
        merged.append(MergedSpan(start, end, type_, sources))
    return _join_names(text, merged)
