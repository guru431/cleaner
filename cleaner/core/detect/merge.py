"""Объединение фрагментов разных слоёв."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cleaner.core.detect.base import DetectContext
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
    for group in groups:
        start, end = group[0].start, max(s.end for s in group)
        sources = tuple(dict.fromkeys(s.source for s in group))
        value = text[start:end].lower()
        # Списки исключений действуют только на точное значение и не отменяют решение пользователя.
        if "manual" not in sources and (value in ctx.settings.never or value in ctx.unmask):
            continue
        senior = min(group, key=lambda s: (_rank(s), s.start - s.end))
        merged.append(MergedSpan(start, end, senior.type, sources))
    return merged
