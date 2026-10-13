"""Конвейер очистки: слои → объединение → сущности → очищенный текст → проверка утечек."""
from __future__ import annotations

from dataclasses import dataclass, field

from cleaner.core import leakcheck, surrogates
from cleaner.core.detect import dictionary, infra, rules, secrets
from cleaner.core.detect.base import DetectContext
from cleaner.core.detect.merge import merge
from cleaner.core.entities import labels
from cleaner.core.entities.resolve import ResolvedSpan, Resolver
from cleaner.core.leakcheck import Leak
from cleaner.core.types import ChatState, Policy, Settings

DETECTORS = (rules, secrets, infra, dictionary)

# Второй проход ищет написания сущностей, найденных в этом же тексте; третий — страховка.
_MAX_PASSES = 3


@dataclass(frozen=True)
class Notice:
    code: str       # surrogate_in_input | foreign_label
    start: int
    end: int


@dataclass
class SanitizeResult:
    sanitized: str
    spans: list[ResolvedSpan]
    notices: list[Notice] = field(default_factory=list)
    leaks: list[Leak] = field(default_factory=list)
    blocked: list[ResolvedSpan] = field(default_factory=list)

    @property
    def deliverable(self) -> bool:
        """Можно ли выдавать очищенный текст пользователю и отправлять его дальше."""
        return not self.leaks and not self.blocked


def _context(state: ChatState, settings: Settings) -> DetectContext:
    return DetectContext(
        settings=settings,
        known=tuple((form, e.type) for e in state.entities.values() for form in e.forms),
        manual=tuple((r.value, r.type) for r in state.rules if r.action == "mask" and r.type is not None),
        unmask=frozenset(r.value.lower() for r in state.rules if r.action == "unmask"),
    )


def _forms(state: ChatState) -> set[str]:
    return {form.lower() for entity in state.entities.values() for form in entity.forms}


def _apply(text: str, spans: list[ResolvedSpan]) -> str:
    pieces, position = [], 0
    for span in spans:
        pieces += [text[position:span.start], span.surrogate]
        position = span.end
    pieces.append(text[position:])
    return "".join(pieces)


def sanitize(state: ChatState, text: str, settings: Settings) -> SanitizeResult:
    """Заменяет чувствительные фрагменты и обновляет state. Исключения слоёв не перехватываются."""
    protected = surrogates.find(state, text)
    notices = [Notice("surrogate_in_input", start, end) for start, end in protected]
    for m in labels.SHAPE.finditer(text):
        if m.group() not in state.surrogates:
            state.foreign_labels.add(m.group())
            notices.append(Notice("foreign_label", m.start(), m.end()))
            protected.append(m.span())
    resolved: list[ResolvedSpan] = []
    for _ in range(_MAX_PASSES):
        before = _forms(state)
        ctx = _context(state, settings)
        found = [span for detector in DETECTORS for span in detector.detect(text, ctx)]
        merged = [
            m for m in merge(text, found, ctx)
            if not any(start <= m.start and m.end <= end for start, end in protected)
        ]
        resolved = Resolver(state, settings, text, ctx.builtin.generic_labels).run(text, merged)
        if _forms(state) == before:
            break
    sanitized = _apply(text, resolved)
    blocked = [
        span for span in resolved
        if settings.policies.get(state.entities[span.entity_id].type) is Policy.BLOCK
    ]
    return SanitizeResult(sanitized, resolved, notices, leakcheck.check(sanitized, state, settings), blocked)
