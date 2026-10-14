"""Конвейер очистки: слои → объединение → сущности → очищенный текст → проверка утечек."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Protocol

from cleaner.core import leakcheck, surrogates
from cleaner.core.detect import dictionary, infra, orgs, rules, secrets
from cleaner.core.detect.base import DetectContext, Detector
from cleaner.core.detect.merge import MergedSpan, merge
from cleaner.core.entities import labels
from cleaner.core.entities.resolve import ResolvedSpan, Resolver
from cleaner.core.leakcheck import Leak
from cleaner.core.types import ChatState, EntityType, Policy, Settings, Span

DETECTORS = (rules, secrets, infra, dictionary, orgs)

# Второй проход ищет написания сущностей, найденных в этом же тексте; третий — страховка.
_MAX_PASSES = 3

# Фрагмент такого вида, задевший выданную замену, — это она сама в другой записи
# («postmaster@domain-1.example», SID с RID) или новое значение рядом с ней («petrov@domain-1.example»,
# «host-1.fabrikam.ru»). Замену второй раз не заменяют (FR-5.9), а часть вне неё скрывают.
_COMPOSED = frozenset({
    EntityType.EMAIL, EntityType.HOST, EntityType.DOMAIN, EntityType.IP,
    EntityType.MAC, EntityType.SID, EntityType.DN,
})
# Составные записи, у которых часть вне замены — самостоятельное значение: «petrov» у адреса,
# «fabrikam.ru» у имени, «OU=Servers,DC=fabrikam,DC=local» у DN. У адресов, MAC и SID такой части
# не бывает: фрагмент вокруг их замены — та же замена в другой записи.
_SPLIT = frozenset({EntityType.EMAIL, EntityType.HOST, EntityType.DOMAIN, EntityType.DN})
_SEPARATORS = ".@,=\\/:;\"' \t\r\n"
_WORD = re.compile(r"\w")
# Служебные ящики (RFC 2142) человека не выдают: «postmaster@domain-1.example» — та же подмена домена.
_ROLE_MAILBOXES = frozenset({
    "postmaster", "hostmaster", "webmaster", "abuse", "noc", "security", "info", "marketing", "sales",
    "support", "noreply", "no-reply",
})


def _piece(text: str, span: MergedSpan, start: int, end: int, ctx: DetectContext) -> MergedSpan | None:
    """Часть записи между заменами, без разделителей по краям; None — скрывать нечего."""
    while start < end and text[start] in _SEPARATORS:
        start += 1
    while end > start and text[end - 1] in _SEPARATORS:
        end -= 1
    value = text[start:end]
    if not _WORD.search(value):
        return None         # одни разделители
    if span.type is EntityType.DN:
        # Имя атрибута без значения («CN=» перед заменой) ничего не выдаёт.
        return MergedSpan(start, end, EntityType.DN, span.sources) if "=" in value else None
    if span.type is EntityType.EMAIL and "@" not in text[span.start:start]:
        if value.lower() in ctx.builtin.builtin_accounts | _ROLE_MAILBOXES:
            return None
        return MergedSpan(start, end, EntityType.ACCOUNT, span.sources)    # имя до «@»
    # Часть имени узла. Общеизвестная («example» после подмены NetBIOS-имени, «www») — не значение.
    if infra.well_known(value, ctx):
        return None
    return MergedSpan(start, end, EntityType.HOST, span.sources)           # домен из неё выделит Resolver


def _outside(
    text: str, span: MergedSpan, ranges: list[tuple[int, int]], starts: list[int], ctx: DetectContext,
) -> list[MergedSpan]:
    """Что скрыть из фрагмента: его целиком, его части вне выданных замен или ничего."""
    i = bisect.bisect_right(starts, span.start) - 1
    if i >= 0 and ranges[i][1] >= span.end:
        return []           # внутри выданной замены
    first = i if i >= 0 and ranges[i][1] > span.start else i + 1
    last = first
    while last < len(ranges) and ranges[last][0] < span.end:
        last += 1
    if first == last or span.type not in _COMPOSED:
        return [span]
    if span.type not in _SPLIT:
        return []
    pieces, position = [], span.start
    for start, end in [*ranges[first:last], (span.end, span.end)]:
        if start > position:
            piece = _piece(text, span, position, min(start, span.end), ctx)
            if piece:
                pieces.append(piece)
        position = max(position, end)
    return pieces


class SecondPass(Protocol):
    """Слой 5: по тексту, очищенному слоями 1–4, находит пропущенное; позиции — в оригинале (раздел 5.6)."""

    def find(self, text: str, sanitized: str, state: ChatState) -> list[Span]: ...


@dataclass(frozen=True)
class Layers:
    """Слои 4 и 5. По умолчанию не выполняются.

    cached — их находки, посчитанные для этого текста раньше: модели не вызываются, а находки
    проходят объединение и сопоставление заново, с текущими правилами чата.
    """

    ner: Detector | None = None
    llm: SecondPass | None = None
    cached: tuple[Span, ...] | None = None


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
    model_spans: list[Span] = field(default_factory=list)   # находки слоёв 4–5 для повторной очистки без моделей

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


def _passes(
    state: ChatState, text: str, settings: Settings,
    protected: list[tuple[int, int]], starts: list[int], extra: list[Span],
) -> list[ResolvedSpan]:
    """Шаги 5.2–5.8 до трёх раз (раздел 5.10); находки слоёв 4–5 добавляются к каждому проходу."""
    resolved: list[ResolvedSpan] = []
    for _ in range(_MAX_PASSES):
        before = _forms(state)
        ctx = _context(state, settings)
        found = [span for detector in DETECTORS for span in detector.detect(text, ctx)] + extra
        merged = [part for m in merge(text, found, ctx) for part in _outside(text, m, protected, starts, ctx)]
        resolved = Resolver(state, settings, text, ctx.builtin.generic_labels).run(text, merged)
        if _forms(state) == before:
            break
    return resolved


def sanitize(state: ChatState, text: str, settings: Settings, layers: Layers = Layers()) -> SanitizeResult:
    """Заменяет чувствительные фрагменты и обновляет state. Исключения слоёв не перехватываются (FR-3.7)."""
    protected = surrogates.find(state, text)
    notices = [Notice("surrogate_in_input", start, end) for start, end in protected]
    for m in labels.SHAPE.finditer(text):
        if m.group() not in state.surrogates:
            state.foreign_labels.add(m.group())
            notices.append(Notice("foreign_label", m.start(), m.end()))
            protected.append(m.span())
    protected.sort()
    starts = [start for start, _ in protected]
    if layers.cached is not None:
        extra = list(layers.cached)
    else:
        extra = layers.ner.detect(text, _context(state, settings)) if layers.ner is not None else []
    resolved = _passes(state, text, settings, protected, starts, extra)
    if layers.cached is None and layers.llm is not None:
        # Слой 5 — один раз, по тексту, который уже очистили слои 1–4; затем проходы повторяются с его находками.
        found = layers.llm.find(text, _apply(text, resolved), state)
        if found:
            extra = extra + found
            resolved = _passes(state, text, settings, protected, starts, extra)
    sanitized = _apply(text, resolved)
    blocked = [
        span for span in resolved
        if settings.policies.get(state.entities[span.entity_id].type) is Policy.BLOCK
    ]
    return SanitizeResult(
        sanitized, resolved, notices, leakcheck.check(sanitized, state, settings), blocked, extra,
    )
