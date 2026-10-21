"""Конвейер очистки: слои → объединение → сущности → очищенный текст → проверка утечек.
Здесь же — сборка исходящего запроса к облачной модели (раздел 10.1)."""
from __future__ import annotations

import bisect
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from types import ModuleType
from typing import Protocol

from cleaner.core import leakcheck, restore, surrogates
from cleaner.core.detect import dictionary, infra, ner, orgs, rules, secrets
from cleaner.core.detect.base import DetectContext, Detector
from cleaner.core.detect.merge import MergedSpan, merge
from cleaner.core.entities import hostmap, labels, netmap, ops
from cleaner.core.entities.resolve import ResolvedSpan, Resolver, name_parts
from cleaner.core.leakcheck import Leak
from cleaner.core.match import normalize
from cleaner.core.types import STRICTNESS, ChatState, EntityType, Policy, Settings, Span

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
_SEPARATOR = re.compile(r"\\{0,2}\.")           # точка между частями имени: и «\.», и «\\.» (hostmap.dotted)
_SEPARATOR_BEFORE = re.compile(r"\\{0,2}\.$")
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
    ruled = [type_ for ruled_start, ruled_end, type_ in span.ruled if start < ruled_end and ruled_start < end]
    if ruled:       # часть, которую задело правило пользователя, — тип правила (из нескольких — со строже политикой)
        policies = ctx.settings.policies
        return MergedSpan(start, end, max(ruled, key=lambda t: STRICTNESS.get(policies.get(t), 0)), span.sources)
    if span.type is EntityType.DN:
        # Имя атрибута без значения («CN=» перед заменой) ничего не выдаёт.
        return MergedSpan(start, end, EntityType.DN, span.sources) if "=" in value else None
    if (span.type is EntityType.EMAIL or span.mail) and "@" not in text[span.start:start]:
        if value.lower() in ctx.builtin.builtin_accounts | _ROLE_MAILBOXES:
            return None
        return MergedSpan(start, end, EntityType.ACCOUNT, span.sources)    # имя до «@»
    # Часть имени узла. Общеизвестная («example» после подмены NetBIOS-имени, «www») — не значение.
    if infra.well_known(value, ctx):
        return None
    return MergedSpan(start, end, EntityType.HOST, span.sources)           # домен из неё выделит Resolver


def _types(text: str, piece: MergedSpan, ctx: DetectContext) -> list[EntityType]:
    """Типы, которые часть записи получит при подмене (resolve._name): часть имени узла — HOST у частей слева от домена и
    DOMAIN у домена в ней, а часть, которой пользователь дал другой тип (правило чата), — тип правила, если его политика
    не мягче (resolve._manual)."""
    if piece.type is not EntityType.HOST:
        return [piece.type]
    left, registrable = name_parts(hostmap.dotted(text[piece.start:piece.end]), piece.precedes)
    retyped = {
        normalize(value): type_ for value, type_, _ in ctx.manual
        if type_ is not None and type_ not in (EntityType.HOST, EntityType.DOMAIN)
    }
    policies = ctx.settings.policies

    def typed(part: str, own: EntityType) -> EntityType:
        """Тип правила мягче своего часть не получает (resolve._manual)."""
        rule = retyped.get(normalize(part))
        return rule if rule and STRICTNESS.get(policies.get(rule), 0) >= STRICTNESS.get(policies.get(own), 0) else own

    return [typed(part, EntityType.HOST) for part in left] + (
        [typed(registrable, EntityType.DOMAIN)] if registrable else []
    )


def _split_holds(text: str, pieces: list[MergedSpan], ctx: DetectContext) -> bool:
    """Держат ли части адреса e-mail его политику: каждая не мягче EMAIL или одна и так блокирует выдачу («блокировать»
    строже «скрывать без восстановления»). Часть, которой пользователь дал тип строже адреса, — часть правила (merge)."""
    policies = ctx.settings.policies
    strictness = [STRICTNESS.get(policies.get(type_), 0) for piece in pieces for type_ in _types(text, piece, ctx)]
    own = STRICTNESS.get(policies.get(EntityType.EMAIL), 0)
    return min(strictness) >= own or max(strictness) == STRICTNESS[Policy.BLOCK]


def _outside(
    text: str, span: MergedSpan, ranges: list[tuple[int, int]], starts: list[int], ctx: DetectContext,
    originals: Callable[[str], str],
) -> list[MergedSpan]:
    """Что скрыть из фрагмента: его целиком, его части вне выданных замен или ничего."""
    i = bisect.bisect_right(starts, span.start) - 1
    if i >= 0 and ranges[i][1] >= span.end:
        return []           # внутри выданной замены
    first = i if i >= 0 and ranges[i][1] > span.start else i + 1
    last = first
    while last < len(ranges) and ranges[last][0] < span.end:
        last += 1
    if first == last and not span.parted:      # адрес с частью строже себя делится и без замены рядом (merge)
        return _placed(text, span, ranges, starts, ctx)
    if span.type not in _COMPOSED and not span.ruled:
        return [span]
    if span.type not in _SPLIT and not span.ruled:
        return []
    bounds = ranges[first:last]
    at = text.find("@", span.start, span.end) if span.type is EntityType.EMAIL or span.mail else -1
    if at >= 0:
        bounds = sorted([*bounds, (at, at + 1)])        # имя входа и имя узла — разные части, и рядом с заменой
    pieces, position = [], span.start
    for start, end in [*bounds, (span.end, span.end)]:
        if start > position:
            piece = _piece(text, span, position, min(start, span.end), ctx)
            if piece:
                pieces += _placed(text, piece, ranges, starts, ctx)
        position = max(position, end)
    if at >= 0 and pieces and not _split_holds(text, pieces, ctx):
        # Адрес строже своих частей не делится (5.10): метки частей восстанавливали бы его при EMAIL «скрывать без
        # восстановления» и не блокировали бы выдачу при «блокировать». Значение метки — адрес с оригиналами замен:
        # «petrov@domain-1.example» — это petrov@contoso.ru, и подмена в значении восстанавливалась бы подменой.
        return [replace(span, value=originals(text[span.start:span.end]))]
    return pieces


def _placed(
    text: str, span: MergedSpan, ranges: list[tuple[int, int]], starts: list[int], ctx: DetectContext,
) -> list[MergedSpan]:
    """Имя, которое стоит через точку после выданной замены или метки или перед ней, — часть имени (5.10): части перед
    заменой — части слева от домена, часть после неё — не первая, и отдельным написанием (5.4) она не становится.
    Одни служебные части перед заменой («www.mail.<TERM_1>…») не скрываются, как и «www» сам по себе. Точка бывает и
    «\\.» или «\\\\.» (имя в регулярном выражении, в том числе в строке JSON)."""
    if span.type not in (EntityType.HOST, EntityType.DOMAIN):
        return [span]
    separator = _SEPARATOR.match(text, span.end)
    gap = separator.end() - span.end if separator else 0
    after = bisect.bisect_left(starts, span.end + gap)
    precedes = gap > 0 and after < len(starts) and starts[after] == span.end + gap
    separator = _SEPARATOR_BEFORE.search(text, max(0, span.start - 3), span.start)
    lead = span.start - separator.start() if separator else 0
    before = bisect.bisect_right(starts, span.start - lead - 1) - 1     # замена, которая кончается перед точкой
    follows = lead > 0 and before >= 0 and ranges[before][1] == span.start - lead
    if not (follows or precedes):
        return [span]
    labels_ = hostmap.dotted(text[span.start:span.end].lower()).split(".")
    if (precedes or len(labels_) == 1) and all(label in ctx.builtin.generic_labels for label in labels_):
        return []
    return [replace(span, follows=follows, precedes=precedes)]


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
    held: tuple[EntityType, ...] = ()       # у выданной замены — типы её сущностей (_pasted)


@dataclass
class SanitizeResult:
    sanitized: str
    spans: list[ResolvedSpan]
    notices: list[Notice] = field(default_factory=list)
    leaks: list[Leak] = field(default_factory=list)
    blocked: list[ResolvedSpan] = field(default_factory=list)
    model_spans: list[Span] = field(default_factory=list)   # находки слоёв 4–5 для повторной очистки без моделей
    blocked_surrogates: list[Notice] = field(default_factory=list)  # вставленные замены сущностей с «блокировать»

    @property
    def deliverable(self) -> bool:
        """Можно ли выдавать очищенный текст пользователю и отправлять его дальше."""
        return not self.leaks and not self.blocked and not self.blocked_surrogates


def _context(state: ChatState, settings: Settings) -> DetectContext:
    return DetectContext(
        settings=settings,
        known=tuple((form, e.type) for e in state.entities.values() for form in e.forms),
        manual=tuple((r.value, r.type, r.bounds) for r in state.rules if r.action == "mask" and r.type is not None),
        unmask=ops.unmasked(state),
        issued_domains=frozenset(fake.lower() for slot, fake in state.issued.items() if slot.endswith("|dns"))
        | {label.lower() for label in labels.domain_labels(state)},
        issued_names=frozenset(fake.lower() for slot, fake in state.issued.items() if slot.endswith("|name")),
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
    protected: list[tuple[int, int]], starts: list[int], extra: list[Span], detectors: tuple[ModuleType, ...],
) -> tuple[list[ResolvedSpan], list[Span]]:
    """Шаги 5.2–5.8 до трёх раз (раздел 5.10); находки слоёв 4–5 добавляются к каждому проходу. Возвращает и находки
    последнего прохода — по ним _held."""
    resolved: list[ResolvedSpan] = []
    found: list[Span] = []
    originals = restore.originals(state, settings)
    for _ in range(_MAX_PASSES):
        before = _forms(state)
        ctx = _context(state, settings)
        found = [span for detector in detectors for span in detector.detect(text, ctx)] + extra
        merged = [
            part for m in merge(text, found, ctx) for part in _outside(text, m, protected, starts, ctx, originals)
        ]
        resolved = Resolver(state, settings, text, ctx.builtin.generic_labels).run(text, merged)
        if _forms(state) == before:
            break
    return resolved, found


def _held(
    text: str, resolved: list[ResolvedSpan], found: list[Span], state: ChatState, settings: Settings,
) -> list[ResolvedSpan]:
    """Типы автоматических находок, которые фрагмент скрыл под меткой другого типа: телефон внутри более длинного пароля,
    выделение «+79161234567 доб» с типом TERM, известный домен внутри адреса e-mail. Тип фрагмента они не меняют —
    находка покрывает лишь часть значения, и её тип был бы неверен для всего (5.7, шаг 4), — но их «блокировать» держит
    выдачу, пока значение скрыто в тексте (FR-4.2). Записываются типы, а не решение: блокировка — по политике на момент
    проверки (очистка, экран чата, сборка запроса), и смена политики повторной очистки не требует. Открытое значение
    (FR-3.6, FR-6.2) не держит ничего, как и вне фрагмента; правило пользователя — не находка. Находки одного типа
    сливаются, и каждый фрагмент проходится один раз на интервал слияния: время линейно."""
    policies = settings.policies
    opened = ops.open_values(state, settings)
    longest = max(map(len, opened), default=0)
    addresses: set[str] | None = None
    intervals: dict[EntityType, list[tuple[int, int]]] = {}
    for span in found:
        if span.source == "manual" or span.end <= span.start or policies.get(span.type, Policy.MASK) is Policy.OFF:
            continue
        # Как в merge: имя через «\.» — то же имя, адрес — в любой записи. Длиннее открытых значений — не открытое
        # (написание длиной в текст не сравнивается).
        if span.type is EntityType.IP and opened:
            if addresses is None:
                addresses = netmap.addresses(opened)
            if netmap.canonical_forms(text[span.start:span.end].lower()) & addresses:
                continue
        elif span.end - span.start <= longest:
            value = text[span.start:span.end].lower()
            if (hostmap.dotted(value) if span.type in (EntityType.HOST, EntityType.DOMAIN) else value) in opened:
                continue
        intervals.setdefault(span.type, []).append((span.start, span.end))
    if not intervals or not resolved:
        return resolved
    ends = [span.end for span in resolved]
    held: list[list[EntityType]] = [[] for _ in resolved]
    for type_, pieces in intervals.items():
        pieces.sort()
        start, end = pieces[0]
        for next_start, next_end in [*pieces[1:], (len(text) + 1, len(text) + 1)]:
            if next_start < end:
                end = max(end, next_end)
                continue
            i = bisect.bisect_right(ends, start)
            while i < len(resolved) and resolved[i].start < end:
                if not held[i] or held[i][-1] is not type_:
                    held[i].append(type_)
                i += 1
            start, end = next_start, next_end
    out = []
    for span, types in zip(resolved, held):
        own = state.entities[span.entity_id].type
        types = [type_ for type_ in types if type_ is not own]
        out.append(replace(span, held=tuple(types)) if types else span)
    return out


def _pasted(state: ChatState, settings: Settings, hits: list[surrogates.Hit]) -> list[tuple[EntityType, ...]]:
    """Типы сущностей выданных замен этого чата, вставленных в текст (FR-5.9): замена сущности с политикой «блокировать»
    блокирует выдачу, как её оригинал (FR-4.2), — по политике на момент проверки; у имени узла — и замены его частей.
    Сущность, значение которой открыто (правило «открыть», список «никогда не скрывать»), — нет: открытый оригинал выдачу
    тоже не блокирует, и иначе вставленную замену было бы нечем снять."""
    if not hits:
        return []
    opened = ops.open_values(state, settings)
    by_entity: dict[str, EntityType | None] = {}
    by_key: dict[str, tuple[EntityType, ...]] = {}

    def own(entity_id: str) -> EntityType | None:
        if entity_id not in by_entity:
            entity = state.entities.get(entity_id)
            by_entity[entity_id] = None if entity is None or entity.restore_value.lower() in opened or any(
                form.lower() in opened for form in entity.forms
            ) else entity.type
        return by_entity[entity_id]

    for hit in hits:
        if hit.key not in by_key:
            by_key[hit.key] = tuple(dict.fromkeys(
                type_ for type_ in map(own, surrogates.owners(state, hit.key)) if type_ is not None
            ))
    return [by_key[hit.key] for hit in hits]


def sanitize(
    state: ChatState, text: str, settings: Settings, layers: Layers = Layers(),
    detectors: tuple[ModuleType, ...] = DETECTORS,
) -> SanitizeResult:
    """Заменяет чувствительные фрагменты и обновляет state. Исключения слоёв не перехватываются (FR-3.7).
    detectors — слои 1–3; у ответа модели в исходящем запросе — только известные значения (FR-8.11)."""
    hits = surrogates.Finder(state, loose=True).finditer(text)
    protected = [hit.span() for hit in hits]
    notices = [
        Notice("surrogate_in_input", hit.start(), hit.end(), held) for hit, held in zip(hits, _pasted(state, settings, hits))
    ]
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
        if layers.llm is not None:
            # Пароль, который слой 4 принял за имя («sunflower77» → <PERSON_1>), остаётся слою 5: он видит текст,
            # уже очищенный слоями 1–4, и иначе не может дать ему тип SECRET. Без слоя 5 находка остаётся: отбросить её —
            # открыть сам пароль (на pii_benchmark так открылись бы почта и номер полиса, записанные с пробелами и словами).
            extra = [span for span in extra if not ner.identifier(text, span)]
    resolved, found = _passes(state, text, settings, protected, starts, extra, detectors)
    if layers.cached is None and layers.llm is not None:
        # Слой 5 — один раз, по тексту, который уже очистили слои 1–4; затем проходы повторяются с его находками.
        second = layers.llm.find(text, _apply(text, resolved), state)
        if second:
            extra = extra + second
            resolved, found = _passes(state, text, settings, protected, starts, extra, detectors)
    resolved = _held(text, resolved, found, state, settings)
    sanitized = _apply(text, resolved)
    policies = settings.policies
    blocked = [
        span for span in resolved
        if Policy.BLOCK in (policies.get(state.entities[span.entity_id].type), *map(policies.get, span.held))
    ]
    blocked_surrogates = [notice for notice in notices if Policy.BLOCK in map(policies.get, notice.held)]
    return SanitizeResult(
        sanitized, resolved, notices, leakcheck.check(sanitized, state, settings), blocked, extra, blocked_surrogates,
    )


# --- исходящий запрос к облачной модели (раздел 10) ---------------------------------------

@dataclass(frozen=True)
class Turn:
    """Ход чата: user — входной текст, system — инструкция пользователя для модели, assistant — ответ
    модели, как он получен. Текст — оригинал; cached — находки слоёв 4–5 этого текста."""

    role: str
    text: str
    cached: tuple[Span, ...] = ()


@dataclass(frozen=True)
class OutMessage:
    role: str       # user | assistant
    text: str


@dataclass(frozen=True)
class OutgoingContext:
    """Всё, что уходит провайдеру. Создаётся только в этом модуле (SEC-1): у egress другого входа нет."""

    chat_id: str
    provider_id: str
    model: str
    system: str
    messages: tuple[OutMessage, ...]

    def texts(self) -> list[str]:
        return [self.system, *(message.text for message in self.messages)]

    def digest(self) -> str:
        """Отпечаток показанного на экране подтверждения: отправляется только он (FR-8.4)."""
        payload = [self.provider_id, self.model, self.system, [[m.role, m.text] for m in self.messages]]
        return hashlib.sha256(json.dumps(payload, ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass
class Outgoing:
    context: OutgoingContext
    leaks: list[tuple[int, Leak]]       # номер сообщения и находка; -1 — системная часть
    blocked: int                        # фрагменты типов с политикой «блокировать»
    skipped: list[int]                  # номера ходов, не вошедших в запрос

    @property
    def sendable(self) -> bool:
        return not self.leaks and not self.blocked


class NotSendable(ValueError):
    """Запрос не собрать; текст можно показать пользователю."""


def system_prompt(label_style: str) -> str:
    """Служебная инструкция раздела 10.2. Восстановление на её соблюдение не полагается."""
    person, email = (labels.format_label(label_style, type_, number) for type_, number in ((EntityType.PERSON, 1), (EntityType.EMAIL, 2)))
    return (
        f"В тексте встречаются обозначения вида {person}, {email}, а также условные адреса и имена узлов. "
        "Это непрозрачные идентификаторы, заменяющие скрытые данные. Переписывай их посимвольно: "
        "не переводи, не склоняй, не изменяй и не придумывай новых.\n"
        f"The text contains placeholders such as {person} or {email}, and stand-in addresses and host names. "
        "They are opaque identifiers for hidden data. Copy them character for character: do not translate, "
        "inflect, change or invent new ones."
    )


def build_outgoing(
    state: ChatState, turns: list[Turn], settings: Settings, provider_id: str, model: str,
) -> Outgoing:
    """Запрос собирается заново при каждой отправке (раздел 10.1) и меняет state, как очистка.

    Входные тексты и инструкции очищаются с текущими правилами чата и сохранёнными находками слоёв 4–5;
    в ответах модели заменяются известные значения (FR-8.11). Соседние ходы одной роли склеиваются:
    Anthropic требует чередования. Ответы до первого вопроса пропускаются — первым идёт вопрос.
    """
    dialogue = [turn.role for turn in turns if turn.role != "system"]      # инструкция — не ход диалога
    if not dialogue or dialogue[-1] != "user":
        raise NotSendable("Последним в чате должен быть вопрос: вставьте текст и дождитесь очистки")
    system = [system_prompt(state.label_style)]
    messages: list[list[str]] = []
    blocked = 0
    skipped = []
    for number, turn in enumerate(turns):
        if turn.role == "assistant":
            if not messages:
                skipped.append(number)
                continue
            result = sanitize(state, turn.text, settings, detectors=(dictionary,))
        else:
            result = sanitize(state, turn.text, settings, Layers(cached=turn.cached))
            # Замена заблокированной сущности, вставленная пользователем, держит отправку, как оригинал (FR-4.2). В ответе
            # модели — нет, последовательно с тем, что в нём ищется (FR-8.11): только оригиналы, в том числе скрытые внутри
            # другой метки (_held). Замена в ответе — эхо того, что облаку уже отправили; сущность замены пришла из
            # входного текста этого чата, и он, пока значение в нём не открыто, блокирует отправку сам.
            blocked += len(result.blocked_surrogates)
        blocked += len(result.blocked)
        if turn.role == "system":
            system.append(result.sanitized)
        elif messages and messages[-1][0] == turn.role:
            messages[-1][1] += "\n\n" + result.sanitized
        else:
            messages.append([turn.role, result.sanitized])
    context = OutgoingContext(
        state.chat_id, provider_id, model, "\n\n".join(system),
        tuple(OutMessage(role, text) for role, text in messages),
    )
    # Утечки — по итоговым текстам: проверяется ровно то, что уйдёт (SEC-2).
    leaks = [(-1, leak) for leak in leakcheck.check(context.system, state, settings)]
    leaks += [
        (number, leak) for number, message in enumerate(context.messages)
        for leak in leakcheck.check(message.text, state, settings)
    ]
    return Outgoing(context, leaks, blocked, skipped)


def probe_context(provider_id: str, model: str) -> OutgoingContext:
    """Проверка подключения (FR-8.2): постоянный текст, без данных пользователя."""
    return OutgoingContext("", provider_id, model, "", (OutMessage("user", "Ответь одним словом: готово"),))
