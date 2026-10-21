"""Объединение фрагментов разных слоёв."""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace

from cleaner.core.detect.base import DetectContext
from cleaner.core.entities import hostmap, netmap
from cleaner.core.types import STRICTNESS, EntityType, Policy, Span


@dataclass(frozen=True)
class MergedSpan:
    start: int
    end: int
    type: EntityType
    sources: tuple[str, ...]
    searchable: bool = True    # Span.searchable
    # Фрагмент слит из нескольких находок, и ни одна не покрывает его целиком («Иван Иван» в «Иван Иван Иван»): искомы
    # их написания, а не он сам (searchable=False) — иначе цепочка становилась написанием длиной в себя (5.7, шаг 2).
    forms: tuple[str, ...] = ()
    # Где во фрагменте лежат правила пользователя, поглотившие имя или адрес e-mail (5.7), и их типы: выданную замену в
    # нём они не трогают, а часть, задетая правилом, получает его тип (5.10). mail — поглощён адрес: части вне правил —
    # части адреса (имя входа — ACCOUNT).
    ruled: tuple[tuple[int, int, EntityType], ...] = ()
    mail: bool = False
    # Фрагмент имени стоит через точку после выданной замены или метки и перед ней (5.10): это часть имени, а не имя.
    follows: bool = False
    precedes: bool = False
    # Значение сущности, если оно не текст фрагмента: адрес e-mail с выданной заменой внутри — с её оригиналом (5.10).
    value: str | None = None


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


# Шаг 3 (раздел 5.7): части имени рядом — фамилия, имя, отчество, инициалы — один PERSON. Имя — до четырёх слов
# («Ильхам Гейдар оглы Алиев», «Иванов И. И.»); ряд длиннее — список людей через пробел, и части остаются как найдены.
NAME_WORDS = 4
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
    return span if (start, end) == (span.start, span.end) else replace(span, start=start, end=end)


def _joined(text: str, pieces: list[MergedSpan]) -> MergedSpan:
    """Имя из соседних частей. Часть, искомая не целиком (слияние пересекающихся находок), делает таким и имя: оно
    хранит написания частей."""
    sources = tuple(dict.fromkeys(source for piece in pieces for source in piece.sources))
    start, end = pieces[0].start, pieces[-1].end
    if all(piece.searchable for piece in pieces):
        return MergedSpan(start, end, EntityType.PERSON, sources)
    forms = tuple(dict.fromkeys(
        form for piece in pieces for form in ((text[piece.start:piece.end],) if piece.searchable else piece.forms)
    ))
    return MergedSpan(start, end, EntityType.PERSON, sources, searchable=False, forms=forms)


def _join_names(text: str, spans: list[MergedSpan]) -> list[MergedSpan]:
    out: list[MergedSpan] = []
    run: list[MergedSpan] = []      # части ряда соседних имён, которым кончается out
    words, listed = 0, False        # слов в ряду; ряд длиннее имени — его части в out по отдельности
    for index, span in enumerate(spans):
        if span.type is EntityType.PERSON:
            ceiling = spans[index + 1].start if index + 1 < len(spans) else len(text)
            span = _with_initials(text, span, out[-1].end if out else 0, ceiling)
            previous = out[-1] if out else None
            count = max(1, len(text[span.start:span.end].split()))
            if previous is not None and previous.type is EntityType.PERSON and _adjacent(text, previous, span):
                run.append(span)
                words += count
                if listed:
                    out.append(span)
                elif words <= NAME_WORDS:
                    out[-1] = _joined(text, run)
                else:
                    listed = True
                    out[-1:] = run
                continue
            run, words, listed = [span], count, False
        out.append(span)
    return out


_DOTTED_NAME = re.compile(r"[\w-]+(?:\.[\w-]+)+")
_NAME_PART = re.compile(r"[^.\\]+")         # часть имени через «.», «\.» или «\\.» (регулярное выражение)
_NAME_TYPES = (EntityType.HOST, EntityType.DOMAIN)


def _name_kept(
    text: str, group: list[Span], start: int, end: int, policies: Mapping[EntityType, Policy],
) -> EntityType | None:
    """Тип имени узла, домена или адреса e-mail, если правила пользователя в нём легли на целые части имени (раздел 6.4:
    каждая часть слева и домен; у адреса — имени после «@»). Такое правило имя не поглощает: часть получит его тип при
    подмене (resolve._name), адрес — свою метку, в которой скрыта и часть. Правило типа со строже политикой, чем у
    адреса, адрес поглощает: метка адреса не блокировала бы выдачу и восстанавливалась бы целиком (у имени узла политику
    части держит resolve._name)."""
    name = next((
        s for s in group
        if s.source != "manual" and s.type in (*_NAME_TYPES, EntityType.EMAIL) and (s.start, s.end) == (start, end)
    ), None)
    if name is not None and name.type is EntityType.EMAIL:
        own = STRICTNESS.get(policies.get(EntityType.EMAIL), 0)
        if any(STRICTNESS.get(policies.get(s.type), 0) > own for s in group if s.source == "manual"):
            return None
        start = text.rfind("@", start, end) + 1
    dotted = hostmap.dotted(text[start:end])        # имя через «\.» и «\\.» — как через точку
    if name is None or not _DOTTED_NAME.fullmatch(dotted):
        return None
    left, registrable = hostmap.parts(dotted)
    labels = [m.span() for m in _NAME_PART.finditer(text, start, end)]
    edges = {*labels[:len(left)], (labels[len(left)][0], end)}
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
        if senior.source == "manual":
            # Пересекающиеся правила пользователя: старшее — со строже политикой, при равных — самое длинное. Иначе
            # «Иван Иванов» (PERSON) поверх «Иванов» (SECRET, блокировать) давал метку человека, и выдача не блокировалась.
            senior = max(
                (s for s in group if s.source == "manual"),
                key=lambda s: (STRICTNESS.get(policies.get(s.type), 0), s.end - s.start),
            )
        # Списки исключений действуют только на точное значение и не отменяют решение пользователя. Адрес — то же
        # значение в любой записи: «2a00:1450:4010::65» в тексте и «2a00:1450:4010:0:0:0:0:65» в списке, «10.1.2.5» и
        # «010.001.002.005», «10.1.2.0» и «10.1.2.0/24» (длину /24 и больше слой 3 во фрагмент не берёт).
        if "manual" not in sources:
            if senior.type in _NAME_TYPES:
                value = hostmap.dotted(value)       # имя через «\.» и «\\.» — то же значение
            if value in ctx.settings.never or value in ctx.unmask:
                continue
            if senior.type is EntityType.IP:
                if opened is None:
                    opened = netmap.addresses(ctx.settings.never | ctx.unmask)
                if netmap.canonical_forms(value) & opened:
                    continue
        kept = senior.source == "manual" and _name_kept(text, group, start, end, policies)
        type_ = kept or senior.type
        if senior.source != "manual":
            # Старшинство выбирает тип, но политика фрагмента не мягче строжайшей из находок того же значения (FR-3.3):
            # иначе «password=+79161234567» при PHONE «блокировать» давал <SECRET_1>, и выдача не блокировалась. Тип —
            # находки со строже политикой, при равных — старшей. Тип и есть решение: то же значение в следующих текстах
            # найдётся написанием этой сущности, а блокировка проверяется по текущей политике её типа. Находка внутри
            # фрагмента — его часть (домен адреса e-mail), а не другое прочтение: тип её значения он не получает (5.10).
            whole = [senior, *(s for s in group if (s.start, s.end) == (start, end))]
            type_ = min(whole, key=lambda s: (-STRICTNESS.get(policies.get(s.type), 0), _rank(s))).type
        ruled, mail = (), False
        records = [s.type for s in group if s.source != "manual" and s.type in (*_NAME_TYPES, EntityType.EMAIL)]
        if senior.source == "manual" and not kept and records:
            ruled = tuple((s.start, s.end, s.type) for s in group if s.source == "manual")
            mail = EntityType.EMAIL in records
            # Правило поглотило запись — фрагмент берёт тип того из двух, чья политика строже (при равных — правила):
            # метка правила не блокировала бы выдачу адреса при EMAIL=BLOCK и восстанавливала бы его при HIDE.
            record = max(records, key=lambda t: STRICTNESS.get(policies.get(t), 0))
            if STRICTNESS.get(policies.get(record), 0) > STRICTNESS.get(policies.get(type_), 0):
                type_ = record
        # Искомым значение делает любая находка того же типа: слово после «Пароль —», которое нашли и словарём чата.
        # Слияние пересекающихся находок, ни одна из которых не покрывает его целиком («Иван Иван» словаря в «Иван Иван
        # Иван …», правило «la la» в «la la la …», цепочка адресов e-mail «a@b.c.a@b.c.a…»), — не значение: искомы
        # написания находок, а цепочка длиной в текст раздувала бы чат, и поиск сверял бы её с каждого слова.
        searchable = any(s.searchable for s in group if s.type is type_)
        forms: tuple[str, ...] = ()
        if searchable and not any((s.start, s.end) == (start, end) for s in group):
            forms = tuple(dict.fromkeys(text[s.start:s.end] for s in group if s.type is type_ and s.searchable))
            searchable = False
        merged.append(MergedSpan(start, end, type_, sources, searchable, forms, ruled, mail))
    return _join_names(text, merged)
