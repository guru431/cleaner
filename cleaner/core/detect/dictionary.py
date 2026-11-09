"""Словарь организации, известные значения чата, правила пользователя и его шаблоны."""
from __future__ import annotations

import threading
from functools import lru_cache

import regex

from cleaner.core.detect.base import DetectContext, DetectorError
from cleaner.core.match import DIGIT_TYPES, Digits, Forms, digit_keys
from cleaner.core.types import STRICT_TYPES, DictEntry, EntityType, Span

name = "dict"

PATTERN_TIMEOUT = 1.0   # секунд на один пользовательский шаблон
_CACHE = 8              # таблиц написаний в памяти (_compiled)
_Key = tuple[tuple[str, ...], tuple[str, ...], tuple[int, ...]]    # написания, режимы, номера нагрузок
_Tables = tuple[Forms[int], Digits[int]]          # написания и ключи цифровых значений (match.digit_keys)
_cache: list[tuple[_Key, _Tables]] = []
_cache_lock = threading.Lock()
_generation = 0
# Нагрузка написания — номер пары (тип, источник): кортежи и таблицы из строк и чисел сборщик мусора не обходит.
_PAYLOADS = [(type_, source) for type_ in EntityType for source in (name, "manual")]
_PAYLOAD = {payload: number for number, payload in enumerate(_PAYLOADS)}
_DIGIT_PAYLOADS = frozenset(_PAYLOAD[type_, name] for type_ in DIGIT_TYPES)     # ищутся и по цифрам (_digits)


def clear_cache() -> None:
    global _generation
    with _cache_lock:
        _cache.clear()
        _generation += 1


def _mode(type_: EntityType) -> str:
    return "strict" if type_ in STRICT_TYPES else "letters"


def _digits(forms: tuple[str, ...], payloads: tuple[int, ...]) -> dict[str, int]:
    """Ключи цифровых значений словаря и сущностей чата; у ключа — первое написание. Выделения пользователя по цифрам не
    ищутся: их ищут как написаны."""
    keys: dict[str, int] = {}
    for form, payload in [(form, payload) for form, payload in zip(forms, payloads) if payload in _DIGIT_PAYLOADS]:
        for key in digit_keys(_PAYLOADS[payload][0], form):
            keys.setdefault(key, payload)
    return keys


def _compiled(forms: _Key, lease=None) -> _Tables:
    """Таблицы написаний — прежние, если написания те же, в том же порядке: сборка на тысячах сущностей чата стоила
    десятки миллисекунд на каждый проход очистки каждой строки. Ключ — сами написания (сравнение, а не хэш). Прежние
    написания — начало новых (новые сущности чата) — к прежним таблицам добавляются остальные, как при сборке с начала."""
    count = len(forms[0])
    with _cache_lock:
        generation = _generation
        allowed = lease is None or lease.active
        for i, (key, compiled) in enumerate(_cache) if allowed else ():
            if key == forms:
                _cache.append(_cache.pop(i))
                return compiled
        prefixes = [(key, compiled) for key, compiled in _cache if len(key[0]) < count] if allowed else []
    start = max(
        (key for key, _ in prefixes if all(now[:len(was)] == was for now, was in zip(forms, key))),
        key=lambda key: len(key[0]), default=None,
    )
    if start is None:
        compiled = Forms(zip(*forms)), Digits(_digits(forms[0], forms[2]))
    else:
        done = len(start[0])
        before, numbers = next(compiled for key, compiled in prefixes if key is start)
        added = {key: payload for key, payload in _digits(forms[0][done:], forms[2][done:]).items()
                 if key not in numbers.keys}
        compiled = before.extended(zip(*(now[done:] for now in forms))), numbers.extended(added)
    with _cache_lock:
        if generation != _generation or (lease is not None and not lease.active):
            from cleaner.core.cache import clear_strings
            clear_strings()
            return compiled
        _cache.append((forms, compiled))
        del _cache[:-_CACHE]
    return compiled


def detect(text: str, ctx: DetectContext) -> list[Span]:
    # Написания, режимы и нагрузки — тремя кортежами (_Key), а не кортежем на написание: ключи таблиц в памяти не
    # удлиняют каждую полную сборку мусора.
    always = [(form, entry.type) for entry in ctx.settings.always for form in (entry.value, *entry.aliases)]
    # Пользователь выделил фрагмент сам — ищем его везде, без оглядки на границы слов; правило смены типа —
    # с границами, с которыми искались написания до неё.
    forms: _Key = (
        tuple([form for form, _ in always] + [form for form, _ in ctx.known] + [form for form, _, _ in ctx.manual]),
        tuple([_mode(type_) for _, type_ in always] + [_mode(type_) for _, type_ in ctx.known]
              + [bounds for _, _, bounds in ctx.manual]),
        tuple([_PAYLOAD[type_, name] for _, type_ in always] + [_PAYLOAD[type_, name] for _, type_ in ctx.known]
              + [_PAYLOAD[type_, "manual"] for _, type_, _ in ctx.manual]),
    )
    written, numbers = _compiled(forms, ctx.cache_lease)
    found = written.find(text)
    # Номер в другой записи: «9031112233» и «903 111-22-33» при известном «+7 (903) 111-22-33» (FR-3.4).
    if numbers.keys:
        found += numbers.find(text, [(start, end) for start, end, _ in found])
    spans = [Span(start, end, *_PAYLOADS[payload]) for start, end, payload in found]
    for pattern in ctx.settings.patterns:
        try:
            for m in regex.finditer(pattern.regex, text, timeout=PATTERN_TIMEOUT):
                if m.end() > m.start():
                    spans.append(Span(m.start(), m.end(), pattern.type, name))
        except TimeoutError as exc:
            raise DetectorError(f"шаблон «{pattern.name}» выполняется слишком долго") from exc
    return spans


# --- падежные формы записей словаря (спецификация 5.4) ----------------------------------------
# Запись с отметкой «искать во всех падежах» ищется и в косвенных падежах единственного числа: «Смирновой Анне Петровне»,
# «по Проекту Полярис». Формы — варианты написания записи: одна замена, та же проверка утечек. Строятся по pymorphy3
# двумя способами: склоняются все слова (ФИО, «Красная площадь») и, кроме людей, только начало до первого
# существительного («улице Ленина», «Проекту Полярис»). Лишняя форма ничего не открывает — её просто нет в текстах.
# Слова в кавычках, сокращения прописными («ООО»), латиница и числа не склоняются.
INFLECTED_TYPES = frozenset({EntityType.PERSON, EntityType.ORG, EntityType.ADDRESS, EntityType.TERM})
_CASES = ("gent", "datv", "accs", "ablt", "loct")
_PIECE = regex.compile(r"«[^»]*»|“[^”]*”|„[^“”]*[“”]|\"[^\"]*\"|[^\W\d_]+(?:-[^\W\d_]+)*|.", regex.DOTALL)
_CYRILLIC = regex.compile(r"[а-яё]", regex.IGNORECASE)
_NAME_GRAMMEMES = ("Name", "Surn", "Patr")


def _parse(word: str, person: bool, gender: str | None):
    """Разбор слова в именительном падеже единственного числа; у людей — как части имени, если такой есть; из равных —
    рода фразы."""
    from cleaner.core.entities.names import _morph

    parses = [
        p for p in _morph().parse(word)
        if "nomn" in p.tag and "plur" not in p.tag and p.tag.POS in ("NOUN", "ADJF", "PRTF")
    ]
    if person and any(g in p.tag for p in parses for g in _NAME_GRAMMEMES):
        parses = [p for p in parses if any(g in p.tag for g in _NAME_GRAMMEMES)]
    return next((p for p in parses if p.tag.gender == gender), parses[0] if parses else None)


def _cased(original: str, word: str) -> str:
    return "-".join(part[:1].upper() + part[1:] for part in word.split("-")) if original[:1].isupper() else word


@lru_cache(maxsize=16384)
def inflected(type_: EntityType, value: str) -> tuple[str, ...]:
    """Падежные формы значения, кроме него самого; () — тип не склоняется или склонять нечего."""
    if type_ not in INFLECTED_TYPES:
        return ()
    from cleaner.core.entities.names import _morph

    pieces = _PIECE.findall(value)
    words = [
        i for i, piece in enumerate(pieces)
        if _CYRILLIC.search(piece) and piece[0] not in "«“„\"" and not (len(piece) > 1 and piece.isupper())
    ]
    person = type_ is EntityType.PERSON
    gender = None           # род фразы: у людей — по имени или отчеству, у прочих — по первому существительному
    for i in words:
        for p in _morph().parse(pieces[i]):
            if "nomn" in p.tag and p.tag.POS == "NOUN" and (not person or "Name" in p.tag or "Patr" in p.tag):
                gender = p.tag.gender
                break
        if gender:
            break
    parses = {i: _parse(pieces[i], person, gender) for i in words}
    nouns = [i for i in words if parses[i] is not None and parses[i].tag.POS == "NOUN"]
    head = [i for i in words if not nouns or i <= nouns[0]]
    out: dict[str, None] = {}
    for chosen in (words,) if person else (words, head):        # части имени склоняются все
        for case in _CASES:
            changed = list(pieces)
            for i in chosen:
                form = parses[i].inflect({case}) if parses[i] is not None else None
                if form is not None:
                    changed[i] = _cased(pieces[i], form.word)
            out.setdefault("".join(changed), None)
    return tuple(form for form in out if form.lower() != value.lower())


def entry(type_: EntityType, value: str, aliases: tuple[str, ...], inflect: bool) -> DictEntry:
    """Запись словаря для ядра: с отметкой «искать во всех падежах» к вариантам добавляются падежные формы значения и
    каждого варианта."""
    if not inflect:
        return DictEntry(type_, value, aliases)
    forms = [form for written in (value, *aliases) for form in inflected(type_, written)]
    return DictEntry(type_, value, tuple(dict.fromkeys([*aliases, *forms])))
