"""Разбор и сведение ФИО (раздел 5.9): роли частей и начальные формы — по pymorphy3.

Упоминание совместимо с сущностью, если ни одна его часть ей не противоречит и хотя бы одна совпала;
присоединяется, если совместимая сущность в чате ровно одна. Мужчина и женщина с одной фамилией,
упомянутые только по фамилии, сливаются — ошибка полезности, а не приватности; исправляется вручную.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from cleaner.core.types import Entity

FIXED_RANK = 1_000_000          # значение для восстановления задал пользователь — разбор его больше не меняет
_ROLES = (("Surn", "last"), ("Name", "first"), ("Patr", "middle"))
_TOKEN = re.compile(r"[^\W\d_]\.|[^\W\d_]+(?:-[^\W\d_]+)*")
_CYRILLIC = re.compile(r"[а-яё]", re.IGNORECASE)
_LETTERS = re.compile(r"[^\W\d_]+")
_PROPER = ("Name", "Surn", "Patr", "Geox", "Orgn", "Trad")   # имя, фамилия, отчество, топоним, организация, марка
_FUNCTION = ("PREP", "CONJ", "PRCL")


@dataclass(frozen=True)
class Word:
    """Слово упоминания: варианты (роль, начальная форма) по всем разборам — или инициал."""

    options: tuple[tuple[str, str], ...] = ()   # роли: last | first | middle | word (роль не определена)
    initial: str = ""                           # инициал — буква в нижнем регистре
    nominative: bool = True


def _fold(value: str) -> str:
    return value.lower().replace("ё", "е")


@lru_cache(maxsize=1)
def _morph():
    import pymorphy3

    return pymorphy3.MorphAnalyzer()


@lru_cache(maxsize=8192)
def _word(token: str) -> Word:
    if token.endswith("."):
        return Word(initial=_fold(token[0]))
    if not _CYRILLIC.search(token):
        return Word((("word", _fold(token)),))
    parses = _morph().parse(token)
    options: list[tuple[str, str]] = []
    nominative = False
    for parse_ in parses:
        if "plur" in parse_.tag:
            continue        # «Петров» — ещё и «(нет) Петров», род. п. мн. ч. имени Пётр: человек в упоминании один
        for grammeme, role in _ROLES:
            if grammeme in parse_.tag:
                option = (role, _fold(parse_.normal_form))
                if option not in options:
                    options.append(option)
                nominative = nominative or "nomn" in parse_.tag
    if not options:          # не имя по словарю: слово сравнивается по начальной форме и как написано
        options = [("word", _fold(parses[0].normal_form))] if parses else []
        if ("word", _fold(token)) not in options:
            options.append(("word", _fold(token)))
        nominative = bool(parses) and "nomn" in parses[0].tag
    return Word(tuple(options), nominative=nominative)


def parse(mention: str) -> tuple[Word, ...]:
    return tuple(_word(token) for token in _TOKEN.findall(mention))


@lru_cache(maxsize=8192)
def _kind(word: str) -> str:
    """noun — нарицательное существительное из словаря, function — предлог, союз или частица, other — прочее."""
    morph = _morph()
    parses = morph.parse(word)
    if parses[0].tag.POS in _FUNCTION:
        return "function"           # раньше имён: у «из» есть разбор «(нет) Ий»
    if not morph.word_is_known(word) or any(grammeme in p.tag for p in parses for grammeme in _PROPER):
        return "other"
    return "noun" if parses[0].tag.POS == "NOUN" else "other"


@lru_cache(maxsize=8192)
def part_of_speech(word: str) -> str | None:
    """Часть речи слова по первому, самому вероятному разбору (NOUN, ADJF, PREP…); None — слова нет в словаре."""
    morph = _morph()
    return morph.parse(word)[0].tag.POS if morph.word_is_known(word) else None


@lru_cache(maxsize=8192)
def animate(word: str) -> bool:
    """Среди разборов слова как существительного есть одушевлённый: «волк», «кузнец», «ворона» бывают фамилиями,
    а «копию», «счёт», «сервер» — нет."""
    return any(p.tag.POS == "NOUN" and "anim" in p.tag for p in _morph().parse(word))


def common_nouns(value: str) -> bool:
    """Только нарицательные существительные из словаря и служебные слова между ними: «из бухгалтерии», «отдел кадров».

    Прилагательное не в счёт: «чапаевская аллея», «васильевского острова» — часть адреса.
    """
    kinds = [_kind(word.lower()) for word in _LETTERS.findall(value)]
    return "noun" in kinds and "other" not in kinds


def _outcome(word: Word, entity: Entity) -> str:
    """match — часть совпала с сущностью; new — добавит ей недостающую часть; conflict — противоречит."""
    if word.initial:
        known = [entity.parts[role][0] for role in ("first", "middle") if entity.parts.get(role)]
        if not known:
            return "new"
        return "match" if word.initial in known else "conflict"
    values = set(entity.parts.values())
    for role, value in word.options:
        if value in entity.words or (role != "word" and entity.parts.get(role) == value) or (role == "word" and value in values):
            return "match"
    if any(role != "word" and role not in entity.parts for role, _ in word.options):
        return "new"
    return "conflict"


def _add(entity: Entity, mention: tuple[Word, ...]) -> None:
    for word in mention:
        if word.initial or not word.options or _outcome(word, entity) == "match":
            continue
        role, value = next(((r, v) for r, v in word.options if r != "word" and r not in entity.parts), word.options[0])
        if role != "word" and role not in entity.parts:
            entity.parts[role] = value
        elif value not in entity.words:
            entity.words.append(value)


def _ensure(entity: Entity) -> None:
    """Сущность из версии до этапа 2: части берутся из её написаний."""
    if not entity.parts and not entity.words:
        for form in entity.forms:
            _add(entity, parse(form))


def compatible(mention: tuple[Word, ...], entity: Entity) -> bool:
    _ensure(entity)
    outcomes = [_outcome(word, entity) for word in mention]
    return "conflict" not in outcomes and "match" in outcomes


def rank(mention: tuple[Word, ...]) -> int:
    """Полнота написания; именительный падеж важнее полноты (раздел 5.9)."""
    full = [word for word in mention if not word.initial]
    nominative = bool(full) and all(word.nominative for word in full)
    return 1000 * nominative + 10 * len(full) + (len(mention) - len(full))


def absorb(entity: Entity, mention: tuple[Word, ...], value: str) -> None:
    """Дополнить сущность частями упоминания; самое полное написание в именительном — значение для восстановления."""
    _ensure(entity)
    _add(entity, mention)
    score = rank(mention)
    if entity.restore_rank != FIXED_RANK and score > entity.restore_rank:
        entity.restore_value = value
        entity.restore_rank = score
