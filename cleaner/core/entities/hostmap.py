"""Разбор доменных имён."""
from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path

import tldextract

_SUFFIXES = Path(__file__).resolve().parents[2] / "data" / "internal_suffixes.txt"
# Встроенный список внутренних суффиксов (FR-10.5); дополнения администратора — set_extra_suffixes.
INTERNAL_SUFFIXES = tuple(dict.fromkeys(
    line.strip().lower() for line in _SUFFIXES.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
))
# Предел имени DNS. Имя длиннее целиком не записывается (resolve) и в деревья поиска не берётся (surrogates, restore).
MAX_NAME = 253
# Точка в регулярном выражении: «\.» («^srv01\.contoso\.ru$») и «\\.» — то же выражение внутри строки JSON, Java, C#
# («"^srv01\\.contoso\\.ru$"»). Три обратные косые и больше точку не экранируют: в выражении это обратная косая и знак.
_ESCAPED_DOT = re.compile(r"(?<!\\)\\{1,2}\.")


def dotted(value: str) -> str:
    """Имя или адрес IPv4 через точку: «\\.» и «\\\\.» — точка."""
    return _ESCAPED_DOT.sub(".", value) if "\\." in value else value


def separator(value: str) -> str:
    """Разделитель частей, которым записано имя или адрес: «\\\\.», «\\.» или точка. Подмену пишут им же."""
    return "\\\\." if "\\\\." in value else "\\." if "\\." in value else "."

extra_suffixes: tuple[str, ...] = ()
_suffix_snapshot: ContextVar[tuple[str, ...] | None] = ContextVar("suffix_snapshot", default=None)
# Список вместе с частным разделом — суффиксы, под которыми имена выбирают арендаторы («blob.core.windows.net»).
_private = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def normalize_suffixes(values: tuple[str, ...]) -> tuple[str, ...]:
    if not values:
        return ()
    cleaned = {value.strip().lower() for value in values}
    return tuple(sorted(cleaned.difference(INTERNAL_SUFFIXES, {""})))


def active_suffixes() -> tuple[str, ...]:
    snapshot = _suffix_snapshot.get()
    return extra_suffixes if snapshot is None else snapshot


@contextmanager
def using_suffixes(snapshot: tuple[str, ...]):
    """Замер и оценка правок распознают домены по тому же снимку, который попадает в отпечаток."""
    token = _suffix_snapshot.set(snapshot)
    try:
        yield
    finally:
        _suffix_snapshot.reset(token)


@lru_cache(maxsize=8)
def _extract_for(values: tuple[str, ...]) -> tldextract.TLDExtract:
    # Только встроенная копия списка публичных суффиксов: библиотека не ходит в сеть.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=INTERNAL_SUFFIXES + values)


def set_extra_suffixes(values: tuple[str, ...]) -> bool:
    """Дополнения администратора к внутренним суффиксам (страница встроенных списков). Список один на службу, как и
    встроенный; ответы has_known_suffix сбрасываются, остальные строковые кэши — cache.clear_strings. True — список
    изменился."""
    global extra_suffixes
    values = normalize_suffixes(values)
    if values == extra_suffixes:
        return False
    extra_suffixes = values
    _known_suffix.cache_clear()
    return True


def split_name(name: str) -> tuple[list[str], str]:
    """Части слева от регистрируемого домена и сам домен. Для неизвестного суффикса домен — ''."""
    labels = name.strip(".").split(".")
    result = _extract_for(active_suffixes())(name.lower())
    if not result.suffix:
        return labels, ""
    tail = len(result.suffix.split(".")) + (1 if result.domain else 0)
    return labels[:-tail], ".".join(labels[-tail:])


def private_suffix(name: str) -> tuple[str, str]:
    """Суффикс имени по списку публичных суффиксов вместе с частным разделом и часть прямо слева от него ('' — её нет)."""
    result = _private(name.lower())
    return result.domain, result.suffix


def parts(name: str) -> tuple[list[str], str]:
    """Части, которые подменяются по отдельности: слева от домена и сам домен. Для неизвестного
    суффикса домен — две последние части."""
    left, registrable = split_name(name)
    if not registrable:
        labels = name.split(".")
        left, registrable = labels[:-2], ".".join(labels[-2:])
    return left, registrable


def has_known_suffix(name: str) -> bool:
    """Ответ для имени не меняется, а спрашивают его часто: метки с именем в значении проверяются при каждой сборке
    восстановления (labels.domain_labels), и поток ответа собирает её на каждом куске — tldextract на 20 000 меток
    стоил 55 мс на сборку."""
    return _known_suffix(name, active_suffixes())


@lru_cache(maxsize=65536)
def _known_suffix(name: str, values: tuple[str, ...]) -> bool:
    return bool(_extract_for(values)(name.lower()).suffix)


def code_like(name: str, ambiguous: frozenset[str]) -> bool:
    """Имя с точками похоже на файл или код, а не на узел (5.4): часть в смешанном регистре (System.Net), все части,
    кроме последней, — числа (1.2.3.dev), последняя — расширение файла или слово кода (ambiguous — встроенный список:
    README.md, setup.py). Так судят слой 3 об имени в тексте и labels.domain_labels о значении метки."""
    labels = name.split(".")
    return (
        any(label != label.lower() and label != label.upper() for label in labels)
        or all(label.isdigit() for label in labels[:-1])
        or labels[-1].lower() in ambiguous
    )


def mirror_case(original: str, fake: str) -> str:
    return fake.upper() if original.isupper() else fake
