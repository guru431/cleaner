"""Разбор доменных имён."""
from __future__ import annotations

from functools import lru_cache

import tldextract

INTERNAL_SUFFIXES = ("local", "lan", "corp", "internal", "intra", "home", "localdomain", "ad")
# Предел имени DNS. Имя длиннее целиком не записывается (resolve) и в деревья поиска не берётся (surrogates, restore).
MAX_NAME = 253

# Только встроенная копия списка публичных суффиксов: в сеть библиотека не ходит.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=INTERNAL_SUFFIXES)


def split_name(name: str) -> tuple[list[str], str]:
    """Части слева от регистрируемого домена и сам домен. Для неизвестного суффикса домен — ''."""
    labels = name.strip(".").split(".")
    result = _extract(name.lower())
    if not result.suffix:
        return labels, ""
    tail = len(result.suffix.split(".")) + (1 if result.domain else 0)
    return labels[:-tail], ".".join(labels[-tail:])


def parts(name: str) -> tuple[list[str], str]:
    """Части, которые подменяются по отдельности: слева от домена и сам домен. Для неизвестного
    суффикса домен — две последние части."""
    left, registrable = split_name(name)
    if not registrable:
        labels = name.split(".")
        left, registrable = labels[:-2], ".".join(labels[-2:])
    return left, registrable


@lru_cache(maxsize=65536)
def has_known_suffix(name: str) -> bool:
    """Ответ для имени не меняется, а спрашивают его часто: метки с именем в значении проверяются при каждой сборке
    восстановления (labels.domain_labels), и поток ответа собирает её на каждом куске — tldextract на 20 000 меток
    стоил 55 мс на сборку."""
    return bool(_extract(name.lower()).suffix)


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
