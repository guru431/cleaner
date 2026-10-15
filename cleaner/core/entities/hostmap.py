"""Разбор доменных имён."""
from __future__ import annotations

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


def has_known_suffix(name: str) -> bool:
    return bool(_extract(name.lower()).suffix)


def mirror_case(original: str, fake: str) -> str:
    return fake.upper() if original.isupper() else fake
