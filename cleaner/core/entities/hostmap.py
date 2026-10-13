"""Разбор доменных имён."""
from __future__ import annotations

import tldextract

INTERNAL_SUFFIXES = ("local", "lan", "corp", "internal", "intra", "home", "localdomain", "ad")

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


def has_known_suffix(name: str) -> bool:
    return bool(_extract(name.lower()).suffix)


def mirror_case(original: str, fake: str) -> str:
    return fake.upper() if original.isupper() else fake
