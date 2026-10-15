"""Общее для слоёв распознавания: контекст и встроенные списки."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from cleaner.core.types import EntityType, Settings, Span

_DATA = Path(__file__).resolve().parents[2] / "data"


class DetectorError(Exception):
    """Слой не смог отработать; очистка должна быть прервана."""


@dataclass(frozen=True)
class Builtin:
    well_known_domains: frozenset[str]
    generic_labels: frozenset[str]
    builtin_accounts: frozenset[str]
    ambiguous_suffixes: frozenset[str]


def _read(name: str) -> frozenset[str]:
    lines = (_DATA / name).read_text(encoding="utf-8").splitlines()
    return frozenset(
        line.strip().lower() for line in lines if line.strip() and not line.lstrip().startswith("#")
    )


@lru_cache(maxsize=1)
def load_builtin() -> Builtin:
    return Builtin(
        well_known_domains=_read("well_known_domains.txt"),
        generic_labels=_read("generic_labels.txt"),
        builtin_accounts=_read("builtin_accounts.txt"),
        ambiguous_suffixes=_read("ambiguous_suffixes.txt"),
    )


@dataclass(frozen=True)
class DetectContext:
    settings: Settings
    known: tuple[tuple[str, EntityType], ...] = ()     # написания сущностей чата
    manual: tuple[tuple[str, EntityType], ...] = ()    # значения, которые пользователь велел скрывать
    unmask: frozenset[str] = frozenset()               # значения, с которых пользователь снял замену
    issued_domains: frozenset[str] = frozenset()       # выданные чатом подмены доменов: «domain-1.example»
    builtin: Builtin = field(default_factory=load_builtin)


class Detector(Protocol):
    name: str

    def detect(self, text: str, ctx: DetectContext) -> list[Span]: ...
