"""Общие типы ядра очистки."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum


class EntityType(str, Enum):
    PERSON = "PERSON"
    ORG = "ORG"
    ADDRESS = "ADDRESS"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    BIRTHDATE = "BIRTHDATE"
    PASSPORT = "PASSPORT"
    INN = "INN"
    SNILS = "SNILS"
    OGRN = "OGRN"
    KPP = "KPP"
    OMS = "OMS"
    CARD = "CARD"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    SECRET = "SECRET"
    ACCOUNT = "ACCOUNT"
    IP = "IP"
    MAC = "MAC"
    HOST = "HOST"
    DOMAIN = "DOMAIN"
    SID = "SID"
    DN = "DN"
    TERM = "TERM"


class Policy(str, Enum):
    MASK = "mask"      # скрывать и восстанавливать
    HIDE = "hide"      # скрывать без восстановления
    BLOCK = "block"    # блокировать выдачу
    OFF = "off"        # не искать


def default_policies() -> dict[EntityType, Policy]:
    policies = {type_: Policy.MASK for type_ in EntityType}
    policies[EntityType.SECRET] = Policy.HIDE
    return policies


# Типы, которым выдаётся подмена того же формата; их написания ищутся со строгими границами.
STRICT_TYPES = frozenset(
    {EntityType.IP, EntityType.MAC, EntityType.HOST, EntityType.DOMAIN, EntityType.SID}
)


@dataclass(frozen=True)
class Span:
    """Фрагмент оригинала, найденный одним слоем."""

    start: int
    end: int
    type: EntityType
    source: str                # rules | secrets | infra | dict | manual
    score: float = 1.0
    validated: bool = False    # подтверждён контрольной суммой или строгим форматом


@dataclass
class Entity:
    id: str
    type: EntityType
    number: int
    key: str                   # канонический ключ
    restore_value: str         # что подставляется при восстановлении метки
    origin: str                # detector | manual | dictionary
    forms: list[str] = field(default_factory=list)   # написания, которые ищутся в текстах чата


@dataclass(frozen=True)
class Surrogate:
    entity_id: str
    original: str | None = None    # None — брать Entity.restore_value
    kind: str = "label"            # label | ip | ip6 | host | mac | sid


@dataclass(frozen=True)
class ChatRule:
    action: str                    # mask | unmask
    value: str
    type: EntityType | None = None


@dataclass
class ChatState:
    """Всё, что чат помнит о заменах. Хранение — забота модуля storage."""

    chat_id: str
    net_key: bytes                                                   # ключ перестановки адресов
    label_style: str = "angle"                                       # angle | square
    entities: dict[str, Entity] = field(default_factory=dict)        # id -> сущность
    surrogates: dict[str, Surrogate] = field(default_factory=dict)   # текст замены -> чья она
    issued: dict[str, str] = field(default_factory=dict)             # «id сущности|вид» -> выданная замена
    rules: list[ChatRule] = field(default_factory=list)
    key_alias: dict[str, str] = field(default_factory=dict)          # «ТИП:ключ» -> id сущности после объединения
    foreign_labels: set[str] = field(default_factory=set)            # строки вида метки, пришедшие извне
    counters: dict[str, int] = field(default_factory=dict)
    net6: dict[str, int] = field(default_factory=dict)               # подсеть /64 -> её номер


@dataclass(frozen=True)
class DictEntry:
    type: EntityType
    value: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class CustomPattern:
    name: str
    regex: str
    type: EntityType


@dataclass(frozen=True)
class Settings:
    """Общие для всех чатов настройки. Значения never — в нижнем регистре."""

    always: tuple[DictEntry, ...] = ()
    never: frozenset[str] = frozenset()
    patterns: tuple[CustomPattern, ...] = ()
    policies: Mapping[EntityType, Policy] = field(default_factory=default_policies)
