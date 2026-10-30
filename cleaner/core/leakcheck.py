"""Проверка утечек: нет ли в тексте, который уходит наружу, известных оригиналов."""
from __future__ import annotations

import bisect
import re
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from cleaner.core import surrogates
from cleaner.core.entities import netmap, ops
from cleaner.core.match import Forms
from cleaner.core.types import STRICT_TYPES, ChatState, DictEntry, EntityType, Policy, Settings

# Записи адресов — как их находит слой 3: IPv4 (и с нулями впереди, и через «\.» или «\\.») с длиной префикса и без, IPv6
# в любой записи, в том числе сразу за подписью («Source:2a00:…»; подпись в запись не входит). У IPv6 берётся и длина
# префикса: сеть из правила пользователя записана с ней. Каждая попытка ограничена словом, и поиск линеен.
_ADDRESS = re.compile(
    r"(?<![\w.])\d{1,3}(\\{0,2}\.)\d{1,3}\1\d{1,3}\1\d{1,3}(?:/\d{1,2})?(?!\w|\\{0,2}\.\d)"
    r"|(?<![\w:.])(?:(?=\w*[^\W\dA-Fa-f])\w+:|\w{5,}:)?"
    r"(?P<v6>(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?P<length>/\d{1,3})?(?![\w:])"
)


@dataclass(frozen=True)
class Leak:
    start: int
    end: int
    entity_id: str | None      # None — значение из словаря организации


def _mode(type_: EntityType) -> str:
    return "strict" if type_ in STRICT_TYPES else "letters"


def _other_notations(
    text: str, keys: dict[str, str | None], state: ChatState, found: set[Leak],
) -> set[Leak]:
    """Адреса IP в записи, которой нет среди написаний: «2a00:1450:4010:0:0:0:0:65» при известном
    «2A00:1450:4010:0::0065», «010.001.002.005» при «10.1.2.5». Каждая запись адреса в тексте сводится к
    каноническому виду и сравнивается с ключами словарём. Запись, которую уже нашло написание, второй находкой не
    становится; запись выданной подмены — подмена, как на шаге 1 (её IPv4 с нулями впереди Finder не вырезает)."""
    spans = sorted((leak.start, leak.end) for leak in found)
    starts = [start for start, _ in spans]
    reach: list[int] = []               # самый дальний конец находок, начатых не позже каждой
    for _, end in spans:
        reach.append(max(end, reach[-1]) if reach else end)
    fakes: set[str] | None = None
    parsed: dict[str, set[str]] = {}    # разбор адреса дорог, а одна запись в тексте обычно повторяется
    leaks: set[Leak] = set()
    for m in _ADDRESS.finditer(text):
        token, start = m.group(), m.start()
        if m.group("v6") is not None:
            token, start = m.group("v6"), m.start("v6")
            if m.group("length"):
                token += m.group("length")
            elif token.endswith(":") and not token.endswith("::"):
                token = token[:-1]          # двоеточие после адреса — знак препинания («…::65: занят»)
        end = start + len(token)
        i = bisect.bisect_left(starts, end) - 1
        if i >= 0 and reach[i] > start:
            continue
        if token not in parsed:
            parsed[token] = netmap.canonical_forms(token)
        forms = parsed[token]
        # Сеть сравнивается сначала целиком: «10.1.2.0/24» — сущность сети, если она есть, а не адреса 10.1.2.0.
        key = next((form for form in sorted(forms, key=len, reverse=True) if form in keys), None)
        if key is None:
            continue
        if fakes is None:
            fakes = netmap.addresses(
                fake for fake, surrogate in state.surrogates.items() if surrogate.kind in ("ip", "ip6")
            )
        if not forms & fakes:
            leaks.add(Leak(start, end, keys[key]))
    return leaks


_Entities = tuple[tuple[str, ...], tuple[EntityType, ...], tuple[tuple[str, ...], ...]]     # id, тип, написания


@dataclass(frozen=True)
class _Index:
    """Таблицы проверки одного содержимого: открытые значения, написания сущностей и словаря, ключи адресов (ключ
    сущности — раньше ключа словаря, у сущностей — первой по порядку). После сборки не меняются."""

    open_values: frozenset[str]
    opened: Forms[None]
    entities: Forms[str | None]
    always: Forms[None]
    entity_keys: dict[str, str]
    keys: dict[str, str | None]


# Таблицы последней проверки каждого чата (не больше _INDEXES чатов, как STATE_CACHE шлюза): на 20 000 сущностях их
# сборка стоила 0,3 с на проверку, а запрос шлюза проверяет дважды (pipeline и egress). Подпись — копия всего, из чего
# они собраны: написаний сущностей по порядку, словаря, выключенных политикой типов, открытых значений; таблицы собираются
# из неё же, а не из изменяемых списков состояния. Подпись равна прежней — таблицы прежние; отличается только новыми
# сущностями в конце — к прежним таблицам добавляются их написания (как при сборке с начала); иначе — сборка с начала.
_INDEXES = 8
_indexes: OrderedDict[str, tuple[tuple, _Index]] = OrderedDict()
_indexes_lock = threading.Lock()


def _index(state: ChatState, settings: Settings) -> _Index:
    # Три кортежа, а не кортеж на сущность: кортежи строк сборщик мусора не отслеживает, и тысячи кортежей подписи в
    # памяти не удлиняют каждую полную сборку.
    values = state.entities.values()
    entities: _Entities = (
        tuple([entity.id for entity in values]), tuple([entity.type for entity in values]),
        tuple([tuple(entity.forms) for entity in values]),
    )
    rest = (
        tuple(settings.always),
        frozenset(type_ for type_, policy in settings.policies.items() if policy is Policy.OFF),
        ops.open_values(state, settings),
    )
    with _indexes_lock:
        cached = _indexes.get(state.chat_id)
    if cached is not None and cached[0][1:] == rest:
        before, index = cached[0][0], cached[1]
        if before == entities:
            with _indexes_lock:
                _indexes.move_to_end(state.chat_id)
            return index
        count = len(before[0])
        if count < len(entities[0]) and all(now[:count] == was for now, was in zip(entities, before)):
            index = _extend(index, tuple(now[count:] for now in entities), rest[1])
        else:
            index = _build(entities, *rest)
    else:
        index = _build(entities, *rest)
    with _indexes_lock:
        _indexes[state.chat_id] = ((entities, *rest), index)
        _indexes.move_to_end(state.chat_id)
        while len(_indexes) > _INDEXES:
            _indexes.popitem(last=False)
    return index


def _opened(open_values: frozenset[str]) -> Callable[[str, EntityType], bool]:
    opened_addresses: set[str] | None = None

    def opened(form: str, type_: EntityType) -> bool:
        """Написание открыто. Адрес — в любой записи, как его оставляет открытым merge: в списке «2a00:…:0:0:65», в
        тексте и у сущности — «2a00:…::65», и вырезать открытое значение по записи из текста не получится."""
        nonlocal opened_addresses
        if form.lower() in open_values:
            return True
        if type_ is not EntityType.IP:
            return False
        if opened_addresses is None:
            opened_addresses = netmap.addresses(open_values)
        return bool(netmap.canonical_forms(form) & opened_addresses)

    return opened


def _searched(
    pairs: Iterable[tuple[str | None, EntityType, Iterable[str]]], off: frozenset[EntityType],
    opened: Callable[[str, EntityType], bool],
) -> tuple[list[tuple[str, str, str | None]], dict[str, str | None]]:
    """Написания, которые ищутся, и ключи адресов. Адрес IP сравнивается и по адресу: написания — только записи, которые
    чат видел. Ключи — канонические записи тех же написаний, поэтому открытые и выключенные политикой не участвуют."""
    forms: list[tuple[str, str, str | None]] = []
    keys: dict[str, str | None] = {}
    for payload, type_, values in pairs:
        if type_ in off:
            continue
        for form in values:
            if not opened(form, type_):
                forms.append((form, _mode(type_), payload))
                key = netmap.canonical_key(form) if type_ is EntityType.IP else None
                if key is not None:
                    keys.setdefault(key, payload)
    return forms, keys


def _build(
    entities: _Entities, always: tuple[DictEntry, ...], off: frozenset[EntityType], open_values: frozenset[str],
) -> _Index:
    opened = _opened(open_values)
    entity_forms, entity_keys = _searched(zip(*entities), off, opened)
    always_forms, always_keys = _searched(
        ((None, entry.type, (entry.value, *entry.aliases)) for entry in always), off, opened,
    )
    return _Index(
        open_values, Forms([(value, "letters", None) for value in open_values]), Forms(entity_forms),
        Forms(always_forms), entity_keys, always_keys | entity_keys,
    )


def _extend(index: _Index, entities: _Entities, off: frozenset[EntityType]) -> _Index:
    """Таблицы index и сущностей entities после его сущностей — те же, что собранные с начала."""
    forms, keys = _searched(zip(*entities), off, _opened(index.open_values))
    added = {key: payload for key, payload in keys.items() if key not in index.entity_keys}
    return replace(
        index, entities=index.entities.extended(forms), entity_keys=index.entity_keys | added, keys=index.keys | added,
    )


def check(text: str, state: ChatState, settings: Settings) -> list[Leak]:
    index = _index(state, settings)
    # Выданные замены вырезаются: подмена может случайно совпасть с настоящим значением.
    chars = list(text)
    for start, end in surrogates.find(state, text):
        chars[start:end] = " " * (end - start)
    # Открытые значения тоже вырезаются: внутри открытого «srv-dc01.corp.contoso.ru» части
    # «srv-dc01» и «contoso.ru» — не утечка, их показали намеренно. Только целыми словами:
    # открытое «Ivan» не должно прятать от проверки «ivanov».
    for start, end, _ in index.opened.find("".join(chars)):
        chars[start:end] = " " * (end - start)
    remaining = "".join(chars)
    found = {Leak(start, end, payload) for start, end, payload in index.entities.find(remaining)}
    found |= {Leak(start, end, None) for start, end, _ in index.always.find(remaining)}
    if index.keys:
        found |= _other_notations(remaining, index.keys, state, found)
    return sorted(found, key=lambda leak: (leak.start, leak.end))
