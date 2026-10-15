"""Проверка утечек: нет ли в тексте, который уходит наружу, известных оригиналов."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

from cleaner.core import surrogates
from cleaner.core.entities import netmap
from cleaner.core.match import find_forms
from cleaner.core.types import STRICT_TYPES, ChatState, EntityType, Policy, Settings

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


def _key(value: str) -> str | None:
    """Каноническая запись адреса или сети — как ключ сущности IP; не адрес — None."""
    try:
        ip, prefix = netmap.parse(value)
    except ValueError:
        return None
    return str(ip) if prefix is None else f"{ip}/{prefix}"


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


def check(text: str, state: ChatState, settings: Settings) -> list[Leak]:
    # Выданные замены вырезаются: подмена может случайно совпасть с настоящим значением.
    chars = list(text)
    for start, end in surrogates.find(state, text):
        chars[start:end] = " " * (end - start)
    open_values = settings.never | {r.value.lower() for r in state.rules if r.action == "unmask"}
    # Открытые значения тоже вырезаются: внутри открытого «srv-dc01.corp.contoso.ru» части
    # «srv-dc01» и «contoso.ru» — не утечка, их показали намеренно. Только целыми словами:
    # открытое «Ivan» не должно прятать от проверки «ivanov».
    for start, end, _ in find_forms("".join(chars), [(value, "letters", None) for value in open_values]):
        chars[start:end] = " " * (end - start)
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

    forms: list[tuple[str, str, str | None]] = []
    # Адрес IP сравнивается и по адресу: написания — только записи, которые чат видел. Ключи — канонические записи
    # тех же написаний сущностей IP и значений словаря, поэтому открытые и выключенные политикой не участвуют.
    keys: dict[str, str | None] = {}

    def search(form: str, type_: EntityType, payload: str | None) -> None:
        forms.append((form, _mode(type_), payload))
        key = _key(form) if type_ is EntityType.IP else None
        if key is not None:
            keys.setdefault(key, payload)

    for entity in state.entities.values():
        if settings.policies.get(entity.type) is Policy.OFF:
            continue
        for form in entity.forms:
            if not opened(form, entity.type):
                search(form, entity.type, entity.id)
    for entry in settings.always:
        if settings.policies.get(entry.type) is Policy.OFF:
            continue
        for form in (entry.value, *entry.aliases):
            if not opened(form, entry.type):
                search(form, entry.type, None)
    remaining = "".join(chars)
    found = {Leak(start, end, payload) for start, end, payload in find_forms(remaining, forms)}
    if keys:
        found |= _other_notations(remaining, keys, state, found)
    return sorted(found, key=lambda leak: (leak.start, leak.end))
