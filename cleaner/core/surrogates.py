"""Поиск выданных замен в тексте.

Кандидаты находятся несколькими шаблонами по виду (метка, адрес, MAC, SID, имя через точку)
и сверяются с таблицей замен словарём — время не зависит от размера таблицы.
"""
from __future__ import annotations

import ipaddress
import re

from cleaner.core.entities import hostmap, macsid
from cleaner.core.types import ChatState

_LABEL = re.compile(r"<[A-Z]+(?:_[A-Z]+)*_\d+>|\[\[[A-Z]+(?:_[A-Z]+)*_\d+\]\]")
# Адрес через «\.» или «\\.» (регулярное выражение, в том числе в строке JSON) — та же подмена: восстановление пишет
# оригинал с тем же разделителем.
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(\\{0,2}\.)\d{1,3}\1\d{1,3}\1\d{1,3}(?:/\d{1,2})?(?!\w|\\{0,2}\.\d)")
# Как в слое 3: адрес может стоять сразу за подписью («Source:2001:db8:1::1»), подпись в замену не входит.
_IPV6 = re.compile(
    r"(?<![\w:.])(?:(?=\w*[^\W\dA-Fa-f])\w+:|\w{5,}:)?"
    r"(?P<addr>(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w:])"
)
_MAC = re.compile(
    r"(?<![\w:.-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![\w:-])"
    r"|(?<![\w.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![\w.])"
)
_SID = re.compile(r"(?<![\w-])(?P<prefix>S-1-5-21-\d+-\d+-\d+)(?:-\d+)?(?![\w-])")
# Часть имени бывает меткой: части, которой пользователь дал другой тип, выдана метка (<TERM_1>.domain-1.example).
_PART = rf"(?:[\w-]+|{_LABEL.pattern})"
_NAME = re.compile(rf"(?<![\w-]){_PART}(?:\.{_PART})*(?![\w-])")
# Имя в регулярном выражении, шаблоне grep, настройке nginx — части через «\.» («^host-1\.domain-1\.example$»). Ищется
# отдельно, только с этим разделителем: восстановление пишет оригинал с ним же, а цепочки через точку — как раньше.
_ESCAPED_NAME = re.compile(rf"(?<![\w-]){_PART}(?:\\\.{_PART})+(?![\w-])")
# Перед ней бывает граница слова выражения («\bhost-1\.domain-1\.example\b»): «b» — не часть имени (слой 3, _BOUNDED).
_BOUNDED_NAME = re.compile(rf"(?<=\\b)(?<!\\\\b){_PART}(?:\\\.{_PART})+(?![\w-])")
# То же выражение внутри строки JSON, Java, C#: «\\.» и «\\b» («"^host-1\\.domain-1\\.example$"», hostmap.dotted).
_DOUBLE_NAME = re.compile(rf"(?<![\w-]){_PART}(?:\\\\\.{_PART})+(?![\w-])")
_DOUBLE_BOUNDED_NAME = re.compile(rf"(?<=\\\\b)(?<!\\\\\\b){_PART}(?:\\\\\.{_PART})+(?![\w-])")


class Hit:
    """Найденная замена; повторяет нужную часть интерфейса re.Match."""

    __slots__ = ("_start", "_end", "key", "string")

    def __init__(self, start: int, end: int, key: str, string: str):
        self._start, self._end, self.key, self.string = start, end, key, string

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end

    def span(self) -> tuple[int, int]:
        return self._start, self._end

    def group(self) -> str:
        return self.string[self._start:self._end]


class Finder:
    """Ищет замены чата. loose=True узнаёт и свои замены в другом виде записи: SID с RID,
    MAC с другими разделителями — так повторная вставка не создаёт новых сущностей (FR-5.9)."""

    def __init__(self, state: ChatState, loose: bool = False):
        self.table = state.surrogates
        self.loose = loose
        # Имена узлов — деревом частей в нижнем регистре; None — замена, которой кончается цепочка. Имя длиннее 253
        # знаков чаты, сохранённые до 15.10.2026, хранят целиком: оно находится по своим частям (6.4), а в дереве
        # было бы глубиной в тысячи частей, и проход с каждой части текста шёл бы на всю эту глубину.
        self.hosts: dict[str | None, dict | str] = {}
        self.macs: dict[str, str] = {}
        self.macs_by_digits: dict[str, str] = {}
        for key, surrogate in state.surrogates.items():
            if surrogate.kind == "host" and len(surrogate.original or "") <= hostmap.MAX_NAME:
                node = self.hosts
                for part in key.lower().split("."):
                    node = node.setdefault(part, {})
                node[None] = key
            elif surrogate.kind == "mac":
                self.macs[key.lower()] = key
                self.macs_by_digits.setdefault(macsid.mac_key(key), key)

    def finditer(self, text: str) -> list[Hit]:
        if not self.table:
            return []
        hits = [
            *self._labels(text), *self._ipv4(text), *self._ipv6(text),
            *self._macs(text), *self._sids(text), *self._names(text),
        ]
        hits.sort(key=lambda hit: (hit.start(), hit.start() - hit.end()))
        kept: list[Hit] = []
        for hit in hits:
            if not kept or hit.start() >= kept[-1].end():
                kept.append(hit)
        return kept

    def _of_kind(self, key: str, *kinds: str) -> bool:
        surrogate = self.table.get(key)
        return surrogate is not None and surrogate.kind in kinds

    def _labels(self, text: str) -> list[Hit]:
        return [Hit(m.start(), m.end(), m.group(), text) for m in _LABEL.finditer(text) if m.group() in self.table]

    def _ipv4(self, text: str) -> list[Hit]:
        hits = []
        for m in _IPV4.finditer(text):
            written = m.group().split("/")[0]
            token, address = hostmap.dotted(m.group()), hostmap.dotted(written)
            if self._of_kind(token, "ip"):
                hits.append(Hit(m.start(), m.end(), token, text))
            elif self._of_kind(address, "ip"):
                hits.append(Hit(m.start(), m.start() + len(written), address, text))
        return hits

    def _ipv6(self, text: str) -> list[Hit]:
        hits = []
        for m in _IPV6.finditer(text):
            token = m.group("addr")
            if token.endswith(":") and not token.endswith("::"):
                token = token[:-1]
            try:
                key = str(ipaddress.IPv6Address(token))
            except ValueError:
                continue
            if self._of_kind(key, "ip6"):
                hits.append(Hit(m.start("addr"), m.start("addr") + len(token), key, text))
        return hits

    def _macs(self, text: str) -> list[Hit]:
        hits = []
        for m in _MAC.finditer(text):
            key = self.macs.get(m.group().lower())
            if key is None and self.loose:
                key = self.macs_by_digits.get(macsid.mac_key(m.group()))
            if key is not None:
                hits.append(Hit(m.start(), m.end(), key, text))
        return hits

    def _sids(self, text: str) -> list[Hit]:
        hits = []
        for m in _SID.finditer(text):
            prefix = m.group("prefix")
            if self._of_kind(prefix, "sid"):
                end = m.end() if self.loose else m.end("prefix")      # при восстановлении RID остаётся
                hits.append(Hit(m.start(), end, prefix, text))
        return hits

    def _names(self, text: str) -> list[Hit]:
        """Имена узлов: самые длинные цепочки частей через точку (или через «\\.»), которые есть в таблице. Цепочка
        проходится по дереву частей, пока она — начало какой-нибудь замены: перебор всех цепочек до длины самой длинной
        замены был бы кубическим на длинной цепочке («a.a.a…»), если в таблице есть имя из тысяч частей."""
        if not self.hosts:
            return []
        hits = []
        patterns = [(_NAME, "."), (_ESCAPED_NAME, "\\."), (_DOUBLE_NAME, "\\\\.")]
        if "\\b" in text:
            patterns += [(_BOUNDED_NAME, "\\."), (_DOUBLE_BOUNDED_NAME, "\\\\.")]
        for pattern, separator in patterns:
            for m in pattern.finditer(text):
                parts = m.group().split(separator)
                offsets = [m.start()]
                for part in parts:
                    offsets.append(offsets[-1] + len(part) + len(separator))
                lowered = [part.lower() for part in parts]      # «İ» в нижнем регистре длиннее: позиции — по тексту
                first = 0
                while first < len(parts):
                    node, last, found = self.hosts, first, None
                    while last < len(parts) and (node := node.get(lowered[last])) is not None:
                        last += 1
                        if None in node:
                            found = last, node[None]
                    if found:
                        hits.append(Hit(offsets[first], offsets[found[0]] - len(separator), found[1], text))
                        first = found[0]
                    else:
                        first += 1
        return hits


def find(state: ChatState, text: str) -> list[tuple[int, int]]:
    """Где в тексте стоят замены этого чата, в том числе в другом виде записи."""
    return [hit.span() for hit in Finder(state, loose=True).finditer(text)]
