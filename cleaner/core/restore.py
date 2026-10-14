"""Восстановление: обратная подстановка оригиналов в ответ модели."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass

from cleaner.core import surrogates
from cleaner.core.entities import labels, macsid, netmap
from cleaner.core.types import ChatState, EntityType, Policy, Settings

Piece = tuple[str, str | None]      # текст и вид выделения; None — кусок ещё не обработан
Handler = Callable[[re.Match[str]], Piece | None]

# Всё, что может стать ссылкой. Цель ссылки Markdown берётся вместе со скобками внутри («x_(1).png»),
# атрибут HTML с адресом — целиком, с кавычками внутри. Голый адрес (со схемой или на «www.») тянется
# до пробела и не кончается знаком препинания или кавычкой; адрес сразу после кавычки кончается
# такой же кавычкой («"https://…","<EMAIL_1>"»), а без неё идёт и через кавычки («?q='…'»).
_START = r"(?:(?:[a-z][a-z0-9+.-]{0,31}:)?//|(?<![\w.-])www\.)"
_END = r"[^\s\"'`.,;:!?)\]}]"
# Атрибут тянется и через строки (браузер выбрасывает из адреса переводы строк), но не дальше
# 4096 знаков: незакрытая кавычка не должна захватить весь ответ. Цель определения ссылки
# в угловых скобках («[1]: <https://… с пробелами>») — до последней «>» строки.
_LINK = re.compile(
    r"\]\((?P<md>(?:[^()\r\n]|\([^()\r\n]*\))*)\)"
    r"|\]:[ \t]*<(?P<ref>[^\r\n]*)>"
    r"|(?<![\w-])(?:href|src|srcset|action|formaction|poster|data|background|cite|ping|style)"
    r"\s*=\s*(?P<quote>[\"'])(?P<attr>[\s\S]{0,4096}?)(?P=quote)"
    rf"|(?P<mailto>mailto:[^\s\"'`]*{_END})"
    rf"|(?<=\")(?P<dq>{_START}[^\s\"`]*{_END})"
    rf"|(?<=')(?P<sq>{_START}[^\s'`]*{_END})"
    rf"|(?P<url>{_START}[^\s`]*{_END})",
    re.IGNORECASE,
)
# Хост — по правилам браузера: имя пользователя кончается на «@» и не содержит «/?#\»,
# хост кончается на «/», «\», «:», «?» или «#».
_URL_HOST = re.compile(
    r"(?:[a-z][a-z0-9+.-]{0,31}:)?//(?:[^/?#\\@\s]*@)?(\[[^\]]+\]|[^/\\:?#\s]+)", re.IGNORECASE
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_MAC = re.compile(
    r"(?<![\w:.-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![\w:-])"
    r"|(?<![\w.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![\w.])"
)


def _tolerant_pattern() -> re.Pattern[str]:
    """Метка с искажённым оформлением: тип и номер читаются как написаны, не угадываются."""
    types = "|".join(
        t.value.replace("_", r"\\?_") for t in sorted(EntityType, key=lambda t: -len(t.value))
    )
    return re.compile(
        r"(?:(?P<open>\\?<|&lt;|\\?\[\\?\[)\s*|(?<![\w<\[]))"
        rf"(?P<type>(?i:{types}))\s*\\?_\s*(?P<num>\d+)(?!\d)"
        r"(?:\s*(?P<close>\\?>|&gt;|\\?\]\\?\]))?"
    )


_TOLERANT = _tolerant_pattern()


@dataclass(frozen=True)
class Segment:
    start: int
    end: int
    kind: str       # restored | altered | derived | unknown | kept_by_policy | foreign_link


@dataclass
class RestoreResult:
    text: str
    segments: list[Segment]
    counters: dict[str, int]


def _split(pieces: list[Piece], pattern: re.Pattern[str] | surrogates.Finder, handler: Handler) -> list[Piece]:
    """Применяет handler к совпадениям pattern в ещё не обработанных кусках."""
    out: list[Piece] = []
    for text, kind in pieces:
        if kind is not None:
            out.append((text, kind))
            continue
        position = 0
        for m in pattern.finditer(text):
            replaced = handler(m)
            if replaced is None:
                continue
            if m.start() > position:
                out.append((text[position:m.start()], None))
            out.append(replaced)
            position = m.end()
        if position < len(text):
            out.append((text[position:], None))
    return out


class _Restorer:
    def __init__(self, state: ChatState, settings: Settings):
        self.state = state
        self.settings = settings
        self.exact = surrogates.Finder(state)
        self.fake_nets: set[int] = set()
        self.macs = {}
        self.own_hosts = {
            text.lower() for text, surrogate in state.surrogates.items()
            if surrogate.kind in ("host", "ip", "ip6")
        }
        # Больше частей, чем в самой длинной выданной подмене, одна цепочка не займёт: без этого
        # предела хост «a.a.a…» из тысяч частей проверялся бы квадратичное время.
        self.depth = max((text.count(".") + 1 for text in self.own_hosts), default=0)
        for text, surrogate in state.surrogates.items():
            if surrogate.kind == "ip":
                self.fake_nets.add(int(ipaddress.IPv4Address(text.split("/")[0])) >> 8)
            elif surrogate.kind == "mac":
                self.macs[macsid.mac_key(text)] = surrogate
        self.counters = dict.fromkeys(
            ("restored", "altered", "derived", "unknown", "kept", "foreign_links"), 0
        )

    def run(self, pieces: list[Piece], links: bool) -> list[Piece]:
        if links:
            pieces = _split(pieces, _LINK, self._link)
        pieces = _split(pieces, self.exact, self._exact)
        pieces = _split(pieces, _TOLERANT, self._label)
        pieces = _split(pieces, _IPV4, self._derived_ip)
        return _split(pieces, _MAC, self._mac)

    def _inner(self, text: str) -> str:
        """Что получилось бы из text без учёта ссылок; счётчики не трогает."""
        saved = dict(self.counters)
        result = "".join(piece for piece, _ in self.run([(text, None)], links=False))
        self.counters = saved
        return result

    def _hidden(self, type_: EntityType) -> bool:
        return self.settings.policies.get(type_) is Policy.HIDE

    def _host_is_ours(self, host: str) -> bool:
        """Хост целиком — выданная подмена или собран только из её частей (host-1.sub-2.domain-1.example)."""
        labels_ = host.strip("[]").lower().split(".")
        reachable = {0}
        for first in range(len(labels_)):
            if first not in reachable:
                continue
            for last in range(first + 1, min(len(labels_), first + self.depth) + 1):
                if ".".join(labels_[first:last]) in self.own_hosts:
                    reachable.add(last)
        return len(labels_) in reachable

    def _is_own(self, target: str) -> bool:
        """Ведёт ли ссылка на наш узел или наш адрес. Всё остальное — чужая ссылка."""
        target = re.sub(r"[\t\r\n]", "", target.strip())   # браузер выбрасывает их из адреса
        if target.lower().startswith("mailto:"):
            address = target[len("mailto:"):]
            return address in self.state.surrogates          # без параметров: в них может быть что угодно
        if target.lower().startswith("www."):
            target = "//" + target
        host = _URL_HOST.match(target)
        return bool(host) and self._host_is_ours(host.group(1))

    def _link(self, m: re.Match[str]) -> Piece | None:
        target = next(
            (m.group(name) for name in ("md", "ref", "attr", "mailto", "dq", "sq", "url") if m.group(name)), ""
        )
        if self._is_own(target):
            return None         # ссылка на наш же узел восстанавливается как обычный текст
        if self._inner(m.group()) == m.group():
            return None         # восстанавливать в ней нечего
        self.counters["foreign_links"] += 1
        return m.group(), "foreign_link"

    def _exact(self, m: surrogates.Hit) -> Piece:
        text = m.group()
        surrogate = self.state.surrogates[m.key]
        entity = self.state.entities[surrogate.entity_id]
        if self._hidden(entity.type):
            self.counters["kept"] += 1
            return text, "kept_by_policy"
        original = surrogate.original if surrogate.original is not None else entity.restore_value
        kind = "restored"
        if surrogate.kind == "host":
            if text.isupper():
                original = original.upper()
            before = m.string[max(0, m.start() - 1):m.start()]
            after = m.string[m.end():m.end() + 2]
            if before == "." or (after[:1] == "." and after[1:2].isalnum()):
                kind = "derived"        # часть имени, которого не было в запросе
        self.counters[kind] += 1
        return original, kind

    def _label(self, m: re.Match[str]) -> Piece | None:
        if m.group() in self.state.foreign_labels:
            return None
        type_ = EntityType(m.group("type").replace("\\", "").upper())
        canonical = labels.format_label(self.state.label_style, type_, int(m.group("num")))
        surrogate = self.state.surrogates.get(canonical)
        if surrogate is None:
            if not (m.group("open") or m.group("close")):
                return None         # просто слово вида TYPE_1 в тексте
            self.counters["unknown"] += 1
            return m.group(), "unknown"
        entity = self.state.entities[surrogate.entity_id]
        if self._hidden(entity.type):
            self.counters["kept"] += 1
            return canonical, "kept_by_policy"
        self.counters["altered"] += 1
        return entity.restore_value, "altered"

    def _derived_ip(self, m: re.Match[str]) -> Piece | None:
        try:
            ip = ipaddress.IPv4Address(m.group())
        except ValueError:
            return None
        bits = netmap.private_bits(ip)
        if bits is None or (int(ip) >> 8) not in self.fake_nets:
            return None
        original = netmap.unmap_private(int(ip), bits, self.state.net_key)
        self.counters["derived"] += 1
        return str(ipaddress.IPv4Address(original)), "derived"

    def _mac(self, m: re.Match[str]) -> Piece | None:
        surrogate = self.macs.get(macsid.mac_key(m.group()))
        if surrogate is None:
            return None
        self.counters["altered"] += 1
        return surrogate.original or m.group(), "altered"


def restore(state: ChatState, answer: str, settings: Settings) -> RestoreResult:
    """Подставляет оригиналы вместо замен чата. Замены сопоставляются только точно."""
    restorer = _Restorer(state, settings)
    parts: list[str] = []
    segments: list[Segment] = []
    position = 0
    for piece, kind in restorer.run([(answer, None)], links=True):
        if kind is not None:
            segments.append(Segment(position, position + len(piece), kind))
        parts.append(piece)
        position += len(piece)
    counters = {**restorer.counters, "table": len(state.surrogates)}
    return RestoreResult("".join(parts), segments, counters)
