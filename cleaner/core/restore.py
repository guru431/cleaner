"""Восстановление: обратная подстановка оригиналов в ответ модели."""
from __future__ import annotations

import bisect
import html
import ipaddress
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from html.entities import html5 as _ENTITIES

from cleaner.core import surrogates
from cleaner.core.entities import labels, macsid, netmap
from cleaner.core.entities.names import FIXED_RANK
from cleaner.core.types import ChatState, EntityType, Policy, Settings, Surrogate

Piece = tuple[str, str | None]      # текст и вид выделения; None — кусок ещё не обработан
Handler = Callable[[re.Match[str]], Piece | None]

# Начало адреса с хостом — как его разбирает браузер (WHATWG URL). У особых схем (http, https, ws, wss, ftp)
# после двоеточия пропускается любая череда «/» и «\», даже пустая: «https:\\evil…», «https:/\evil…» и
# «http:evil…» ведут на evil. У file хост стоит за двумя косыми любого вида, у прочих схем — только за «//».
# Адрес без схемы браузер разбирает от страницы с особой схемой, поэтому «\\evil…» и «/\evil…» — то же, что
# «//evil…»; но череда с «\» внутри пути или имени («C:\\Users\\…» в строке кода) — путь, а не адрес.
_SPECIAL = r"(?<![\w+.-])(?:https?|wss?|ftp):"
_AUTHORITY = (
    _SPECIAL + r"|(?<![\w+.-])file:[/\\]{2}|[a-z][a-z0-9+.-]{0,31}://|(?<![/\\])(?://|(?<![\w.:%-])[/\\]{2})"
)
# Всё, что может стать ссылкой. Цель ссылки Markdown берётся вместе со скобками внутри («x_(1).png»),
# атрибут HTML с адресом — целиком, с кавычками внутри. Голый адрес (со схемой или на «www.») тянется
# до пробела и не кончается знаком препинания или кавычкой; адрес сразу после кавычки кончается
# такой же кавычкой («"https://…","<EMAIL_1>"»), а без неё идёт и через кавычки («?q='…'»).
_START = rf"(?:{_AUTHORITY}|(?<![\w.-])www\.)"
_END = r"[^\s\"'`.,;:!?)\]}]"
# Строки в image-set() и -webkit-image-set() — в любом варианте, не только в первом, — и в src() браузер
# тоже загружает сам, как url(). Аргументы такого вызова берутся целиком, по скобкам любого вида: внутри
# бывают градиенты и var() с блоком, а «)» в строке, в комментарии или после «\» вызов не кончает. Строка
# и комментарий без конца тянутся до конца ответа, как в CSS; вложенность глубже _CSS_DEPTH и незакрытый
# вызов — тоже до конца ответа, в сторону ссылки. Каждый шаг атомарен: разбор не возвращается и линеен.
_CSS_DEPTH = 4
_CSS_ITEM = (
    r"\"(?:\\[\s\S]|[^\\\"])*(?:\"|\Z)|'(?:\\[\s\S]|[^\\'])*(?:'|\Z)|/\*[\s\S]*?(?:\*/|\Z)"
    r"|\\[\s\S]|[^\\()\[\]{}\"']"
)


def _css_args(depth: int) -> str:
    level = rf"(?>{_CSS_ITEM})*+"
    for _ in range(depth):
        level = rf"(?>{_CSS_ITEM}|[(\[{{]{level}[)\]}}])*+"
    return level


def _css_name(name: str) -> str:
    """Имя функции или правила CSS в любой записи, которую браузер прочтёт как это имя (CSS Syntax 3): каждый
    знак — сам или экранированный. Код — до шести шестнадцатеричных цифр («\\72», «\\000052»), один пробельный
    знак или CRLF за ним входят в экранирование («u\\72 l(» — это url(). За кодом короче шести цифр не стоит
    ещё цифра: «\\726c» — другой знак; код из шести цифр кончается сам: «s\\000072c(» — это src(). Знак, который не
    шестнадцатеричная цифра, экранируется и так: «\\r» — это «r», а «\\a» — перевод строки, не «a». Регистр не
    важен: _LINK собран без учёта регистра. Длина каждого варианта ограничена, поэтому поиск остаётся линейным."""
    parts = []
    for char in name:
        code = "|".join(sorted({f"{ord(c):x}" for c in (char.lower(), char.upper())}))
        escaped = rf"\\(?:0000(?:{code})|0{{0,3}}(?:{code})(?![0-9a-f]))(?:\r\n|[ \t\r\n\f])?"
        if char.lower() not in "0123456789abcdef":
            escaped += rf"|\\{re.escape(char)}"
        parts.append(rf"(?:{re.escape(char)}|{escaped})")
    return "".join(parts)


# Имена, по которым браузер загружает адрес сам, — в любой записи: «u\72l(», «@\69mport», «image-s\65t(» в
# элементе style, в файле CSS и в атрибуте style загружают так же, как url(), @import и image-set().
_URL = _css_name("url")
_IMPORT = "@" + _css_name("import")
_SET = rf"(?:(?:{_css_name('-webkit-')})?{_css_name('image-set')}|{_css_name('src')})"


# Атрибут тянется и через строки до той же кавычки: браузер выбрасывает из адреса переводы строк.
# Это линейно — поиск каждого атрибута кончается на следующей такой же кавычке. Значение без кавычек
# берётся до пробельного знака ASCII, как в HTML, но и через «>»: «>» могла закрывать метку
# («href=//наш:<EMAIL_1>@evil…»), а после восстановления её нет, и значение у браузера длиннее. Определение
# ссылки Markdown — только в начале строки, как в CommonMark, цель в угловых скобках может стоять на
# следующей строке и содержать пробелы («[1]: <https://… …>»): иначе «[ERROR]: <EMAIL_1>» в журнале
# считалось бы ссылкой; цель без скобок — до пробела или управляющего знака. Без кавычек и без скобок цель
# со схемой и так нашлась бы как голый адрес, а записанную ссылками на знаки («&#47;&#47;evil…») — нет.
# Адрес в CSS url(…) и @import браузер загружает сам — и в атрибуте style, и в
# элементе style, и в файле CSS: аргумент в кавычках берётся до той же кавычки с учётом «\"» (без неё
# строку CSS кончает конец текста — и загружает), без кавычек — до «)». Между @import и строкой браузер
# пропускает пробелы и комментарии («@import/**/"…"»), а внутри url( комментарий — уже часть адреса, и
# «url(/**/"…")» не загружает ничего. Поэтому ссылка @import — пробелы и комментарии за ним и первая строка
# после них (url() за ними находится сам по себе); строки нет — ссылка только из пробелов и комментариев,
# и текст, где @import лишь упомянут, восстанавливается как обычно. Комментарий без «*/» тянется до конца
# ответа, как в CSS, и адреса в нём проверяются вместе со ссылкой. Каждый шаг атомарен, совпадение есть всегда:
# «@import/*@import/*…» читается до конца один раз — поиск, который мог бы не найти строку и откатиться,
# перечитывал бы незакрытый комментарий от каждого @import, и время было бы квадратичным. Нашей ссылка
# считается, только если наши все адреса в ней при любом прочтении ссылок на знаки (_Restorer._is_own,
# _readings).
_LINK = re.compile(
    r"\]\((?P<md>(?:[^()\r\n]|\([^()\r\n]*\))*)\)"
    r"|(?m:^)[ ]{0,3}\[[^\]\r\n]+\]:[ \t]*(?:\r?\n[ \t]*)?"
    r"(?:<(?P<ref>[^\r\n]*)>|(?P<dest>[^\x00-\x20<][^\x00-\x20]*))"
    r"|(?<![\w-])(?P<name>href|src|srcset|action|formaction|poster|data|background|cite|ping|style|content)"
    r"\s*=\s*(?:(?P<quote>[\"'])(?P<attr>[\s\S]*?)(?P=quote)|(?P<unquoted>[^\t\n\f\r \"'][^\t\n\f\r ]*))"
    rf"|(?<![\w-]){_URL}\(\s*(?P<cq>[\"'])(?P<css>(?:\\[\s\S]|[^\\])*?)(?:(?P=cq)|\Z)"
    rf"|{_IMPORT}(?P<imp>(?>\s|/\*[\s\S]*?(?:\*/|\Z))*+(?:\"(?:\\[\s\S]|[^\\\"])*+|'(?:\\[\s\S]|[^\\'])*+)?)"
    rf"|(?<![\w-]){_URL}\((?P<cssu>(?:\\[\s\S]|[^\\()\"'])*)\)"
    rf"|(?<![\w-]){_SET}\((?P<set>{_css_args(_CSS_DEPTH)}(?=[)\]}}])|[\s\S]*)"
    rf"|(?P<mailto>mailto:[^\s\"'`]*{_END})"
    rf"|(?<=\")(?P<dq>{_START}[^\s\"`]*{_END})"
    rf"|(?<=')(?P<sq>{_START}[^\s'`]*{_END})"
    rf"|(?P<url>{_START}[^\s`]*{_END})",
    re.IGNORECASE,
)
# Каждый адрес внутри ссылки и его хост — по правилам браузера: косые за началом адреса пропускаются, имя
# пользователя с паролем не содержит «/?#\» и кончается на последнем «@» («a@наш:1@evil…» ведёт на evil),
# хост кончается на «/», «\», «:», «?» или «#». Пробелы имя пользователя не кончают: браузер кодирует их как
# «%20», и «https://наш x@evil…» в атрибуте ведёт на evil. У «file:///путь» хоста нет — это локальный файл (а
# «file:////узел/…» — путь UNC, его хост находится как обычно). Имя пользователя не тянется через начало
# адреса с особой схемой («//a:https:@…»): у того адреса свой хост, и поиск остаётся линейным на «https:https:…»;
# любое другое начало адреса содержит «/» или «\», на которых имя пользователя тоже кончается.
_URL_HOSTS = re.compile(
    r"file:[/\\]{3}(?![/\\])"
    rf"|(?:(?:{_AUTHORITY})[/\\]*+(?:(?:(?!{_SPECIAL})[^/?#\\])*@)?|(?<![\w.-])(?=www\.))"
    r"(\[[^\]]+\]|[^/\\:?#\s]+)",
    re.IGNORECASE,
)
# Ссылка на знак HTML («&#47;», «&#x2F», «&sol;», «&nbsp» без «;») — так же, как её находит html.unescape.
_CHARREF = re.compile(r"&(?:#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)")
# Числовая ссылка, которую раскрывает CommonMark: только с «;», до семи десятичных или шести шестнадцатеричных цифр.
_MD_NUMERIC = re.compile(r"&#(?:[0-9]{1,7}|[xX][0-9a-fA-F]{1,6});")
_ASCII_ALNUM = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _charref(ref: str, reader: str) -> str:
    """Во что раскроет ссылку на знак ref читатель: html — текст HTML (как html.unescape), attr — значение
    атрибута HTML, md — CommonMark. Имя ищется самое длинное из таблицы HTML5. Имя без «;» (старый набор: «&amp»,
    «&nbsp», «&not») атрибут не раскрывает, если за ним буква, цифра или «=» («?a=1&notify=2»), а CommonMark не
    раскрывает никогда; числовую ссылку без «;» HTML раскрывает всегда, CommonMark — нет."""
    if ref[1] == "#":
        if reader == "md" and not _MD_NUMERIC.fullmatch(ref):
            return ref
        hexadecimal = ref[2] in "xX"
        digits = ref.rstrip(";")[3 if hexadecimal else 2:].lstrip("0")
        if len(digits) > 8:
            # Больше U+10FFFF, и браузер ставит U+FFFD. Ведущие нули — не повод: «&#00…047;» — это «/», а
            # html.unescape на 4300 цифрах и больше падает с ValueError.
            return "\N{REPLACEMENT CHARACTER}"
        return html.unescape(f"&#{'x' if hexadecimal else ''}{digits or '0'};")
    name = ref[1:]
    end = next((end for end in range(len(name), 1, -1) if name[:end] in _ENTITIES), 0)
    if not end:
        return ref
    if not name[:end].endswith(";") and (
        reader == "md" or (reader == "attr" and end < len(name) and (name[end] in _ASCII_ALNUM or name[end] == "="))
    ):
        return ref
    return _ENTITIES[name[:end]] + name[end:]


def _readings(text: str) -> tuple[str, ...]:
    """Текст ссылки так, как его прочтут: как есть (CSS в элементе style и в файле, простой текст), в тексте HTML,
    в значении атрибута HTML и в цели ссылки CommonMark. Ссылки на знаки браузер и CommonMark раскрывают до разбора
    адреса: «&#47;&#47;evil…» в атрибуте — это «//evil…», «наш&commat;evil…» — «наш@evil…». Где окажется ответ,
    неизвестно, поэтому ссылка наша, только если наша при каждом прочтении. Одного html.unescape мало: в атрибуте
    «&#47;&#47;наш&nbspevil…» — один хост с «&nbsp» внутри, а html.unescape раскрыл бы «&nbsp» в пробел, и хост
    оборвался бы на нашем имени. Одинаковые прочтения проверяются один раз."""
    if "&" not in text:
        return (text,)
    readings = [_CHARREF.sub(lambda m: _charref(m.group(), reader), text) for reader in ("html", "attr", "md")]
    return tuple(dict.fromkeys((text, *readings)))
# Вне тегов HTML — текст до первого «<» и участки от «>» до ближайшего «<» или кавычки, если между «<» и
# этой «>» кавычек нет. Кавычка оставляет атрибут в теге: «>» могла стоять в значении («<a title="a>b"
# href=…»). Любой «<», не только «<буква», и любая кавычка — в сторону ссылки; поиск линеен: каждая
# попытка кончается на ближайшем «<».
_OUTSIDE_TAGS = re.compile(r"<[^<>\"']*>([^<\"']*)")
_HOST_TYPES = frozenset({EntityType.IP, EntityType.HOST, EntityType.DOMAIN})
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_MAC = re.compile(
    r"(?<![\w:.-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![\w:-])"
    r"|(?<![\w.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![\w.])"
)


def _tolerant_pattern() -> re.Pattern[str]:
    """Метка с искажённым оформлением: тип и номер читаются как написаны, не угадываются. Без закрывающего
    ограничителя метка — отдельное слово: «PERSON_1x», «person_1_name» в коде — не метки. Регистр не
    важен только у латиницы: «İ» и «ſ» без учёта регистра совпали бы с «I» и «S»."""
    types = "|".join(
        t.value.replace("_", r"\\?_") for t in sorted(EntityType, key=lambda t: -len(t.value))
    )
    return re.compile(
        r"(?:(?P<open>\\?<|&lt;|\\?\[\\?\[)\s*|(?<![\w<\[]))"
        rf"(?P<type>(?ai:{types}))\s*\\?_\s*(?P<num>\d+)(?!\d)"
        r"(?:\s*(?P<close>\\?>|&gt;|\\?\]\\?\])|(?!\w))"
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


def _nowhere(token: str) -> bool:
    """Адрес без схемы («//TODO:…» в коде, «//share/…», «\\\\fs01\\home\\…») после восстановления не ведёт на
    внешний узел: в нём нет ни точки, ни того, что браузер превратит в точку («%2E», «。»), ни «@», «[» и второго
    адреса, а хост — не число (браузер читает «//1572395042» как IPv4). Такой хост — одно имя без домена."""
    text = unicodedata.normalize("NFKC", token)
    hosts = _URL_HOSTS.findall(text)
    return (
        not any(char in text for char in ".%。@[") and len(hosts) <= 1
        and not any(re.fullmatch(r"\d+|0x[0-9a-f]*", host, re.IGNORECASE) for host in hosts)
    )


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
        self.issued = set(state.issued.values())      # свои замены сущностей; имени узла целиком среди них нет
        self.fake_nets: set[int] = set()
        self.macs = {}
        self.own_hosts = {
            text.lower() for text, surrogate in state.surrogates.items()
            if surrogate.kind in ("host", "ip", "ip6")
        }
        # Метка, выданная адресу или имени узла вместо подмены (совпадение адресов, значение не того вида),
        # в хосте ссылки ведёт на наш же узел: «http://<IP_1>:8080/». Модель пишет её и без скобок.
        for text, surrogate in state.surrogates.items():
            if surrogate.kind == "label" and state.entities[surrogate.entity_id].type in _HOST_TYPES:
                bare = text.strip("<>[]").lower()
                self.own_hosts |= {bare, f"<{bare}>", f"&lt;{bare}&gt;"}
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
        self.tags: tuple[str, list[tuple[int, int]], list[int]] | None = None    # ответ и участки вне тегов

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
        """Не уведёт ли ссылка оригиналы на чужой узел. Наша — если наши все адреса внутри неё:
        за нашим адресом в том же атрибуте может стоять чужой (srcset, незакрытая кавычка,
        «?next=https://…»), а совпадение целиком дальше не проверяется. Значение без адреса —
        не ссылка (data="…" в коде), его восстанавливают как обычный текст. Ссылки на знаки раскрываются до
        разбора адреса, и цель должна быть нашей при каждом их прочтении (_readings)."""
        return all(self._is_own_reading(reading) for reading in _readings(target))

    def _is_own_reading(self, target: str) -> bool:
        target = re.sub(r"[\t\r\n]", "", target.strip())   # браузер выбрасывает их из адреса
        if target.lower().startswith("mailto:"):
            address = target[len("mailto:"):]
            return address in self.state.surrogates          # без параметров: в них может быть что угодно
        return all(self._host_is_ours(m.group(1)) for m in _URL_HOSTS.finditer(target) if m.group(1) is not None)

    def _outside_tags(self, text: str, position: int) -> bool:
        if self.tags is None or self.tags[0] is not text:
            first = text.find("<")
            spans = [(0, len(text) if first < 0 else first), *(m.span(1) for m in _OUTSIDE_TAGS.finditer(text))]
            self.tags = (text, spans, [start for start, _ in spans])
        _, spans, starts = self.tags
        i = bisect.bisect_right(starts, position) - 1
        return i >= 0 and position < spans[i][1]

    def _argument(self, m: re.Match[str]) -> bool:
        """Не атрибут тега, а именованный аргумент вызова в коде: «post(url, data="…")», «form(action="…")».
        Всё, что может оказаться атрибутом тега, — по-прежнему ссылка: и «<img alt=a, src=…», и сам по себе
        «src="…"» в тексте, который вставят в тег."""
        before = m.string[max(0, m.start() - 64):m.start()].rstrip()
        return before.endswith(("(", ",")) and self._outside_tags(m.string, m.start())

    def _foreign(self, m: re.Match[str]) -> bool:
        """Ведёт ли ссылка на чужой узел и есть ли в ней что восстанавливать."""
        if m.group("attr") is not None and self._argument(m):
            # Значение аргумента — строка кода: ссылки в нём проверяются как в обычном тексте, а найденная
            # чужая оставляет метки во всём значении.
            return any(self._foreign(inner) for inner in _LINK.finditer(m.string, m.start("attr"), m.end("attr")))
        target = next((
            m.group(name)
            for name in (
                "md", "ref", "dest", "attr", "unquoted", "css", "imp", "cssu", "set", "mailto", "dq", "sq", "url",
            )
            if m.group(name)
        ), "")
        # Экранирования CSS браузер раскрывает до загрузки — и в имени, и в адресе: «\2f\2f evil…» — это
        # «//evil…», «наш\40 evil…» — «наш@evil…». Хост, видный в тексте, тогда не тот, что загрузят, поэтому
        # ссылка CSS (url(), @import, image-set(), src(), атрибут style) с «\» нашей не бывает — и с «\»,
        # записанной ссылкой на знак: в атрибуте style «&bsol;2f» — это «\2f».
        css = any(m.group(name) is not None for name in ("css", "imp", "cssu", "set"))
        css = css or (m.group("name") or "").lower() == "style"
        if self._is_own(target) and not (css and any("\\" in reading for reading in _readings(m.group()))):
            return False        # ссылка на наш же узел восстанавливается как обычный текст
        restored = self._inner(m.group())
        if (
            target[:2] in ("//", "/\\", "\\/", "\\\\") and any(m.group("dq", "sq", "url"))
            and all(_nowhere(reading) for reading in _readings(restored))     # «&#46;» — тоже точка
        ):
            return False        # «//TODO:…» в коде: и после восстановления адрес не ведёт на внешний узел
        return restored != m.group()        # иначе — если в ней есть что восстанавливать

    def _link(self, m: re.Match[str]) -> Piece | None:
        if not self._foreign(m):
            return None
        self.counters["foreign_links"] += 1
        return m.group(), "foreign_link"

    def _fixed(self, surrogate: Surrogate | None) -> str | None:
        """Значение для восстановления, заданное пользователем (FR-6.4), если оно задано."""
        entity = self.state.entities[surrogate.entity_id] if surrogate else None
        return entity.restore_value if entity and entity.restore_rank == FIXED_RANK else None

    def _original(self, key: str, surrogate: Surrogate) -> str:
        """Оригинал замены. Значение, заданное пользователем, важнее записанного при выдаче. Имя узла целиком
        выдано не своей сущности, а составлено из замен частей — оно и собирается по частям."""
        fakes, parts = key.split("."), (surrogate.original or "").split(".")
        if surrogate.kind == "host" and key not in self.issued and 2 < len(fakes) <= len(parts):
            left = len(fakes) - 2           # части слева от domain-N.example; остальное — домен оригинала
            pairs = [*zip(fakes[:left], parts), (".".join(fakes[left:]), ".".join(parts[left:]))]
            return ".".join(self._fixed(self.state.surrogates.get(fake.lower())) or part for fake, part in pairs)
        if surrogate.original is None:
            return self.state.entities[surrogate.entity_id].restore_value       # метка
        return self._fixed(surrogate) or surrogate.original

    def _exact(self, m: surrogates.Hit) -> Piece:
        text = m.group()
        surrogate = self.state.surrogates[m.key]
        entity = self.state.entities[surrogate.entity_id]
        if self._hidden(entity.type):
            self.counters["kept"] += 1
            return text, "kept_by_policy"
        original = self._original(m.key, surrogate)
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
        if self._hidden(EntityType.IP):
            self.counters["kept"] += 1
            return m.group(), "kept_by_policy"
        original = netmap.unmap_private(int(ip), bits, self.state.net_key)
        self.counters["derived"] += 1
        return str(ipaddress.IPv4Address(original)), "derived"

    def _mac(self, m: re.Match[str]) -> Piece | None:
        surrogate = self.macs.get(macsid.mac_key(m.group()))
        if surrogate is None:
            return None
        if self._hidden(self.state.entities[surrogate.entity_id].type):
            self.counters["kept"] += 1
            return m.group(), "kept_by_policy"
        self.counters["altered"] += 1
        return self._original(m.group(), surrogate), "altered"


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


# Знаки, из которых состоит замена в любом допустимом виде записи: метки (в том числе «\<PERSON\_1\>»,
# «&lt;PERSON_1&gt;», «[[PERSON_1]]»), адреса с длиной префикса, IPv6, MAC, имена узлов.
_TOKEN_CHAR = re.compile(r"[\w.:/<>\[\]&;\-]")
_HOLD = 512


class StreamRestorer:
    """Потоковый режим (раздел 7): показывается восстановление префикса, в котором замена не может оборваться.

    Префикс кончается последним пробельным знаком. Хвост без пробелов длиннее 512 знаков (минифицированный
    JSON) отдаётся до последнего знака, который не входит ни в одну запись замены. feed возвращает весь
    показываемый текст, а не прирост: восстановление длинного префикса может изменить начало (ссылка,
    закрытая позже). Итог — finish(): полное восстановление всего ответа.
    """

    def __init__(self, state: ChatState, settings: Settings):
        self.state = state
        self.settings = settings
        self.text = ""
        self._cut = 0
        self._shown = ""

    def _safe_end(self) -> int:
        end = max(self.text.rfind(" "), self.text.rfind("\n"), self.text.rfind("\t"), self.text.rfind("\r")) + 1
        if len(self.text) - end > _HOLD:
            tail = self.text[end:]
            end += max((i + 1 for i, ch in enumerate(tail) if not _TOKEN_CHAR.match(ch)), default=0)
        return end

    def feed(self, chunk: str) -> str:
        self.text += chunk
        cut = self._safe_end()
        if cut != self._cut:
            self._cut = cut
            self._shown = restore(self.state, self.text[:cut], self.settings).text
        return self._shown

    def finish(self) -> RestoreResult:
        return restore(self.state, self.text, self.settings)
