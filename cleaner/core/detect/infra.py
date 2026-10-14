"""Слой 3: адреса, имена узлов, учётные записи, SID, LDAP-имена."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

from cleaner.core.detect.base import DetectContext
from cleaner.core.entities import hostmap, netmap
from cleaner.core.types import EntityType, Span

name = "infra"

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?!\w|\.\d)")
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
# Слово перед числом, по которому видно, что это номер версии; «ver» внутри «server» не считается.
_VERSION_BEFORE = re.compile(
    r"(?<![^\W\d_])(?:version|верси[яию]|ver\.?|build|сборка|release|v)\s*[:=]?\s*$", re.IGNORECASE
)
_MAC = re.compile(
    r"(?<![\w:.-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![\w:-])"
    r"|(?<![\w.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![\w.])"
)
_MAC_KEEP = frozenset({"ffffffffffff", "000000000000"})

# Длина схемы ограничена: без предела цепочка «a.b.a.b…» без «://» даёт квадратичный перебор.
_URL_HOST = re.compile(
    r"\b[a-z][a-z0-9+.-]{0,31}://(?:[^\s/@]+@)?(?P<host>[^\s/:?#\"'<>\[\]@]+)", re.IGNORECASE
)
# Двоеточие перед «\\» — это «C:\\Users» из журнала JSON, а не сетевой путь; путь из JSON — «\\\\host».
_UNC_HOST = re.compile(r"(?<![\\\w:])\\\\(?:\\\\)?(?P<host>[\w.-]+)(?=\\)")
_PARAM_HOST = re.compile(r"(?<![\w-])(?:-ComputerName|-Server|-cn|/S)[ \t]+(?P<host>[\w.-]+)", re.IGNORECASE)
_MACHINE = re.compile(r"(?<![\w.$-])(?P<host>(?=[A-Za-z-]*\d)[A-Za-z0-9][A-Za-z0-9-]{1,14})\$(?![\w$])")
_DOTTED = re.compile(r"(?<![\w.$@-])(?:\w(?:[\w-]{0,61}\w)?\.)+[^\W\d_][\w-]{1,62}(?![\w-]|\.\w)")

# Перед доменом может стоять двоеточие ключа команды («/user:CONTOSO\ivanov»); обратная косая
# бывает удвоена (журналы JSON).
_DOMAIN_LOGIN = re.compile(
    r"(?<![\w\\./-])(?P<dom>[A-Za-z][A-Za-z0-9-]{1,14})\\{1,2}(?P<login>[A-Za-z0-9_][\w.$-]{0,63})(?![\w\\])"
)
_FILE_EXT = re.compile(
    r"\.(?:txt|log|docx?|xlsx?|pptx?|pdf|exe|dll|ps1|psm1|bat|cmd|ini|cfg|conf|xml|json|ya?ml|csv|zip|7z|rar"
    r"|bak|tmp|sys|dat|msi|png|jpe?g|gif|lnk|reg|evtx?|py|sh|sql|db|mdb|pst|ost|html?)$",
    re.IGNORECASE,
)
# Имя профиля из двух-трёх слов с пробелами берётся целиком, если за ним идёт разделитель пути,
# кавычка, знак препинания перед пробелом или концом текста либо конец строки; иначе — до пробела,
# а знак препинания в конце отрезается.
_PROFILE = re.compile(
    r"(?:\b[a-z]:\\{1,2}Users\\{1,2}|(?<![\w.\\])\\{1,2}Users\\{1,2}|(?<![\w.])/home/|(?<![\w.])/Users/)"
    r"(?:(?P<spaced>[^\W\d_]+(?:-[^\W\d_]+)*(?: [^\W\d_]+(?:-[^\W\d_]+)*){1,2})"
    r"(?=[\\/\"'`]|[.,;:!?)]+(?:\s|$)|[ \t]*(?:\r?\n|$))"
    r"|(?P<login>[^\\/\s:*?\"<>|]+))",
    re.IGNORECASE,
)
_TRAILING = ".,;:!?)"
_SID = re.compile(r"(?<![\w-])S-1-5-21-\d+-\d+-\d+(?:-\d+)?(?![\w-])")
# Число компонентов ограничено: без предела цепочка «CN=a,CN=a,…» без DC даёт квадратичный перебор.
_DN = re.compile(
    r"(?<![\w=])(?:(?:CN|OU|O|L|ST|C)=[^,;\r\n\"<>=]+,\s*){1,16}DC=[\w-]+(?:,\s*DC=[\w-]+){0,8}"
    r"|(?<![\w=])DC=[\w-]+(?:,\s*DC=[\w-]+){1,8}",
    re.IGNORECASE,
)


def _ipv4(text: str) -> Iterator[Span]:
    for m in _IPV4.finditer(text):
        address, _, prefix = m.group().partition("/")
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if not netmap.is_maskable(ip) or _VERSION_BEFORE.search(text[max(0, m.start() - 16):m.start()]):
            continue
        end = m.start() + len(address)
        if prefix and int(prefix) < 24 and netmap.private_bits(ip) is not None:
            if int(ip) & ((1 << (32 - int(prefix))) - 1) == 0:
                end = m.end()       # адрес сети: длина префикса входит во фрагмент
        yield Span(m.start(), end, EntityType.IP, name, validated=True)


def _ipv6(text: str) -> Iterator[Span]:
    for m in _IPV6.finditer(text):
        candidate = m.group()
        if candidate.endswith(":") and not candidate.endswith("::"):
            candidate = candidate[:-1]      # двоеточие после адреса — знак препинания
        try:
            ip = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        if netmap.is_maskable(ip):
            yield Span(m.start(), m.start() + len(candidate), EntityType.IP, name, validated=True)


def _mac(text: str) -> Iterator[Span]:
    for m in _MAC.finditer(text):
        if re.sub(r"[^0-9A-Fa-f]", "", m.group()).lower() not in _MAC_KEEP:
            yield Span(m.start(), m.end(), EntityType.MAC, name, validated=True)


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def well_known(value: str, ctx: DetectContext) -> bool:
    """Общеизвестное имя или имя из списка «никогда не скрывать», включая поддомены."""
    parts = value.lower().strip(".").split(".")
    listed = ctx.builtin.well_known_domains | ctx.settings.never
    if len(parts) == 1:
        return parts[0] in listed or parts[0] in ctx.builtin.generic_labels
    return any(".".join(parts[i:]) in listed for i in range(len(parts)))


def _name_type(value: str) -> EntityType:
    left, registrable = hostmap.split_name(value)
    return EntityType.DOMAIN if registrable and not left else EntityType.HOST


def _plausible(value: str, text: str, end: int, ctx: DetectContext) -> bool:
    """Имя с точками вне сетевого контекста: похоже ли оно на узел, а не на код или файл."""
    labels = value.split(".")
    if any(label != label.lower() and label != label.upper() for label in labels):
        return False        # смешанный регистр внутри части: System.Net
    if all(label.isdigit() for label in labels[:-1]):
        return False        # номер версии: 1.2.3.dev
    if labels[-1].lower() in ctx.builtin.ambiguous_suffixes:
        return False        # расширение файла или слово из кода
    if text[end:end + 1] == "(":
        return False        # вызов метода
    return hostmap.has_known_suffix(value)


def _hosts(text: str, ctx: DetectContext) -> Iterator[Span]:
    for pattern in (_URL_HOST, _UNC_HOST, _PARAM_HOST):
        for m in pattern.finditer(text):
            value = m.group("host").rstrip(".,;!)")     # «…contoso.ru, пароль спроси»
            if not re.fullmatch(r"[\w.-]+", value) or _is_address(value) or well_known(value, ctx):
                continue
            start = m.start("host")
            yield Span(start, start + len(value), _name_type(value), name)
    for m in _MACHINE.finditer(text):
        if not m.group("host").isdigit():
            yield Span(m.start("host"), m.end("host"), EntityType.HOST, name)
    for m in _DOTTED.finditer(text):
        value = m.group()
        if not well_known(value, ctx) and _plausible(value, text, m.end(), ctx):
            yield Span(m.start(), m.end(), _name_type(value), name)


def _accounts(text: str, ctx: DetectContext) -> Iterator[Span]:
    builtin = ctx.builtin.builtin_accounts
    known_domains = {form.lower() for form, type_ in ctx.known if type_ is EntityType.DOMAIN}
    for entry in ctx.settings.always:
        if entry.type is EntityType.DOMAIN:
            known_domains.update(form.lower() for form in (entry.value, *entry.aliases))
    for m in _DOMAIN_LOGIN.finditer(text):
        dom, login = m.group("dom"), m.group("login").rstrip(".-")
        if dom.lower() in builtin or not (dom.isupper() or dom.lower() in known_domains):
            continue
        if not login or _FILE_EXT.search(login) or (login[0] in "ntr" and login[1:2].isupper()):
            continue        # путь к файлу или экранированный перевод строки, а не учётная запись
        yield Span(m.start("dom"), m.end("dom"), EntityType.DOMAIN, name)
        if login.lower() not in builtin:
            start = m.start("login")
            yield Span(start, start + len(login), EntityType.ACCOUNT, name)
    for m in _PROFILE.finditer(text):
        group = "spaced" if m.group("spaced") else "login"
        login = m.group(group).rstrip(_TRAILING)
        if login and login.lower() not in builtin and not re.search(r"[%$]", login):
            start = m.start(group)
            yield Span(start, start + len(login), EntityType.ACCOUNT, name)


def detect(text: str, ctx: DetectContext) -> list[Span]:
    spans = [*_ipv4(text), *_ipv6(text), *_mac(text), *_hosts(text, ctx), *_accounts(text, ctx)]
    spans += [Span(m.start(), m.end(), EntityType.SID, name, validated=True) for m in _SID.finditer(text)]
    spans += [Span(m.start(), m.end(), EntityType.DN, name) for m in _DN.finditer(text)]
    return spans
