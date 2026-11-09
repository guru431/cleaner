"""Слой 3: адреса, имена узлов, учётные записи, SID, LDAP-имена."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from functools import lru_cache

from cleaner.core.detect.base import DetectContext
from cleaner.core.entities import hostmap, netmap
from cleaner.core.entities.labels import SHAPE as _LABEL
from cleaner.core.types import EntityType, Span

name = "infra"

# Адрес в регулярном выражении, правиле nginx, шаблоне grep пишут через «\.» («^10\.1\.2\.35$»), внутри строки JSON,
# Java, C# — через «\\.» (hostmap.dotted); все три разделителя одного вида.
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(\\{0,2}\.)\d{1,3}\1\d{1,3}\1\d{1,3}(?:/\d{1,2})?(?!\w|\\{0,2}\.\d)")
# Адрес не начинается внутри другой записи через двоеточие, но может стоять сразу за подписью
# («Source:f54a:…», «IPv6:2a00:…»): за словом, которое не может быть группой адреса, — с буквой
# не из 0-9a-f или длиннее четырёх знаков. Подпись во фрагмент не входит. Последние 32 бита бывают записаны адресом IPv4
# («::ffff:10.20.30.40», NAT64 «64:ff9b::10.1.2.3») — адрес целиком, а не «::ffff:10» и число за ним.
_IPV6 = re.compile(
    r"(?<![\w:.])(?:(?=\w*[^\W\dA-Fa-f])\w+:|\w{5,}:)?"
    r"(?P<addr>(?:[0-9A-Fa-f]{0,4}:){2,6}\d{1,3}(?:\.\d{1,3}){3}(?![\w.])"
    r"|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:]))"
)
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
# Двоеточие перед «\\» — это «C:\\Users» из журнала JSON, а не сетевой путь; путь из JSON — «\\\\host». Имя узла не
# начинается с точки, и за ним — ресурс, а не точка выражения: «\\bportal\\.contoso» и «.*\\.corp\\.» — выражение в строке
# JSON (_ESCAPED), а не узлы «bportal» и «.corp».
_UNC_HOST = re.compile(r"(?<![\\\w:])\\\\(?:\\\\)?(?P<host>\w[\w.-]*)(?=\\(?!\\?\.))")
_HOST_PREFIX = re.compile(r"[\w.-]*")     # имя узла без знаков за ним: «», «”», «**», «}», «…»
# Буква диска после ключа — не узел («dir /s C:\Temp»). Узел бывает в кавычках, через двоеточие («-ComputerName:PC07») и
# списком через запятую («-ComputerName SRV01,SRV02», «'SRV01', 'SRV02'»): фрагмент — каждый узел. Пробел после запятой —
# только перед кавычкой: «-ComputerName WS-0142, затем …» — продолжение текста, а не узел.
_HOST_ITEM = r"[\"']?(?![a-z]:)[\w.-]+[\"']?"
_HOST_LIST = rf"(?P<hosts>{_HOST_ITEM}(?:,(?:[ \t]*(?=[\"']))?{_HOST_ITEM})*)"
_LIST_HOST = re.compile(r"[\w.-]+")
_PARAM_HOST = re.compile(rf"(?<![\w-])(?:-ComputerName|-Server|-cn)(?::|[ \t]+){_HOST_LIST}", re.IGNORECASE)
# «/S имя» — компьютер только у команд, которые принимают его этим ключом, и в той же команде: у dir,
# xcopy, findstr, del, robocopy, reg «/S» — подкаталоги («dir /s logs»), у shutdown — выключение.
# Аргументов до ключа не больше тридцати: иначе цепочка «schtasks schtasks …» без ключа давала бы
# квадратичный перебор.
_REMOTE_SWITCH = re.compile(
    r"(?<![\w-])(?:schtasks|systeminfo|tasklist|taskkill|gpresult|getmac|driverquery|eventcreate|openfiles"
    rf"|waitfor|setx|takeown)(?:\.exe)?(?:[ \t]+[^\s|&;]+){{0,30}}?[ \t]+/S[ \t]+{_HOST_LIST}",
    re.IGNORECASE,
)
_MACHINE = re.compile(r"(?<![\w.$-])(?P<host>(?=[A-Za-z-]*\d)[A-Za-z0-9][A-Za-z0-9-]{1,14})\$(?![\w$])")
# Начало имени. Имя начинается и после точки за знаком, который не часть имени («*.contoso.ru» сертификата и DNS,
# «domain=.contoso.ru» cookie, «no_proxy=.contoso.ru,.corp.local», «${env}.contoso.ru»), но не после «/» и «\» с точкой —
# это файл на точку в пути («~/.env.local», «C:\Users\ivanov\.local»); и после «@» без имени входа перед ним («все
# адреса @contoso.ru»): адрес e-mail целиком — дело слоя 1. Ведущие «.», «*.», «@» во фрагмент не входят.
_START = r"(?<![\w$-])(?<![\w\\/-]\.)(?<![\w.+-]@)"
_DOTTED = re.compile(rf"{_START}(?:\w(?:[\w-]{{0,61}}\w)?\.)+[^\W\d_][\w-]{{1,62}}(?![\w-]|\.\w)")
# Файл на точку — не имя, хотя его части похожи на имя: «.env.local», «.env.dev», «.zshrc.local», «.tmux.conf.local».
# Первая часть — имя такого файла (_dotfile), а за ней одна часть или настройки «…local».
_DOTFILE = re.compile(r"\w*env|\w{3,}rc|\w*config|\w*profile|aliases|tmux", re.IGNORECASE)
# Имя в регулярном выражении, шаблоне grep, настройке nginx — части через «\.», бывает и вперемешку с точками
# («^www\.contoso\.ru$»); внутри строки JSON, Java, C# то же выражение пишут через «\\.» («"^www\\.contoso\\.ru$"»,
# hostmap.dotted). Цепочка начинается и после «\.» или точки за знаком выражения («.*\.contoso\.ru»,
# «(.+)\.contoso\.ru»), но не после «\»: в «C:\Users\ivanov\.local» «\» — разделитель пути, а «.local» — папка профиля, и
# в JSON («C:\\Users\\ivanov\\.local») так же. Берутся только цепочки с «\.» или «\\.»: остальные — дело _DOTTED.
_ESCAPED_CHAIN = r"(?:\w(?:[\w-]{0,61}\w)?\\{0,2}\.)+[^\W\d_][\w-]{1,62}(?![\w-]|\\{0,2}\.\w)"
_ESCAPED = re.compile(rf"(?<![\w$\\-])(?<![\w-]\.)(?<![\w-]\\\.)(?<![\w-]\\\\\.){_ESCAPED_CHAIN}")
# Имя между границами слова выражения («\bcontoso\.ru\b», в строке — «\\bcontoso\\.ru\\b»): «b» — не часть имени.
# Только парой: «\bob\.local» в «C:\Users\bob\.local» — путь.
_BOUNDED = re.compile(rf"(?<=\\b)(?<!\\\\\\b){_ESCAPED_CHAIN}(?=\\{{1,2}}b(?!\w))")
# Имя, часть которого — метка: части, которой пользователь дал другой тип, выдана метка (<TERM_1>.domain-1.example,
# host-1.<ORG_1>). Рядом с ней может стоять настоящее имя: «<TERM_1>.fabrikam.ru», «srv-db02.<TERM_1>.domain-1.example»,
# и через «\.» тоже.
_PART = rf"(?:[\w-]+|{_LABEL.pattern})"
_LABELLED = re.compile(rf"{_START}(?:{_PART}\\{{0,2}}\.)*(?:{_LABEL.pattern})(?:\\{{0,2}}\.{_PART})*")
_LABEL_BEFORE = re.compile(rf"(?:{_LABEL.pattern})\\{{0,2}}\.$")
_NAME_PART = re.compile(r"[^.\\]+")         # часть имени через «.», «\.» или «\\.» — и метка

# Перед доменом может стоять двоеточие ключа команды («/user:CONTOSO\ivanov»); обратная косая
# бывает удвоена (журналы JSON). Имя входа может быть и кириллицей («CORP\иванов»). Косая после входа —
# продолжение пути, а не учётная запись; в строке JSON (косая удвоена) путь — снова «\\», а одна косая —
# экранирование: «CONTOSO\\ivanov\r\n» — вывод команды, который Codex отдаёт строкой JSON (приёмка 5В).
# В адресе и журнале веб-сервера косая записана «%5C» («user=CONTOSO%5Civanov»); «%5C» после входа — путь.
_DOMAIN_LOGIN = re.compile(
    r"(?<![\w\\./-])(?P<dom>[A-Za-z][A-Za-z0-9-]{1,14})"
    r"(?:\\(?P<login>\w[\w.$-]{0,63})(?![\w\\])|\\\\(?P<jlogin>\w[\w.$-]{0,63})(?!\w|\\\\)"
    r"|%5[Cc](?P<ulogin>\w[\w.$-]{0,63})(?![\w\\]|%5[Cc]))"
)
# Корни реестра в коротком виде («reg query HKLM\Software /s») — не домены, а раздел за ними — не вход.
# Длинные («HKEY_LOCAL_MACHINE\…») шаблон домена не берёт: в нём нет «_».
_REGISTRY_HIVES = frozenset({"hklm", "hkcu", "hkcr", "hku", "hkcc"})
_FILE_EXT = re.compile(
    r"\.(?:txt|log|docx?|xlsx?|pptx?|pdf|exe|dll|ps1|psm1|bat|cmd|ini|cfg|conf|xml|json|ya?ml|csv|zip|7z|rar"
    r"|bak|tmp|sys|dat|msi|png|jpe?g|gif|lnk|reg|evtx?|py|sh|sql|db|mdb|pst|ost|html?)$",
    re.IGNORECASE,
)
# Имя профиля из двух-трёх слов с пробелами берётся целиком, если за ним идёт разделитель пути,
# кавычка, знак препинания перед пробелом или концом текста либо конец строки; иначе — до пробела,
# а знак препинания и кавычка в конце отрезаются. Дефис и апостроф между буквами — внутри слова
# («Petrov-Vodkin», «O'Brien», «Il'ya»), апостроф перед буквой закрывающей кавычкой не считается.
# Диск в записи Git Bash и MSYS — «/c/Users/», WSL — «/mnt/c/Users/», Cygwin — «/cygdrive/c/Users/».
_PROFILE = re.compile(
    r"(?:\b[a-z]:\\{1,2}Users\\{1,2}|(?<![\w.\\])\\{1,2}Users\\{1,2}|(?<![\w.])/home/|(?<![\w.])/Users/"
    r"|(?<![\w.])(?:/mnt|/cygdrive)?/[a-z]/Users/)"
    r"(?:(?P<spaced>[^\W\d_]+(?:[-'’][^\W\d_]+)*(?: [^\W\d_]+(?:[-'’][^\W\d_]+)*){1,2})"
    r"(?=[\\/\"`]|['’](?![^\W\d_])|[.,;:!?)]+(?:\s|$)|[ \t]*(?:\r?\n|$))"
    r"|(?P<login>[^\\/\s:*?\"<>|]+))",
    re.IGNORECASE,
)
_TRAILING = ".,;:!?)'’"
# Логин-заглушка в примере пути («/Users/name/», «C:\Users\username\» в описаниях инструментов агентов) — не учётная запись.
_PROFILE_PLACEHOLDERS = frozenset(
    {"name", "username", "user", "yourname", "your_name", "you", "login", "имя", "логин", "пользователь"}
)
_SID = re.compile(r"(?<![\w-])S-1-5-21-\d+-\d+-\d+(?:-\d+)?(?![\w-])")
# Число компонентов ограничено: без предела цепочка «CN=a,CN=a,…» без DC даёт квадратичный перебор. Знак значения
# бывает экранирован (RFC 4514): «CN=Ivanov\, Ivan» — фамилия и имя, в строке JSON — «\\,». Значение берётся без отката
# («++»): иначе разбиения цепочки обратных косых перебирались бы.
_DN = re.compile(
    r"(?<![\w=])(?:(?:CN|OU|O|L|ST|C)=(?:\\{1,2}[^\r\n]|[^\\,;\r\n\"<>=])++,\s*){1,16}DC=[\w-]+(?:,\s*DC=[\w-]+){0,8}"
    r"|(?<![\w=])DC=[\w-]+(?:,\s*DC=[\w-]+){1,8}",
    re.IGNORECASE,
)


def _ipv4(text: str) -> Iterator[Span]:
    for m in _IPV4.finditer(text):
        address, _, prefix = m.group().partition("/")
        try:
            ip = netmap.parse(address)[0]
        except ValueError:
            continue
        if not netmap.is_maskable(ip) or _VERSION_BEFORE.search(text[max(0, m.start() - 16):m.start()]):
            continue
        end = m.start() + len(address)
        if prefix and int(prefix) < 24 and netmap.private_bits(ip) is not None:
            if int(ip) & ((1 << (32 - int(prefix))) - 1) == 0:
                if int(prefix) <= netmap.private_bits(ip):
                    # Частный диапазон целиком («10.0.0.0/8») ничего не выдаёт, как документационные, а его подмена — он
                    # сам: перестановка не трогает неизменные биты диапазона, и он всегда становился бы меткой.
                    continue
                end = m.end()       # адрес сети: длина префикса входит во фрагмент
        yield Span(m.start(), end, EntityType.IP, name, validated=True)


def _ipv6(text: str) -> Iterator[Span]:
    for m in _IPV6.finditer(text):
        candidate = m.group("addr")
        if candidate.endswith(":") and not candidate.endswith("::"):
            candidate = candidate[:-1]      # двоеточие после адреса — знак препинания
        try:
            ip = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        if ip.ipv4_mapped is not None:
            continue        # «::ffff:» и адрес IPv4: адрес находит _ipv4 — та же сущность, что без «::ffff:», петля открыта
        if netmap.is_maskable(ip):
            start = m.start("addr")
            yield Span(start, start + len(candidate), EntityType.IP, name, validated=True)


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


@lru_cache(maxsize=16)
def _longest(listed: frozenset[str]) -> int:
    return max(map(len, listed), default=0)


def well_known(value: str, ctx: DetectContext) -> bool:
    """Общеизвестное имя или имя из списка «никогда не скрывать», включая поддомены. Суффиксы сверяются справа и не
    длиннее самого длинного значения списков: цепочка из тысяч частей («abc.def.…») иначе проверялась бы
    квадратичное время. «\\.» и «\\\\.» — точка."""
    name = hostmap.dotted(value.lower()).strip(".")
    known, never = ctx.builtin.well_known_domains, ctx.settings.never
    if "." not in name:
        return name in known or name in never or name in ctx.builtin.generic_labels
    longest = max(_longest(known), _longest(never))
    end = len(name)
    while end >= 0:
        dot = name.rfind(".", 0, end)
        if len(name) - dot - 1 > longest:
            return False
        suffix = name[dot + 1:]
        if suffix in known or suffix in never:
            return True
        end = dot
    return False


def _under_issued(value: str, ctx: DetectContext) -> bool:
    """Имя под выданной чатом подменой домена («srv-db02.domain-1.example») или под меткой доменного имени
    («srv-db02.<ORG_1>» рядом с host-1.<ORG_1>, labels.domain_labels): «example» в нём общеизвестно, но части перед подменой
    вписал человек — это настоящие имена. Выданные части («host-1») и общеизвестные («www») конвейер оставляет
    как есть (pipeline._outside)."""
    parts = value.lower().split(".")
    return (len(parts) > 2 and ".".join(parts[-2:]) in ctx.issued_domains) or (
        len(parts) > 1 and parts[-1] in ctx.issued_domains      # метка — одна часть
    )


def _with_issued(value: str, ctx: DetectContext) -> bool:
    """В имени стоит выданная замена — подмена части («Petrov.host-1.fabrikam.ru»), домена или метка доменного имени: это
    имя, которое пользователь вписал рядом с ней, а не код, и признаки кода (_plausible) к нему не применяются."""
    parts = value.lower().split(".")
    return any(part in ctx.issued_names or part in ctx.issued_domains for part in parts) or any(
        f"{part}.{after}" in ctx.issued_domains for part, after in zip(parts, parts[1:])
    )


def _name_type(value: str) -> EntityType:
    left, registrable = hostmap.split_name(value)
    return EntityType.DOMAIN if registrable and not left else EntityType.HOST


def _plausible(value: str, text: str, end: int, ctx: DetectContext) -> bool:
    """Имя с точками вне сетевого контекста: похоже ли оно на узел, а не на код или файл."""
    if hostmap.code_like(value, ctx.builtin.ambiguous_suffixes) or text[end:end + 1] == "(":
        return False        # System.Net, 1.2.3.dev, README.md, вызов метода
    return hostmap.has_known_suffix(value)


def _dotfile(value: str) -> bool:
    """Имя, которое стоит после точки, — файл на точку (_DOTFILE): «.env.local», «.env.dev», «.tmux.conf.local». Имя под
    доменом с публичным суффиксом («.env.contoso.ru») — имя."""
    labels = value.split(".")
    return bool(_DOTFILE.fullmatch(labels[0])) and (len(labels) == 2 or labels[-1].lower() == "local")


def _plain_runs(value: str, start: int) -> Iterator[tuple[int, int]]:
    """Позиции цепочек обычных частей имени между метками; value — имя, как написано (через «.», «\\.» или «\\\\.»), start
    — его позиция в тексте."""
    run = end = None
    for part in _NAME_PART.finditer(value):
        if _LABEL.fullmatch(part.group()):
            if run is not None:
                yield run, end
            run = None
            continue
        if run is None:
            run = start + part.start()
        end = start + part.end()
    if run is not None:
        yield run, end


def _named(m: re.Match) -> Iterator[tuple[int, str]]:
    """Позиции и записи узлов совпадения: один узел или каждый узел списка (_HOST_LIST)."""
    if m.re.groupindex.get("hosts") is None:
        yield m.start("host"), m.group("host")
        return
    for host in _LIST_HOST.finditer(m.group("hosts")):
        yield m.start("hosts") + host.start(), host.group()


def _hosts(text: str, ctx: DetectContext) -> Iterator[Span]:
    for pattern in (_URL_HOST, _UNC_HOST, _PARAM_HOST, _REMOTE_SWITCH):
        for m in pattern.finditer(text):
            for start, host in _named(m):
                value = _HOST_PREFIX.match(host).group().rstrip(".")     # «…contoso.ru», «…ru,»
                if not re.fullmatch(r"[\w.-]+", value) or _is_address(value):
                    continue
                if well_known(value, ctx) and not _under_issued(value, ctx):
                    continue
                yield Span(start, start + len(value), _name_type(value), name)
    for m in _MACHINE.finditer(text):
        if not m.group("host").isdigit():
            yield Span(m.start("host"), m.end("host"), EntityType.HOST, name)
    escaped = "\\." in text
    for pattern in (_DOTTED, _ESCAPED, _BOUNDED) if escaped else (_DOTTED,):
        for m in pattern.finditer(text):
            value = hostmap.dotted(m.group())       # проверки — как у имени через точку
            if pattern is not _DOTTED and value == m.group():
                continue
            if text[m.start() - 1:m.start()] == "." and (
                _dotfile(value) or _LABEL_BEFORE.search(text, max(0, m.start() - 40), m.start())
            ):
                continue        # файл на точку; имя после метки ищет _LABELLED
            if _under_issued(value, ctx) or (not well_known(value, ctx) and (
                _plausible(value, text, m.end(), ctx) or (_with_issued(value, ctx) and hostmap.has_known_suffix(value))
            )):
                yield Span(m.start(), m.end(), _name_type(value), name)
    # Имя с меткой — если оно под выданной подменой домена (или меткой домена) либо после последней метки стоит имя
    # с точкой, как у _DOTTED; «<PERSON_1>.docx» и «<ORG_1>.ru» — не имена. Фрагменты — цепочки частей между метками:
    # фрагмент с меткой правило пользователя поглотило бы целиком вместе с ней (5.7), а выданную замену в цепочке
    # отрежет конвейер (pipeline._outside).
    for m in _LABELLED.finditer(text):
        value = hostmap.dotted(m.group())
        if "." not in value or len(value) > 253:
            continue        # метка сама по себе; длиннее имени DNS — не имя, а проверка частей квадратична
        parts = value.split(".")
        last = max(i for i, part in enumerate(parts) if _LABEL.fullmatch(part))
        tail = ".".join(parts[last + 1:])
        if not _under_issued(value, ctx) and not ("." in tail and not well_known(tail, ctx) and (
            _plausible(tail, text, m.end(), ctx) or (_with_issued(value, ctx) and hostmap.has_known_suffix(tail))
        )):
            continue
        for start, end in _plain_runs(m.group(), m.start()):
            run = hostmap.dotted(text[start:end])
            if _under_issued(run, ctx) or not well_known(run, ctx):      # «www», выданный «domain-1.example» — нет
                yield Span(start, end, EntityType.HOST, name)


def _accounts(text: str, ctx: DetectContext) -> Iterator[Span]:
    builtin = ctx.builtin.builtin_accounts
    known_domains = {form.lower() for form, type_ in ctx.known if type_ is EntityType.DOMAIN}
    for entry in ctx.settings.always:
        if entry.type is EntityType.DOMAIN:
            known_domains.update(form.lower() for form in (entry.value, *entry.aliases))
    # Имя NetBIOS домена Active Directory обычно — первая часть его имени DNS: «contoso» у «contoso.ru».
    known_domains.update([name.split(".", 1)[0] for name in known_domains if "." in name])
    for m in _DOMAIN_LOGIN.finditer(text):
        group = next(group for group in ("login", "jlogin", "ulogin") if m.group(group) is not None)
        dom, login = m.group("dom"), m.group(group).rstrip(".-")
        if dom.lower() in builtin or dom.lower() in _REGISTRY_HIVES or not (dom.isupper() or dom.lower() in known_domains):
            continue
        if not login or _FILE_EXT.search(login) or (login[0] in "ntr" and login[1:2].isupper()):
            continue        # путь к файлу или экранированный перевод строки, а не учётная запись
        if len(login) == 1:
            continue        # «DONE\\n», «\d» в шаблоне; написание из одной буквы скрывалось бы во всём чате
        yield Span(m.start("dom"), m.end("dom"), EntityType.DOMAIN, name)
        if login.lower() not in builtin:
            start = m.start(group)
            yield Span(start, start + len(login), EntityType.ACCOUNT, name)
    for m in _PROFILE.finditer(text):
        group = "spaced" if m.group("spaced") else "login"
        login = m.group(group).rstrip(_TRAILING)
        if (
            login and login.lower() not in builtin and login.lower() not in _PROFILE_PLACEHOLDERS
            and not re.search(r"[%$]", login)
        ):
            start = m.start(group)
            yield Span(start, start + len(login), EntityType.ACCOUNT, name)


def detect(text: str, ctx: DetectContext) -> list[Span]:
    spans = [*_ipv4(text), *_ipv6(text), *_mac(text), *_hosts(text, ctx), *_accounts(text, ctx)]
    spans += [Span(m.start(), m.end(), EntityType.SID, name, validated=True) for m in _SID.finditer(text)]
    spans += [Span(m.start(), m.end(), EntityType.DN, name) for m in _DN.finditer(text)]
    return spans
