"""Слой 2: учётные записи и пары «логин / пароль» по контексту.

Учётная запись — значение ключа входа (логин, login, user, username, User Id), слово после «логин», имя в журнале
Windows («Account Name:» рядом с «Account Domain:») и в строке sshd («Failed password for … from», «Invalid user … from»).
Пара — «логин / пароль» и «логин:пароль» после слов «доступ», «учётка», «креды»; пароль скрывается, только если похож на
пароль. Имя входа — латиницей; адрес e-mail, «ДОМЕН\\логин» и путь профиля находят слои 1 и 3."""
from __future__ import annotations

import bisect
import re

from cleaner.core.detect.base import DetectContext
from cleaner.core.detect.rules import _URL_SERVICE_LOGINS
from cleaner.core.detect.secrets import (
    _CURL, _NET_USER, _PROSE_WORDS, _TRAILING, _looks_like_password, _net_user_password, _value as _secret_value,
)
from cleaner.core.types import EntityType, Span

name = "secrets"

# Имя входа: латиница, цифры, «.», «_», «-»; не кончается точкой или дефисом.
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9_])?")
# Слово ключа входа в конце имени ключа: «login», «DB_USER», «dbUser», «user_name», «User Id», «логин». Имя ключа целиком
# досчитывается назад кодом (_key_start): выражение, начатое с имени, пробовалось бы с каждой буквы текста.
_ACCOUNT_KEY = re.compile(
    r"(?P<word>[uUlLлЛ](?:(?<=[uU])(?i:ser(?:[ _.-]?(?:name|id))?|id)|(?<=[lL])(?i:ogin)|(?<=[лЛ])(?i:огин)))"
    r"(?![\w.-])(?P<quote>[\"']?)[ \t]*+(?P<sep>[:=])[ \t]*+"
)
# Ключи с тем же словом, которые хранят не имя: время и число входов, флаги.
_NOT_ACCOUNT_KEY = re.compile(
    r"(?:last|first|max|min|num|count|total|failed|allow\w*|require\w*|enable\w*|disable\w*|is|has|can)"
    r"[_.-]?(?:user(?:[ _.-]?(?:name|id))?|uid|login)",
    re.IGNORECASE,
)
_KEY_CHARS = re.compile(r"[\w.-]")
# Значение: в кавычках или до пробела и знаков кода.
_VALUE = re.compile(r"\"(?P<dq>[^\"\r\n]{1,64})\"|'(?P<sq>[^'\r\n]{1,64})'|(?P<bare>[^\s\"'<>,;&|(){}\[\]]{1,64}+)")
# После «user:», «login:» без приставки в переписке и комментариях стоит фраза («User: Can you help me?»): значение —
# последнее на строке (и перед «\n» строки JSON) или перед знаком конца поля.
_LINE_END = re.compile(r"[ \t]*+(?:[,;\"'}\])&]|\r?\n|\\[nr]|$)")
# Слова, которые после ключа входа стоят вместо имени: типы, ключевые слова, заглушки, приветствия и названия служб.
_NOT_LOGIN = _PROSE_WORDS | frozenset({
    "str", "string", "int", "bool", "boolean", "any", "object", "dict", "list", "none", "null", "nil", "undefined",
    "bytes", "float", "tuple", "set", "union", "sequence", "mapping", "path", "uuid", "foo", "bar", "baz",
    "true", "false", "yes", "no", "on", "off", "required", "optional", "enabled", "disabled", "user", "users",
    "username", "login", "name", "id", "uid", "me", "self", "current", "anonymous", "unknown", "example", "demo",
    "password", "pass", "secret", "text", "value", "hello", "hi", "hey", "thanks", "ok", "okay", "test",
    "email", "mail", "windows", "vpn", "ad", "ldap", "sso", "domain", "local", "na", "agent",
})
# Учётные записи дистрибутивов, служб и образов по умолчанию — не имя человека или организации, как стандартные имена
# Windows из builtin_accounts.txt: «ansible_user: ubuntu» иначе скрывал бы Ubuntu во всём чате. Список — здесь, а не в
# общем файле: тот же файл решает и пути профиля слоя 3 («/home/ubuntu/»).
_SERVICE_ACCOUNTS = frozenset({
    "sa", "ubuntu", "centos", "debian", "fedora", "ec2-user", "azureuser", "vagrant", "pi", "postgres", "mysql",
    "mariadb", "oracle", "redis", "mongodb", "nginx", "www-data", "apache", "httpd", "git", "gitlab-runner", "jenkins",
    "docker", "node", "daemon", "bin", "sys", "ftp", "sshd", "mail", "elastic", "kibana", "grafana", "prometheus",
})
# Первое имя атрибута в коде: «request.user», «self.login», «config.db_user».
_CODE_OBJECTS = frozenset({
    "self", "this", "cls", "request", "req", "ctx", "context", "config", "cfg", "settings", "os", "env", "process",
    "options", "opts", "args", "params", "session", "auth", "g", "current", "user", "data", "form", "props",
})
_CAMEL = re.compile(r"[a-z][A-Z]")
_CONSTANT = re.compile(r"[A-Z0-9]+(?:_[A-Z0-9]+)+")
# Искомым написанием чата становится имя с цифрой, знаком или от пяти знаков: «user: app» иначе скрывал бы слово app во
# всех текстах чата.
_SPECIFIC = re.compile(r"[0-9._-]|.{5}")

# «логин ivanov», «логином i.petrova», «логин — ivanov» (после «:» и «=» — правило ключа).
_LOGIN_WORD = re.compile(r"[лЛ](?<!\w[лЛ])(?i:огин(?:а|у|ом|е|ы)?)(?:[ \t]*+[—–][ \t]*+|[ \t]++(?:-[ \t]++)?)")
# Журнал безопасности Windows: «Account Name:» и «Account Domain:» одного блока (русский журнал — «Имя учетной записи:»,
# «Домен учетной записи:»). Без второго поля рядом «Account Name:» — скорее имя владельца счёта. Значение — одно слово
# до конца строки: «NT AUTHORITY», «Window Manager» — служебные.
_EVENT_LABEL = re.compile(r"A(?<!\wA)ccount (?P<en>Name|Domain):|(?P<ru>Имя|Домен) уч[её]тной записи:")
_EVENT_VALUE = re.compile(r"[ \t]*+(?P<value>\S++)[ \t]*+(?=\r?\n|$)")
_EVENT_DISTANCE = 400
_EVENT_SERVICE = re.compile(r"-|(?i:dwm|umfd)-\d+|.*\$")
# sshd: «Failed password for [invalid user] имя from», «Invalid user имя from», «Accepted publickey for имя from»,
# «session opened for user имя(uid=…)». В журнале нападений учётные записи — все подбираемые имена.
_SSHD = re.compile(
    r"(?:(?:F(?<!\wF)ailed|A(?<!\wA)ccepted) [\w/-]++ for (?:invalid user )?|I(?<!\wI)nvalid user )(?P<login>[^\s(]++) from "
    r"|s(?<!\ws)ession (?:opened|closed) for user (?P<session>[^\s(]++)"
)
# Пара после «доступ», «учётка», «креды» (существительные: «доступен по адресу» — не они): до трёх слов, «:», тире или
# пробел, имя, «/» или «:» и пароль до пробела. «:», «/», «\» в пароль не входят: «доступен по адресу cdf:742b:2e85:…»
# (IPv6), время, путь и адрес — не пары.
_PAIR = re.compile(
    r"[дДуУкКcC](?<!\w[дДуУкКcC])(?i:(?<=[дД])оступ(?:а|у|ом|е|ы|ов|ам|ами|ах)?|(?<=[уУ])ч[её]тк(?:а|и|у|ой|е)?"
    r"|(?<=[кК])ред(?:ы|ов|ами|ах|ам)?|(?<=[cC])reds)(?!\w)"
    r"(?:[ \t]++[^\s:/]++){0,3}?(?:[ \t]*+[:—–=][ \t]*+|[ \t]++)"
    r"(?P<login>[A-Za-z0-9][\w.-]{0,63}+)(?:[ \t]*+/[ \t]*+|:)(?P<password>[^\s/\\:]{1,128}+)(?=\s|$)"
)


def _key_start(text: str, end: int) -> int:
    """Начало имени ключа, которое кончается в end. Буква «\\n», «\\t», «\\r» строки JSON перед ним — не часть имени."""
    start = end
    while start > 0 and _KEY_CHARS.match(text, start - 1):
        start -= 1
    if start > 0 and text[start - 1] == "\\" and start < end and text[start] in "ntr":
        start += 1
    return start


def _before(text: str, position: int) -> str:
    """Знак перед position без пробелов, переводов строки и кавычек — до 64 знаков назад."""
    for i in range(position - 1, max(-1, position - 65), -1):
        if text[i] not in " \t\r\n\"'":
            return text[i]
    return ""


def _login(value: str, ctx: DetectContext, english: bool) -> bool:
    """value — имя входа, а не слово, тип, код или служебная запись. english — ключ или слово латиницей («user»,
    «login») или слово перед именем («логин Windows»): там слово с заглавной без цифр и знаков («User», «Hello») — тип
    или слово, а не имя."""
    lowered = value.lower()
    if (
        not _LOGIN.fullmatch(value) or not any(c.isalpha() for c in value) or lowered in _NOT_LOGIN
        or lowered in ctx.builtin.builtin_accounts or lowered in _SERVICE_ACCOUNTS or _CAMEL.search(value)
        or _CONSTANT.fullmatch(value)
    ):
        return False
    if english and value[0].isupper() and value.isalpha():
        return False
    parts = lowered.split(".")
    return not (len(parts) > 1 and (parts[0] in _CODE_OBJECTS or parts[-1] in _NOT_LOGIN))


def _account(start: int, end: int, text: str) -> Span:
    return Span(start, end, EntityType.ACCOUNT, name, searchable=_SPECIFIC.search(text, start, end) is not None)


def _value(text: str, position: int) -> tuple[int, int, bool] | None:
    """Границы значения с position и без кавычек ли оно."""
    m = _VALUE.match(text, position)
    if not m:
        return None
    group = next(g for g in ("dq", "sq", "bare") if m.group(g) is not None)
    start, end = m.span(group)
    if group == "bare":
        if end < len(text) and text[end] in "([{\"'":
            return None                    # вызов, индекс, приставка строки в коде: «input()», «Optional[User]», «r'…'»
        end = start + len(m.group(group).rstrip(_TRAILING))
    return start, end, group == "bare"


def _keyed(text: str, ctx: DetectContext) -> list[Span]:
    """Значение ключа входа: «login: ivanov», «DB_USER=billing_app», «"username": "ivanov"», «User Id=app»."""
    spans = []
    for m in _ACCOUNT_KEY.finditer(text):
        key_start = _key_start(text, m.start("word"))
        key, prefix = text[key_start:m.end("word")], text[key_start:m.start("word")]
        if _NOT_ACCOUNT_KEY.fullmatch(key):
            continue
        word = m.group("word")
        camel = prefix and prefix[-1].islower() and word[0].isupper()
        if prefix and prefix[-1] not in "_.-" and not camel and (
            len(prefix) > 4 or not prefix.isalpha() or word.lower() == "uid"
        ):
            continue                       # «super user», «--reuid» — слово, а не ключ входа; слитно — «dbuser», «ftpuser»
        if m.group("sep") == "=" and _before(text, key_start) in ("(", ","):
            continue                       # аргумент вызова в коде: «connect(user=db_user, …)»
        bounds = _value(text, m.end())
        if not bounds:
            continue
        start, end, bare = bounds
        if bare and m.group("quote"):
            continue                       # ключ в кавычках и имя без них — переменная кода: «{"user": user_id}»
        login, english = text[start:end], key.isascii()
        if not prefix and english and not _LINE_END.match(text, end):
            continue                       # реплика «User: Can you help me?», комментарий «the login: keep polling»
        if login.lower() != key.lower() and _login(login, ctx, english):
            spans.append(_account(start, end, text))
    return spans


def _after_login_word(text: str, ctx: DetectContext) -> list[Span]:
    spans = []
    for m in _LOGIN_WORD.finditer(text):
        bounds = _value(text, m.end())
        if bounds and _login(text[bounds[0]:bounds[1]], ctx, english=True):
            spans.append(_account(bounds[0], bounds[1], text))
    return spans


def _windows_event(text: str, ctx: DetectContext) -> list[Span]:
    """Имя и домен учётной записи в событии журнала Windows: только при втором поле в _EVENT_DISTANCE знаков."""
    labels = [(m.start(), m.end(), (m.group("en") or m.group("ru")) in ("Name", "Имя")) for m in _EVENT_LABEL.finditer(text)]
    names = [start for start, _, is_name in labels if is_name]
    domains = [start for start, _, is_name in labels if not is_name]
    spans = []
    for start, end, is_name in labels:
        partners = domains if is_name else names
        i = bisect.bisect_left(partners, start - _EVENT_DISTANCE)
        value = _EVENT_VALUE.match(text, end)
        if i == len(partners) or partners[i] > start + _EVENT_DISTANCE or not value:
            continue
        found = value.group("value")
        if _EVENT_SERVICE.fullmatch(found) or found.lower() in ctx.builtin.builtin_accounts:
            continue
        if is_name and _login(found, ctx, english=False):
            spans.append(_account(*value.span("value"), text))
        elif not is_name and "." not in found and _LOGIN.fullmatch(found):    # имя DNS находит слой 3
            spans.append(Span(*value.span("value"), EntityType.DOMAIN, name))
    return spans


def _sshd(text: str, ctx: DetectContext) -> list[Span]:
    spans = []
    for m in _SSHD.finditer(text):
        group = "login" if m.group("login") is not None else "session"
        if _login(m.group(group), ctx, english=False):
            spans.append(_account(*m.span(group), text))
    return spans


def _pairs(text: str, ctx: DetectContext) -> list[Span]:
    """«доступ ivanov / Qwerty123!»: пароль — от шести знаков двух видов, с буквой и цифрой или знаком; не путь и не
    адрес (знаки «/» и «\\» в него не входят)."""
    spans = []
    for m in _PAIR.finditer(text):
        password = m.group("password").rstrip(".,;:…")      # конец фразы; «!» и «?» — знаки пароля
        if not (_looks_like_password(password) and any(c.isalpha() for c in password)):
            continue
        if _login(m.group("login"), ctx, english=False):
            spans.append(_account(*m.span("login"), text))
        start = m.start("password")
        spans.append(Span(start, start + len(password), EntityType.SECRET, name))
    return spans


def _commands(text: str, ctx: DetectContext) -> list[Span]:
    """Имя пары в «curl -u имя:пароль» и «net user имя пароль» — там, где слой секретов скрыл пароль. Служебные входы
    адреса («git», «x-access-token», rules._URL_SERVICE_LOGINS) человека не выдают, как и в «https://git@…»."""
    spans = []
    for pattern, password, groups in (
        (_CURL, lambda m: _secret_value(m, minimum=2), ("dlogin", "slogin", "blogin")),
        (_NET_USER, _net_user_password, ("qlogin", "login")),
    ):
        for m in pattern.finditer(text):
            group = next(group for group in groups if m.group(group) is not None)
            login = m.group(group)
            if password(m) and login.lower() not in _URL_SERVICE_LOGINS and _login(login, ctx, english=False):
                spans.append(_account(*m.span(group), text))
    return spans


def detect(text: str, ctx: DetectContext) -> list[Span]:
    return (
        _keyed(text, ctx) + _after_login_word(text, ctx) + _windows_event(text, ctx) + _sshd(text, ctx)
        + _pairs(text, ctx) + _commands(text, ctx)
    )
