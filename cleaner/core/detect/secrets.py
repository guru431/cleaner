"""Слой 2: пароли, ключи и токены — по виду значения и по контексту."""
from __future__ import annotations

import re
from functools import lru_cache

from cleaner.core.detect.base import DetectContext
from cleaner.core.types import EntityType, Span

name = "secrets"

_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)
# Подпись может быть пустой («alg: none»): такой токен раньше находило правило JWT из detect-secrets.
_JWT = re.compile(r"(?<![\w-])eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*")
_TOKEN = re.compile(
    r"""(?<![\w-])(?:
        AKIA[0-9A-Z]{16}
      | gh[pousr]_[A-Za-z0-9]{36,}
      | github_pat_[A-Za-z0-9_]{40,}
      | glpat-[\w-]{20,}
      | xox[baprs]-[A-Za-z0-9-]{10,}
      | sk_live_[A-Za-z0-9]{16,}
      | AIza[\w-]{35}
      | sk-[A-Za-z0-9_-]{20,}
      | npm_[A-Za-z0-9]{36}
      | \d{8,10}:AA[\w-]{33}
    )(?![\w-])""",
    re.VERBOSE,
)

# Значение без кавычек тянется до пробела. «;», «&» и «,» внутри пароля законны; концом значения
# они служат, только если за ними пробел, конец текста или следующее поле вида «имя=»
# (строка подключения, параметры адреса). Имя поля пробелов не содержит: в «pwd=Qw,er7y retries=3»
# запятая — часть пароля. Исключение — «;» перед словами с заглавной буквы через пробел и «=»:
# это поля ADO.NET («;Persist Security Info=», «;User ID=»).
_BARE = r"(?P<bare>(?:[^\s;&,\"'<>]|[;&,](?![\s;&,]|[\w.-]+=|(?<=;)[A-Z][\w.-]*(?: [A-Z][\w.-]*)+=|$))+)"
_VALUE = rf"""(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)'|{_BARE})"""
# Имя ключа содержит слово целиком или склеенным: db_password, dbpass, userpwd, accessToken.
# Имя берётся целиком одним проходом без возвратов («++»), а слово секрета ищется в нём кодом:
# предел длины имени пропускал длинные ключи (spring….client-secret), а без предела выражение
# со словом внутри перебирало «tokentoken…» квадратичное время. Значение разбирается отдельно и
# только у ключа со словом секрета: пара без него не съедает соседнюю («id:token=…»).
_KEY_NAME = re.compile(r"""(?<![\w.-])(?P<key>[\w.-]++)["']?\s*[:=]\s*""")
_KEY_WORD = re.compile(
    r"password|passwd|passphrase|pass|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|credential|пароль",
    re.IGNORECASE,
)
_VALUE_AT = re.compile(_VALUE)
# Имена ключей, которые содержат те же слова, но хранят не секрет: счётчики токенов,
# политики паролей, атрибуты Active Directory, обычные слова с «pass».
_NOT_SECRET_KEY = re.compile(
    r"""(?:[\w.-]*[_.-])?(?:max|min|num|total|prompt|completion|input|output|context)[_.-]?tokens?
      | tokens
      | (?:[\w.-]*[_.-])?tokens?[_.-]?(?:type|count|limit|usage|budget|endpoint|url|uri|ttl|lifetime|expir\w*)
      | [\w.-]*tokeniz\w*
      | [\w.-]*(?:bypass|compass|passive|passed|passage|passenger|pass[_.-]?through)[\w.-]*
      | (?:bad|max|min)?pwd(?:lastset|properties|historylength|count|age|length)
      | badpasswordtime
      | [\w.-]*password[_.-]?(?:policy|length|min\w*|max\w*|expir\w*|age|complexity|history
                              |last[_.-]?set|neverexpires|required|changed|reset\w*)""",
    re.IGNORECASE | re.VERBOSE,
)
# Ключ, который кончается словом секрета, хранит секрет, какие бы слова ни стояли перед ним:
# bypass_token, passwordResetToken, VERCEL_AUTOMATION_BYPASS_SECRET. Список выше его не отменяет.
_SECRET_END = re.compile(
    r"(?:^|[_.-])(?i:password|passwd|passphrase|pass|pwd|secret|token|key|credentials?|пароль)$"
    r"|(?<=[a-z])(?:Password|Passwd|Passphrase|Pass|Pwd|Secret|Token|Key|Credentials?)$"
)
_XML = re.compile(
    r"<(?P<tag>[\w.-]{0,64}(?:password|passwd|secret|token|api[_-]?key)[\w.-]{0,64})>"
    r"(?P<bare>[^<\r\n]+)</(?P=tag)>",
    re.IGNORECASE,
)
# Длина схемы ограничена: без предела цепочка «a.b.a.b…» без «://» даёт квадратичный перебор.
# Логина может не быть: «redis://:пароль@хост» — стандартная запись Redis.
_URL = re.compile(r"\b[a-z][a-z0-9+.-]{0,31}://[^\s:/@]*:(?P<bare>[^\s@/]+)@", re.IGNORECASE)
# Слово после пробела, начатое с «-», — следующий параметр («--password --verbose»), а «/p:имя=значение» —
# свойство MSBuild («/p:Configuration=Release»; пароль в нём находит правило ключа). Пароль из base64
# с «=» на конце («/p:dGVzdDE=») свойством не считается: после «=» у свойства есть значение.
_CLI = re.compile(
    r"(?<![\w-])(?:--?(?:password|passwd|pwd|pass|secret|token|api-key)(?:\s+(?!-)|=)"
    r"|/p(?:assword)?:(?![A-Za-z_][\w-]*=[^\s=]))" + _VALUE,
    re.IGNORECASE,
)
_SECURE = re.compile(
    r"""ConvertTo-SecureString\s+(?:-String\s+)?(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)')""",
    re.IGNORECASE,
)
# После тире или дефиса в прозе часто идёт не пароль («Пароль — это строка…»). Такое значение
# отбрасывается, только если это слово-связка или за ним продолжается фраза, а само оно на пароль
# не похоже; после «:» и «=» берётся любое.
_PHRASE = re.compile(
    r"(?<!\w)(?:пароль|password)(?:[ \t]+[\w-]+){0,3}"
    r"(?P<sep>[ \t]*[:=][ \t]*|[ \t]*[—–][ \t]*|[ \t]+-[ \t]+)" + _VALUE,
    re.IGNORECASE,
)
_PROSE = re.compile(r"(?<!\w)(?:пароль|password)(?:\s+is)?\s+(?P<bare>(?!-)[^\s,;:=]+)", re.IGNORECASE)
# Русское слово через дефис («по-прежнему», «кто-то») похоже на пароль только дефисом, а то же слово
# без дефиса паролем в тексте и так не считается.
_HYPHENATED_WORD = re.compile(r"[а-яё]+(?:-[а-яё]+)+", re.IGNORECASE)
_LINKING_WORDS = frozenset({"это", "is", "was", "not", "see", "не", "см"})
_CLAUSE = re.compile(r"[ \t]+\w")
_AUTH = re.compile(
    r"\bauthorization\s*[:=]\s*[\"']?(?:bearer|basic|token|negotiate|ntlm|apikey)\s+(?P<bare>[^\s\"'<>,;]+)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?<!\w)bearer\s+(?P<bare>[A-Za-z0-9._~+/=-]{16,})", re.IGNORECASE)
# После «bearer» в тексте бывают слова («bearer authentication», «Bearer authentication-scheme»):
# в настоящем токене есть цифры или заглавные внутри слова.
_WORDS = re.compile(r"[A-Za-z][a-z]*(?:[-./][A-Za-z][a-z]*)*")
# Под ключом со словом секрета в коде часто стоит не значение, а вызов команды PowerShell
# («$pwd = Read-Host», «$token = Invoke-RestMethod»).
_CMDLET = re.compile(r"(?:Get|Read|ConvertTo|ConvertFrom|Import|Invoke|New)-[A-Z][A-Za-z]*")

_NOT_SECRET = frozenset({
    "true", "false", "yes", "no", "none", "null", "nil", "on", "off", "required", "optional",
    "enabled", "disabled", "bearer", "basic", "string", "text", "prompt", "да", "нет", "ok",
})
# Подстановки и выражения — не значения: ${VAR}, $(...), $env:VAR, %VAR%, {{...}}, <...>, [[...]],
# $VAR и $var без цифр (переменная), (... . «$ecret123» с цифрами — значение.
_TEMPLATE = re.compile(
    r"^(?:[*xX•·.]+|\$\{.*\}|\$\(.*|\$env:\w+|%\w+%|\{\{.*\}\}|<[^>]*>|\[\[[^\]]*\]\]|\$[A-Za-z_]+|\(.*)$"
)

# Правила по энтропии и по ключевым словам шумят на обычном тексте; контекст у нас свой.
# Правила npm, JWT и OpenAI без начала слова перебирают строку от каждого «//», «eyJ», «sk-» —
# квадратичное время под общей блокировкой интерпретатора, то есть остановка службы для всех.
# Их токены находят свои правила: _TOKEN (npm_, sk-), _JWT и ключ «_authToken=» в .npmrc.
# IP-адреса — работа слоя 3: там они получают подмену и восстанавливаются (спецификация 6.2).
_SKIPPED_PLUGINS = frozenset({
    "Base64HighEntropyString", "HexHighEntropyString", "KeywordDetector",
    "NpmDetector", "JwtTokenDetector", "OpenAIDetector", "IPPublicDetector",
})
# Правила IBM, Cloudant и Softlayer разбирают пробелы вокруг «=» тремя повторами подряд (« *», « +»,
# « *»): на длинном ряде пробелов это кубическое время. Ряд сжимается до одного пробела — повторы
# принимают любое их число, а двух пробелов подряд нет ни в одном значении этих правил.
_SPACES = re.compile(" {2,}")


@lru_cache(maxsize=1)
def _library_plugins() -> tuple:
    """Правила detect-secrets как объекты. Через них, а не через scan_line: тот читает
    общие для процесса настройки, которые меняет любой параллельный вызов, и слушается
    пометки «pragma: allowlist secret» во вставленном тексте."""
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    return tuple(
        cls()
        for cls in get_mapping_from_secret_type_to_class().values()
        if cls.__name__ not in _SKIPPED_PLUGINS
    )


def _library_spans(text: str, own: list[Span]) -> list[Span]:
    """Токены известных сервисов по правилам detect-secrets — там, где свои правила ничего не нашли."""
    spans: list[Span] = []
    # Занятые знаки — картой, а не перебором найденного: токен, повторённый на строке выгрузки сотни
    # раз, давал кубическое время (каждое повторение сверялось с каждым найденным, и столько же раз).
    taken = bytearray(len(text))
    for span in own:
        taken[span.start:span.end] = b"\x01" * (span.end - span.start)
    offset = 0
    for line in text.splitlines(keepends=True):
        squeezed = _SPACES.sub(" ", line)
        values = dict.fromkeys(value for plugin in _library_plugins() for value in plugin.analyze_string(squeezed))
        for value in values:
            if len(value) < 8:
                continue
            position = line.find(value)    # значение ищется в настоящей строке, не в сжатой
            while position >= 0:
                start, end = offset + position, offset + position + len(value)
                if taken.find(1, start, end) < 0:
                    spans.append(Span(start, end, EntityType.SECRET, name, validated=True))
                    taken[start:end] = b"\x01" * len(value)
                position = line.find(value, position + 1)
        offset += len(line)
    return spans


def _value(m: re.Match[str], minimum: int = 3) -> tuple[int, int] | None:
    """Границы значения в совпадении или None, если это не секрет. После имени ключа или параметра
    берётся и короткое значение (minimum=2): «password=Q7» — тоже пароль."""
    for group in ("dq", "sq", "bare"):
        if group not in m.re.groupindex or m.group(group) is None:
            continue
        start, end = m.span(group)
        if _TEMPLATE.match(m.group(group)):    # до обрезки: закрывающая скобка — часть подстановки
            return None
        if group == "bare":
            while end > start and m.string[end - 1] in ".,)]}":
                end -= 1
        value = m.string[start:end]
        if len(value) < minimum or value.lower() in _NOT_SECRET or _TEMPLATE.match(value):
            return None
        return start, end
    return None


def _looks_like_password(value: str) -> bool:
    kinds = (
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    )
    return len(value) >= 6 and sum(kinds) >= 2 and (kinds[2] or kinds[3])


def _not_a_value(key: str, value: str) -> bool:
    """Значение под ключом со словом секрета, которое секретом не является: имя той же переменной
    («cancellationToken: cancellationToken», «accessToken: AccessToken;»; но «password: password» —
    слабый пароль), вызов команды и число под ключом токена — счётчик («max_new_tokens: 1024»).
    Токенов из одних цифр не бывает, а пароль из цифр обычен, поэтому числа — только у «token».
    PWD и OLDPWD с путём — рабочий каталог оболочки, а не поле Pwd строки подключения."""
    return (
        (value.lower() == key.lower() and not _KEY_WORD.fullmatch(key))
        or _CMDLET.fullmatch(value) is not None
        or (value.isdigit() and all(word.lower() == "token" for word in _KEY_WORD.findall(key)))
        or (key.upper() in ("PWD", "OLDPWD") and value.startswith(("/", "~")))
    )


def detect(text: str, ctx: DetectContext) -> list[Span]:
    spans = [
        Span(m.start(), m.end(), EntityType.SECRET, name, validated=True)
        for pattern in (_PEM, _JWT, _TOKEN)
        for m in pattern.finditer(text)
    ]
    parsed_until = 0
    for m in _KEY_NAME.finditer(text):
        key = m.group("key")
        # Пара внутри уже разобранного значения пропускается: её значение кончается там же, а без этого
        # «token=token=…» или «PWD=/PWD=/…» разбирали значение до конца строки от каждого ключа.
        # Цена — пара внутри отвергнутого значения («PWD=/x?token=…») не ищется.
        if m.start() < parsed_until:
            continue
        if not _KEY_WORD.search(key) or (_NOT_SECRET_KEY.fullmatch(key) and not _SECRET_END.search(key)):
            continue
        value = _VALUE_AT.match(text, m.end())
        if not value:
            continue
        parsed_until = value.end()
        bounds = _value(value, minimum=2)
        if bounds and not _not_a_value(key, text[bounds[0]:bounds[1]]):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for pattern in (_XML, _URL, _CLI, _SECURE, _AUTH, _BEARER):
        for m in pattern.finditer(text):
            bounds = _value(m, minimum=2 if pattern is _CLI else 3)
            if bounds and not (pattern in (_AUTH, _BEARER) and _WORDS.fullmatch(text, *bounds)):
                spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _PHRASE.finditer(text):
        bounds = _value(m)
        if not bounds:
            continue
        value = text[bounds[0]:bounds[1]]
        dashed = m.group("sep").strip() in ("—", "–", "-")
        prose = value.lower() in _LINKING_WORDS or _CLAUSE.match(text, bounds[1]) is not None
        if not dashed or not prose or _looks_like_password(value):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _PROSE.finditer(text):
        bounds = _value(m)
        if bounds and _looks_like_password(text[bounds[0]:bounds[1]]) and not _HYPHENATED_WORD.fullmatch(text, *bounds):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    return spans + _library_spans(text, spans)
