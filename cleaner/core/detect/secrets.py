"""Слой 2: пароли, ключи и токены — по виду значения и по контексту."""
from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable
from functools import lru_cache

from cleaner.core.detect.base import DetectContext
from cleaner.core.entities.names import part_of_speech
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
# Пароль без слова-ключа на своём месте в известной команде. «net use \\хост\ресурс пароль /user:…» —
# первое слово после пути, кроме параметров и «*» (запрос пароля). «mysql -pпароль» — только слитно:
# «-p имя» — запрос пароля и имя базы, «-P» — порт; не дальше двадцати слов и не за «|», «;», «&».
# «sshpass -p пароль»; ключ приложения в web.config — <add key="…Password" value="…"/>.
_COMMANDS = (
    re.compile(
        r"(?<![\w-])net[ \t]+use[ \t]+(?:(?:[a-z]:|\*)[ \t]+)?\\\\[^\s\\]+\\\S+(?:[ \t]+/\S+)*[ \t]+(?![/*])"
        + _VALUE,
        re.IGNORECASE,
    ),
    re.compile(r"(?<![\w-])(?:mysql|mariadb)[\w.-]*(?:[ \t]+(?!-p)[^\s|;&]++){0,20}?[ \t]+-p" + _VALUE),
    re.compile(r"(?<![\w-])sshpass[ \t]+-p[ \t]*" + _VALUE),
)
_ADD_KEY = re.compile(
    r"""<add\s+key\s*=\s*(?P<q>["'])(?P<key>[^"'<>\r\n]+)(?P=q)\s+value\s*=\s*"""
    r"""(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)')""",
    re.IGNORECASE,
)
_SECURE = re.compile(
    r"""ConvertTo-SecureString\s+(?:-String\s+)?(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)')""",
    re.IGNORECASE,
)
# После тире или дефиса в прозе часто идёт не пароль («Пароль — это строка…»). Такое значение
# отбрасывается, только если это слово прозы (_prose_word) и на пароль оно не похоже; продолжение фразы
# за ним не в счёт: «Пароль от Wi-Fi — sunflower для гостей» — пароль. После «:» и «=» берётся любое.
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
# Слова, которые в тексте стоят после «Пароль —» вместо пароля. Русские служебные слова, местоимения,
# прилагательные, наречия, числительные и глаголы распознаёт словарь (_prose_word), здесь — только то, что он
# читает существительным; английские — списком.
_PROSE_WORDS = _LINKING_WORDS | frozenset({
    "минимум", "рабочий", "строка", "набор", "комбинация", "сочетание", "слово", "фраза", "дата", "номер", "имя",
    "фамилия",
    "the", "a", "an", "this", "that", "it", "same", "your", "my", "our", "his", "her", "their", "any", "one",
    "at", "of", "for", "from", "in", "on", "to", "by", "with", "without", "as", "like", "and", "or", "but",
    "also", "only", "just", "still", "are", "be", "has", "have", "will", "should", "must", "can", "never",
    "minimum", "min", "maximum", "more", "less", "old", "new", "empty", "blank", "temporary", "current",
    "previous", "initial", "usual", "standard", "unchanged", "changed", "expired", "reset", "sent", "stored",
})
_RUSSIAN_WORD = re.compile(r"[а-яё]+(?:-[а-яё]+)*", re.IGNORECASE)
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
# Вызов или индекс в коде после ключа — тоже не значение: «password = input()», «token = os.environ["TOKEN"]»,
# «api_key=config.get("key")» давали секреты «input(», «os.environ[», и обрывок кода скрывался во всём чате.
# Имя через точку перед скобкой — код всегда («getpass.getpass()», «$cred.GetNetworkCredential().Password»).
# Имя без точки — только когда скобка кончает значение и за ней сразу «)», «]» или кавычка (вызов без
# аргументов, аргумент или индекс строкой): «password=Ab(1» и «Summer2024(» в конце строки — пароли.
# Значение в кавычках не проверяется: «"Qwerty1("» — строка, а не выражение.
_CALL = re.compile(r"\$?[A-Za-z_]\w*(?P<dotted>(?:\.[A-Za-z_]\w*)+)?[(\[]")

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
# Сколько разных значений строки ищется по всей строке. Только такой поиск находит повтор значения без контекста
# его правила («aws_key="…"», а дальше по строке то же значение без ключа), но стоит длину строки на каждое
# значение: строка выгрузки с тысячами разных токенов шла квадратичное время (8000 SID на строке в 472 КБ — 3,4 с).
# Остальные значения берутся там, где их нашли правила; повтор без контекста находит следующий проход очистки
# по известным значениям чата (слой 3), а пропущенный — проверка утечек.
_REPEATS = 50


@lru_cache(maxsize=1)
def _library_rules() -> tuple[re.Pattern[str], ...]:
    """Выражения правил detect-secrets (denylist) по порядку правил. Не scan_line: тот читает общие для процесса
    настройки, которые меняет любой параллельный вызов, и слушается пометки «pragma: allowlist secret» во вставленном
    тексте. И не analyze_string: все включённые правила берут его общим, а он отдаёт значения без позиций."""
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    return tuple(
        regex
        for cls in get_mapping_from_secret_type_to_class().values()
        if cls.__name__ not in _SKIPPED_PLUGINS
        for regex in cls().denylist
    )


def _library_hits(squeezed: str) -> dict[str, list[int]]:
    """Значения правил в строке -> их начала, в порядке analyze_string. Значение — как у него: findall отдаёт
    непустые группы совпадения, а у выражения без групп — всё совпадение."""
    hits: dict[str, list[int]] = {}
    for regex in _library_rules():
        groups = range(1, regex.groups + 1) if regex.groups else (0,)
        for m in regex.finditer(squeezed):
            for group in groups:
                if len(m.group(group) or "") >= 8:
                    hits.setdefault(m.group(group), []).append(m.start(group))
    return hits


def _unsqueezed(line: str) -> Callable[[int], int]:
    """Позиция в строке со сжатыми рядами пробелов -> позиция в настоящей строке."""
    after: list[int] = []      # первая позиция сжатой строки после ряда
    removed: list[int] = []    # сколько пробелов выброшено до неё
    total = 0
    for m in _SPACES.finditer(line):
        total += m.end() - m.start() - 1
        after.append(m.end() - total)
        removed.append(total)

    def original(position: int) -> int:
        index = bisect_right(after, position)
        return position + (removed[index - 1] if index else 0)

    return original


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
        hits = _library_hits(_SPACES.sub(" ", line))
        original = _unsqueezed(line) if len(hits) > _REPEATS else None
        for index, (value, starts) in enumerate(hits.items()):
            if original is None or index < _REPEATS:
                places = []                    # все вхождения, и там, где правило значения не видит
                position = line.find(value)    # значение ищется в настоящей строке, не в сжатой
                while position >= 0:
                    places.append(position)
                    position = line.find(value, position + 1)
            else:                              # значение с рядом пробелов внутри в настоящей строке другое
                places = [p for p in map(original, starts) if line.startswith(value, p)]
            for position in places:
                start, end = offset + position, offset + position + len(value)
                if taken.find(1, start, end) < 0:
                    spans.append(Span(start, end, EntityType.SECRET, name, validated=True))
                    taken[start:end] = b"\x01" * len(value)
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
            if _code(m.string, start, end):
                return None
        value = m.string[start:end]
        if len(value) < minimum or value.lower() in _NOT_SECRET or _TEMPLATE.match(value):
            return None
        return start, end
    return None


def _code(string: str, start: int, end: int) -> bool:
    """Значение без кавычек string[start:end] — вызов или индекс в коде (см. _CALL)."""
    call = _CALL.match(string, start, end)
    return call is not None and (
        call.group("dotted") is not None or (call.end() == end < len(string) and string[end] in ")]\"'")
    )


def _looks_like_password(value: str) -> bool:
    kinds = (
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    )
    return len(value) >= 6 and sum(kinds) >= 2 and (kinds[2] or kinds[3])


def _prose_word(value: str) -> bool:
    """Слово фразы после «Пароль —», а не пароль: из _PROSE_WORDS или русское слово словаря, кроме существительного.
    Существительное и слово не из словаря — значение: «подсолнух», «йцукен» бывают паролями. Цена — русское
    прилагательное или глагол в роли пароля («Пароль — зелёный») остаётся открытым."""
    word = value.lower().replace("ё", "е")
    return word in _PROSE_WORDS or (
        _RUSSIAN_WORD.fullmatch(word) is not None and part_of_speech(word) not in (None, "NOUN")
    )


def _secret_key(key: str) -> bool:
    return bool(_KEY_WORD.search(key)) and not (_NOT_SECRET_KEY.fullmatch(key) and not _SECRET_END.search(key))


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
        if m.start() < parsed_until or not _secret_key(key):
            continue
        value = _VALUE_AT.match(text, m.end())
        if not value:
            continue
        parsed_until = value.end()
        bounds = _value(value, minimum=2)
        if bounds and not _not_a_value(key, text[bounds[0]:bounds[1]]):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _ADD_KEY.finditer(text):
        bounds = _value(m, minimum=2) if _secret_key(m.group("key")) else None
        if bounds and not _not_a_value(m.group("key"), text[bounds[0]:bounds[1]]):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for pattern in (_XML, _URL, _CLI, _SECURE, _AUTH, _BEARER, *_COMMANDS):
        for m in pattern.finditer(text):
            bounds = _value(m, minimum=2 if pattern is _CLI or pattern in _COMMANDS else 3)
            if bounds and not (pattern in (_AUTH, _BEARER) and _WORDS.fullmatch(text, *bounds)):
                spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _PHRASE.finditer(text):
        bounds = _value(m)
        if not bounds:
            continue
        value = text[bounds[0]:bounds[1]]
        dashed = m.group("sep").strip() in ("—", "–", "-")
        # Значение в кавычках написано как есть, а не словом фразы. Русское слово через дефис похоже на пароль
        # только дефисом («по-прежнему», см. _HYPHENATED_WORD) — его решает словарь.
        looks = _looks_like_password(value) and not _HYPHENATED_WORD.fullmatch(value)
        if not dashed or m.group("bare") is None or looks or not _prose_word(value):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _PROSE.finditer(text):
        bounds = _value(m)
        if bounds and _looks_like_password(text[bounds[0]:bounds[1]]) and not _HYPHENATED_WORD.fullmatch(text, *bounds):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    return spans + _library_spans(text, spans)
