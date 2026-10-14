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
_JWT = re.compile(r"(?<![\w-])eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}(?![\w-])")
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
# (строка подключения, параметры адреса).
_BARE = r"(?P<bare>(?:[^\s;&,\"'<>]|[;&,](?![\s;&,]|[\w .-]+=|$))+)"
_VALUE = rf"""(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)'|{_BARE})"""
# Имя ключа содержит слово целиком или склеенным: db_password, dbpass, userpwd, accessToken.
_KEY = (
    r"[\w.-]*(?:password|passwd|passphrase|pass|pwd|secret|token|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|credential|пароль)[\w.-]*"
)
_KV = re.compile(rf"""(?<![\w.-])(?P<key>{_KEY})["']?\s*[:=]\s*{_VALUE}""", re.IGNORECASE)
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
_XML = re.compile(
    r"<(?P<tag>[\w.-]*(?:password|passwd|secret|token|api[_-]?key)[\w.-]*)>(?P<bare>[^<\r\n]+)</(?P=tag)>",
    re.IGNORECASE,
)
# Длина схемы ограничена: без предела цепочка «a.b.a.b…» без «://» даёт квадратичный перебор.
_URL = re.compile(r"\b[a-z][a-z0-9+.-]{0,31}://[^\s:/@]+:(?P<bare>[^\s@/]+)@", re.IGNORECASE)
_CLI = re.compile(
    r"(?<![\w-])(?:--?(?:password|passwd|pwd|pass|secret|token|api-key)(?:\s+|=)|/p(?:assword)?:)" + _VALUE,
    re.IGNORECASE,
)
_SECURE = re.compile(
    r"""ConvertTo-SecureString\s+(?:-String\s+)?(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)')""",
    re.IGNORECASE,
)
# После тире или дефиса в прозе часто идёт не пароль («Пароль — это…»): такое значение
# принимается, только если похоже на пароль; после «:» и «=» — любое.
_PHRASE = re.compile(
    r"(?<!\w)(?:пароль|password)(?:[ \t]+[\w-]+){0,3}"
    r"(?P<sep>[ \t]*[:=][ \t]*|[ \t]*[—–][ \t]*|[ \t]+-[ \t]+)" + _VALUE,
    re.IGNORECASE,
)
_PROSE = re.compile(r"(?<!\w)(?:пароль|password)(?:\s+is)?\s+(?P<bare>[^\s,;:=]+)", re.IGNORECASE)
_AUTH = re.compile(
    r"\bauthorization\s*[:=]\s*[\"']?(?:bearer|basic|token|negotiate|ntlm|apikey)\s+(?P<bare>[^\s\"'<>,;]+)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?<!\w)bearer\s+(?P<bare>[A-Za-z0-9._~+/=-]{16,})", re.IGNORECASE)

_NOT_SECRET = frozenset({
    "true", "false", "yes", "no", "none", "null", "nil", "on", "off", "required", "optional",
    "enabled", "disabled", "bearer", "basic", "string", "text", "prompt",
})
# Подстановки и выражения — не значения: ${VAR}, $(...), $env:VAR, %VAR%, {{...}}, <...>, [[...]],
# $VAR и $var без цифр (переменная), (... . «$ecret123» с цифрами — значение.
_TEMPLATE = re.compile(
    r"^(?:[*xX•·.]+|\$\{.*\}|\$\(.*|\$env:\w+|%\w+%|\{\{.*\}\}|<[^>]*>|\[\[[^\]]*\]\]|\$[A-Za-z_]+|\(.*)$"
)

# Правила по энтропии и по ключевым словам шумят на обычном тексте; контекст у нас свой.
_SKIPPED_PLUGINS = frozenset({"Base64HighEntropyString", "HexHighEntropyString", "KeywordDetector"})


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
    offset = 0
    for line in text.splitlines(keepends=True):
        for plugin in _library_plugins():
            for value in plugin.analyze_string(line):
                if len(value) < 8:
                    continue
                position = line.find(value)
                while position >= 0:
                    start, end = offset + position, offset + position + len(value)
                    if not any(span.start < end and start < span.end for span in own + spans):
                        spans.append(Span(start, end, EntityType.SECRET, name, validated=True))
                    position = line.find(value, position + 1)
        offset += len(line)
    return spans


def _value(m: re.Match[str]) -> tuple[int, int] | None:
    """Границы значения в совпадении или None, если это не секрет."""
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
        if len(value) < 3 or value.lower() in _NOT_SECRET or _TEMPLATE.match(value):
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


def detect(text: str, ctx: DetectContext) -> list[Span]:
    spans = [
        Span(m.start(), m.end(), EntityType.SECRET, name, validated=True)
        for pattern in (_PEM, _JWT, _TOKEN)
        for m in pattern.finditer(text)
    ]
    for pattern in (_KV, _XML, _URL, _CLI, _SECURE, _AUTH, _BEARER):
        for m in pattern.finditer(text):
            if pattern is _KV and _NOT_SECRET_KEY.fullmatch(m.group("key")):
                continue
            bounds = _value(m)
            if bounds:
                spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _PHRASE.finditer(text):
        bounds = _value(m)
        if not bounds:
            continue
        dashed = m.group("sep").strip() in ("—", "–", "-")
        if not dashed or _looks_like_password(text[bounds[0]:bounds[1]]):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _PROSE.finditer(text):
        bounds = _value(m)
        if bounds and _looks_like_password(text[bounds[0]:bounds[1]]):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    return spans + _library_spans(text, spans)
