"""Слой 2: пароли, ключи и токены — по виду значения и по контексту."""
from __future__ import annotations

import re

from cleaner.core.detect.base import DetectContext
from cleaner.core.types import EntityType, Span

name = "secrets"

_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.DOTALL
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

_VALUE = r"""(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)'|(?P<bare>[^\s;,&"'<>]+))"""
_STRONG = (
    r"[\w.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential|пароль)[\w.-]*"
)
_WEAK = r"(?:[\w.-]*[_.-])?(?:pass|pwd|token)(?:[_.-][\w.-]*)?"
_KV = re.compile(rf"""(?<![\w.-])(?:{_STRONG}|{_WEAK})["']?\s*[:=]\s*{_VALUE}""", re.IGNORECASE)
_XML = re.compile(
    r"<(?P<tag>[\w.-]*(?:password|passwd|secret|token|api[_-]?key)[\w.-]*)>(?P<bare>[^<\r\n]+)</(?P=tag)>",
    re.IGNORECASE,
)
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<bare>[^\s@/]+)@", re.IGNORECASE)
_CLI = re.compile(
    r"(?<![\w-])(?:--?(?:password|passwd|pwd|pass|secret|token|api-key)(?:\s+|=)|/p(?:assword)?:)" + _VALUE,
    re.IGNORECASE,
)
_SECURE = re.compile(
    r"""ConvertTo-SecureString\s+(?:-String\s+)?(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)')""",
    re.IGNORECASE,
)
_PHRASE = re.compile(
    r"(?<!\w)(?:пароль|password)(?:[ \t]+[\w-]+){0,3}[ \t]*[:=—–][ \t]*" + _VALUE, re.IGNORECASE
)
_PROSE = re.compile(r"(?<!\w)(?:пароль|password)(?:\s+is)?\s+(?P<bare>[^\s,;:=]+)", re.IGNORECASE)

_NOT_SECRET = frozenset({
    "true", "false", "yes", "no", "none", "null", "nil", "on", "off", "required", "optional",
    "enabled", "disabled", "bearer", "basic", "string", "text", "prompt",
})
# Подстановки и выражения — не значения: ${VAR}, $(...), %VAR%, {{...}}, <...>, [[...]], $var, (...
_TEMPLATE = re.compile(r"^(?:[*xX•·.]+|\$\{.*\}|\$\(.*|%\w+%|\{\{.*\}\}|<[^>]*>|\[\[[^\]]*\]\]|\$\w+|\(.*)$")

# Правила по энтропии и по ключевым словам шумят на обычном тексте; контекст у нас свой.
_SKIPPED_PLUGINS = frozenset({"Base64HighEntropyString", "HexHighEntropyString", "KeywordDetector"})


def _library_spans(text: str, own: list[Span]) -> list[Span]:
    """Токены известных сервисов по правилам detect-secrets — там, где свои правила ничего не нашли."""
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
    from detect_secrets.core.scan import scan_line
    from detect_secrets.settings import transient_settings

    names = [
        cls.__name__
        for cls in get_mapping_from_secret_type_to_class().values()
        if cls.__name__ not in _SKIPPED_PLUGINS
    ]
    spans: list[Span] = []
    with transient_settings({"plugins_used": [{"name": plugin} for plugin in names]}):
        offset = 0
        for line in text.splitlines(keepends=True):
            for secret in scan_line(line):
                value = secret.secret_value or ""
                position = line.find(value) if len(value) >= 8 else -1
                if position >= 0:
                    start, end = offset + position, offset + position + len(value)
                    if not any(span.start < end and start < span.end for span in own):
                        spans.append(Span(start, end, EntityType.SECRET, name, validated=True))
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
    for pattern in (_KV, _XML, _URL, _CLI, _SECURE, _PHRASE):
        for m in pattern.finditer(text):
            bounds = _value(m)
            if bounds:
                spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _PROSE.finditer(text):
        bounds = _value(m)
        if bounds and _looks_like_password(text[bounds[0]:bounds[1]]):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    return spans + _library_spans(text, spans)
