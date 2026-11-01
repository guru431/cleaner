"""Правила журнала отправленного (спецификация 2026-10-28, раздел 7): отпечатки блоков и разговоров, пометки удержанных
блоков. Открытый хэш не годится: по нему подбирается известный пароль, — отпечатки считаются HMAC."""
from __future__ import annotations

import hashlib
import hmac
import json

# Причины удержания блока (7.4): постоянный текст — пометка повторяется дословно от хода к ходу.
REASONS = {
    "media": "изображение или файл не передаётся",
    "blocked": "содержит значение типа {type}",
    "failed": "очистка не выполнена",
}


def canonical(node: object) -> bytes:
    """Канонический JSON: ключи по порядку, без пробелов. cache_control блока верхнего уровня не входит — агент
    переносит его с блока на блок от хода к ходу (проверка 18.1d)."""
    if isinstance(node, dict):
        node = {key: value for key, value in node.items() if key != "cache_control"}
    return json.dumps(node, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _hmac(secret: bytes, *parts: bytes) -> str:
    return hmac.new(secret, b"\0".join(parts), hashlib.sha256).hexdigest()


def block_digest(secret: bytes, protocol: str, role: str, kind: str, node: object) -> str:
    return _hmac(secret, protocol.encode(), role.encode(), kind.encode(), canonical(node))


def conversation_id(secret: bytes, key_id: str, first: object, *, session: str = "", epoch: int = 0) -> str:
    """Stable client conversation id plus first user message and key. Without an id, first-message fallback is scoped
    to the key's persistent reset epoch. Keeping epoch zero's encoding lets existing fallback histories resume."""
    parts = [key_id.encode(), canonical(first)]
    if session:
        parts += [b"session", session.encode()]
    elif epoch:
        parts += [b"epoch", str(epoch).encode()]
    return _hmac(secret, *parts)


def chat_secret(dek: bytes) -> bytes:
    """Ключ отпечатков блоков — свой у каждого чата, выведенный из его ключа."""
    return hmac.new(dek, b"cleaner-agent-ledger", hashlib.sha256).digest()


def conversation_secret(global_key: bytes) -> bytes:
    return hmac.new(global_key, b"cleaner-agent-conversation", hashlib.sha256).digest()


def placeholder(reason: str) -> str:
    return f"[Cleaner: блок не передан — {reason}]"
