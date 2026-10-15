"""Шифрование содержимого: AES-256-GCM. У каждого чата свой ключ, его оборачивает главный ключ."""
from __future__ import annotations

import base64
import os
from collections.abc import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MASTER_KEY_ENV = "CLEANER_MASTER_KEY"
_NONCE = 12
_EXPORT_MAGIC = b"CLEANERKEY1"
_SALT = 16


class CryptoError(Exception):
    """Ключ не тот, данные повреждены или ключ задан неверно."""


def new_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def seal(key: bytes, data: bytes, aad: str) -> bytes:
    """Шифрует data; aad привязывает шифртекст к месту хранения (таблица, столбец, строка)."""
    nonce = os.urandom(_NONCE)
    return nonce + AESGCM(key).encrypt(nonce, data, aad.encode("utf-8"))


def unseal(key: bytes, blob: bytes, aad: str) -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:_NONCE], blob[_NONCE:], aad.encode("utf-8"))
    except (InvalidTag, ValueError) as exc:
        raise CryptoError("данные не расшифровываются: другой ключ или повреждение") from exc


def encode_key(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


def key_line(key: bytes) -> str:
    return f"{MASTER_KEY_ENV}={encode_key(key)}"


def master_key_from_env(environ: Mapping[str, str] = os.environ) -> bytes:
    value = environ.get(MASTER_KEY_ENV, "")
    if not value:
        raise CryptoError(f"не задана переменная {MASTER_KEY_ENV}")
    try:
        key = base64.b64decode(value, validate=True)
    except ValueError as exc:           # binascii.Error, а для не-ASCII — сам ValueError
        raise CryptoError(f"{MASTER_KEY_ENV} — не base64") from exc
    if len(key) != 32:
        raise CryptoError(f"{MASTER_KEY_ENV} должна содержать 32 байта")
    return key


def _from_passphrase(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def export_key(key: bytes, passphrase: str) -> bytes:
    """Главный ключ в файл для переноса: зашифрован ключом из пароля (scrypt)."""
    salt = os.urandom(_SALT)
    return _EXPORT_MAGIC + salt + seal(_from_passphrase(passphrase, salt), key, "key-export")


def import_key(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(_EXPORT_MAGIC):
        raise CryptoError("это не файл ключа Cleaner")
    salt = blob[len(_EXPORT_MAGIC):len(_EXPORT_MAGIC) + _SALT]
    return unseal(_from_passphrase(passphrase, salt), blob[len(_EXPORT_MAGIC) + _SALT:], "key-export")
