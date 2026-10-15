import pytest

from cleaner.storage import crypto


def test_sealed_data_opens_only_with_the_same_key_and_context():
    key = crypto.new_key()
    blob = crypto.seal(key, "секрет".encode(), "items.original:1")
    assert crypto.unseal(key, blob, "items.original:1") == "секрет".encode()
    with pytest.raises(crypto.CryptoError):
        crypto.unseal(key, blob, "items.original:2")
    with pytest.raises(crypto.CryptoError):
        crypto.unseal(crypto.new_key(), blob, "items.original:1")


def test_the_same_text_seals_differently_each_time():
    key = crypto.new_key()
    assert crypto.seal(key, b"x", "a") != crypto.seal(key, b"x", "a")


def test_master_key_comes_from_the_environment():
    key = crypto.new_key()
    assert crypto.master_key_from_env({crypto.MASTER_KEY_ENV: crypto.encode_key(key)}) == key
    assert crypto.key_line(key) == f"{crypto.MASTER_KEY_ENV}={crypto.encode_key(key)}"
    for environ in ({}, {crypto.MASTER_KEY_ENV: "не base64"}, {crypto.MASTER_KEY_ENV: crypto.encode_key(b"short")}):
        with pytest.raises(crypto.CryptoError):
            crypto.master_key_from_env(environ)


def test_exported_key_needs_the_passphrase():
    key = crypto.new_key()
    blob = crypto.export_key(key, "длинная фраза")
    assert crypto.import_key(blob, "длинная фраза") == key
    with pytest.raises(crypto.CryptoError):
        crypto.import_key(blob, "другая фраза")
    with pytest.raises(crypto.CryptoError):
        crypto.import_key(b"not a key file", "длинная фраза")
