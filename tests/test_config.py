from pathlib import Path

import pytest

from cleaner import config
from cleaner.config import Config


def test_load_reads_every_section(tmp_path):
    path = tmp_path / "cleaner.toml"
    path.write_text(
        '[server]\nhost = "10.20.0.10"\nport = 5464\ntls_cert = "c.pem"\ntls_key = "k.pem"\n'
        '[paths]\ndata_dir = "/var/lib/cleaner"\n[limits]\nmax_text_chars = 1000\n[ui]\nutc_offset_hours = 5\n',
        encoding="utf-8",
    )
    cfg = config.load(path)
    assert (cfg.host, cfg.port, cfg.tls_cert, cfg.tls_key, cfg.max_text_chars, cfg.utc_offset_hours) == (
        "10.20.0.10", 5464, "c.pem", "k.pem", 1000, 5,
    )
    assert cfg.db_path == Path("/var/lib/cleaner") / "cleaner.db"


def test_empty_file_gives_loopback_defaults(tmp_path):
    path = tmp_path / "cleaner.toml"
    path.write_text("", encoding="utf-8")
    cfg = config.load(path)
    assert (cfg.host, cfg.port, cfg.max_text_chars, cfg.utc_offset_hours) == ("127.0.0.1", 5464, 500_000, 3)


def test_tls_is_required_outside_loopback():
    with pytest.raises(ValueError):
        config.check_transport(Config(host="10.20.0.10"))
    config.check_transport(Config(host="127.0.0.1"))
    config.check_transport(Config(host="localhost"))
    config.check_transport(Config(host="10.20.0.10", tls_cert="c.pem", tls_key="k.pem"))


def test_models_directory_and_file_limit(tmp_path):
    path = tmp_path / "cleaner.toml"
    path.write_text('[paths]\nmodels_dir = "/opt/cleaner/models"\n[limits]\nmax_file_mb = 20\n', encoding="utf-8")
    cfg = config.load(path)
    assert (cfg.models_dir, cfg.max_file_mb) == (Path("/opt/cleaner/models"), 20)
    assert (Config().models_dir, Config().max_file_mb) == (Path("models"), 50)
