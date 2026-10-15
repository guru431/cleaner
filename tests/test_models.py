import json
import os
from pathlib import Path

import pytest

from cleaner import models


def fake_spec(name: str = "demo") -> models.ModelSpec:
    def fetch(target: Path) -> None:
        (target / "weights.bin").write_bytes(b"\x01\x02")
        (target / "sub").mkdir()
        (target / "sub" / "config.json").write_text("{}", encoding="utf-8")
        (target / ".cache").mkdir()
        (target / ".cache" / "lock").write_text("служебный файл загрузчика", encoding="utf-8")

    return models.ModelSpec(name, "test/demo", lambda: "rev1", fetch)


def test_install_writes_a_manifest_and_moves_the_directory_whole(tmp_path):
    final = models.install(tmp_path, fake_spec())
    assert final == tmp_path / "demo" and not (tmp_path / "demo.incoming").exists()
    manifest = json.loads((final / models.MANIFEST).read_text(encoding="utf-8"))
    assert (manifest["source"], manifest["revision"], sorted(manifest["files"])) == (
        "test/demo", "rev1", ["sub/config.json", "weights.bin"],
    )
    assert models.verify(tmp_path, fake_spec()) == []


def test_verify_finds_changed_missing_and_extra_files(tmp_path):
    final = models.install(tmp_path, fake_spec())
    (final / "weights.bin").write_bytes(b"\x00")
    (final / "sub" / "config.json").unlink()
    (final / "extra.txt").write_text("x", encoding="utf-8")
    assert models.verify(tmp_path, fake_spec()) == [
        "изменён файл weights.bin", "нет файла sub/config.json", "лишний файл extra.txt",
    ]
    assert models.verify(tmp_path, fake_spec("absent")) == ["нет каталога: выполните models download"]


def test_install_refuses_an_existing_directory_and_replaces_a_broken_download(tmp_path):
    (tmp_path / "demo.incoming").mkdir()
    (tmp_path / "demo.incoming" / "half.bin").write_bytes(b"x")
    final = models.install(tmp_path, fake_spec())
    assert not (final / "half.bin").exists()
    with pytest.raises(ValueError):
        models.install(tmp_path, fake_spec())


def test_download_environment_allows_the_hub_only_for_this_command(tmp_path, monkeypatch):
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HOME", "HF_HUB_DISABLE_TELEMETRY"):
        monkeypatch.setenv(name, "1")
    cache = models.prepare_download(tmp_path)
    assert "HF_HUB_OFFLINE" not in os.environ and "TRANSFORMERS_OFFLINE" not in os.environ
    assert os.environ["HF_HOME"] == str(cache) and cache.is_dir()


def test_specs_pin_revisions():
    assert [spec.directory for spec in models.SPECS] == [models.RUBERT_DIR, models.GLINER_DIR, models.DOCLING_DIR]
    assert len(models.SPECS[0].revision()) == 40 and len(models.SPECS[1].revision()) == 40
