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


@pytest.mark.parametrize("manifest", ["{}", "[]", '{"files": []}'])
def test_verify_reports_a_manifest_without_the_file_list(tmp_path, manifest):
    """FINDINGS P3 «verify() переживает повреждённый JSON манифеста, но не маниф...»: KeyError вместо ответа."""
    final = models.install(tmp_path, fake_spec())
    (final / models.MANIFEST).write_text(manifest, encoding="utf-8")
    assert models.verify(tmp_path, fake_spec()) == ["нет манифеста или он повреждён"]


def test_verify_refuses_an_empty_manifest_of_another_source_and_revision(tmp_path):
    """Аудит 2026-10-21: пустой каталог с манифестом {"source": другой, "revision": старая, "files": {}} давал OK."""
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / models.MANIFEST).write_text(
        json.dumps({"source": "different/source", "revision": "old-revision", "files": {}}), encoding="utf-8",
    )
    assert models.verify(tmp_path, fake_spec()) == [
        "в манифесте нет файлов: удалите каталог и выполните models download",
        "источник different/source вместо test/demo: удалите каталог и выполните models download",
        "ревизия old-revision вместо закреплённой rev1: удалите каталог и выполните models download",
    ]


def test_verify_finds_a_consistent_directory_of_an_outdated_revision(tmp_path):
    """Закреплённая ревизия сменилась, а каталог прежней поставки сам с собой согласован — это тоже провал."""
    models.install(tmp_path, fake_spec())
    newer = models.ModelSpec("demo", "test/demo", lambda: "rev2", fake_spec().fetch)
    assert models.verify(tmp_path, newer) == [
        "ревизия rev1 вместо закреплённой rev2: удалите каталог и выполните models download",
    ]


def test_verify_needs_the_files_the_loader_reads(tmp_path):
    """Манифест и каталог без весов согласованы между собой, но модель из них не загрузится."""
    spec = fake_spec()
    models.install(tmp_path, spec)
    required = models.ModelSpec("demo", "test/demo", lambda: "rev1", spec.fetch, ("weights.bin", "tokenizer.json"))
    assert models.verify(tmp_path, required) == ["в манифесте нет обязательного файла tokenizer.json"]


@pytest.mark.parametrize("files", ['{"weights.bin": 5}', '{"weights.bin": "abc"}'])
def test_verify_reports_file_entries_that_are_not_sha256(tmp_path, files):
    final = models.install(tmp_path, fake_spec())
    (final / models.MANIFEST).write_text(f'{{"source": "test/demo", "revision": "rev1", "files": {files}}}', encoding="utf-8")
    assert models.verify(tmp_path, fake_spec()) == ["нет манифеста или он повреждён"]


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
    # Файл ONNX GLiNER нужен ветке ner_models.GLINER_ONNX: без него переключение потребовало бы загрузки.
    from cleaner.core.detect.ner_models import GLINER_ONNX_FILE

    assert "model.safetensors" in models.SPECS[0].required and GLINER_ONNX_FILE in models.SPECS[1].required
