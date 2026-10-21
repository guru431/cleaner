"""Модели слоя 4 и разбора документов в models_dir (раздел 15): единственная команда, которой нужен интернет.

Порядок — как у весов на сервере (vLLM, CURRENT-STATE.md, «Жизненный цикл весов»): загрузка в <каталог>.incoming,
манифест sha256 каждого файла, перенос готовым каталогом; поверх существующего каталога не пишет. models verify
сверяет файлы с манифестом. Служба читает каталог только для чтения (ProtectSystem=strict).
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

MANIFEST = ".cleaner-manifest.json"
RUBERT_DIR = "rubert-base-pii-ner"
GLINER_DIR = "gliner-pii-base-v1.0"
DOCLING_DIR = "docling"
_RUBERT = ("redmadrobot-rnd/rubert-base-pii-ner", "c802e8cd26f85d1cf920973ea6f83965a0618d63")
_GLINER = ("knowledgator/gliner-pii-base-v1.0", "61726e0ad791dcab3e29339bbec3ad42ded65641")
CACHE = ".hf-download"


@dataclass(frozen=True)
class ModelSpec:
    directory: str                        # каталог внутри models_dir
    source: str                           # репозиторий Hugging Face или «docling»
    revision: Callable[[], str]           # закреплённая ревизия; у Docling — версия пакета, она закрепляет свои модели
    fetch: Callable[[Path], None]         # загрузка в пустой каталог
    required: tuple[str, ...] = ()        # файлы, которые читает загрузчик модели; у Docling набор меняется с версией


def _fetch_rubert(target: Path) -> None:
    from huggingface_hub import snapshot_download

    snapshot_download(
        _RUBERT[0], revision=_RUBERT[1], local_dir=target,
        allow_patterns=["config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json", "LICENSE", "README.md"],
    )


def _fetch_gliner(target: Path) -> None:
    """GLiNER сохраняется своим save_pretrained: так в каталог попадают конфигурация основы и токенизатор."""
    from gliner import GLiNER
    from huggingface_hub import snapshot_download

    source = target.with_name(target.name + ".source")
    shutil.rmtree(source, ignore_errors=True)
    snapshot_download(
        _GLINER[0], revision=_GLINER[1], local_dir=source,
        ignore_patterns=["onnx/model.onnx", "onnx/model_fp16.onnx", "trainer_state.json"],
    )
    try:
        GLiNER.from_pretrained(str(source)).save_pretrained(target, safe_serialization=True)
        # Файл ONNX quint8 — для ветки B2 задачи 3 (ner_models.GLINER_ONNX): чтобы переключение не требовало загрузки.
        (target / "onnx").mkdir(exist_ok=True)
        shutil.copy2(source / "onnx" / "model_quint8.onnx", target / "onnx" / "model_quint8.onnx")
    finally:
        shutil.rmtree(source, ignore_errors=True)


def _fetch_docling(target: Path) -> None:
    """Только раскладка страниц и таблицы: собственное распознавание Docling не нужно — сканы идут в ocr-ru."""
    from docling.utils.model_downloader import download_models

    download_models(
        output_dir=target, progress=True, with_layout=True, with_tableformer=True,
        with_code_formula=False, with_picture_classifier=False, with_rapidocr=False, with_easyocr=False,
    )


SPECS = (
    ModelSpec(RUBERT_DIR, _RUBERT[0], lambda: _RUBERT[1], _fetch_rubert,
              ("config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json")),
    ModelSpec(GLINER_DIR, _GLINER[0], lambda: _GLINER[1], _fetch_gliner,
              ("gliner_config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json", "onnx/model_quint8.onnx")),
    ModelSpec(DOCLING_DIR, "docling", lambda: importlib.metadata.version("docling-slim"), _fetch_docling),
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REDOWNLOAD = "удалите каталог и выполните models download"


def _files(directory: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != MANIFEST:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(block)
            result[path.relative_to(directory).as_posix()] = digest.hexdigest()
    return result


def prepare_download(models_dir: Path) -> Path:
    """Окружение этой команды: обращение к Hugging Face разрешено, кэш — во временном каталоге рядом с моделями.

    Вызывается до первого импорта huggingface_hub: библиотека читает переменные при импорте.
    """
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"):
        os.environ.pop(name, None)
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    cache = models_dir / CACHE
    cache.mkdir(parents=True, exist_ok=True)
    os.environ["HF_HOME"] = str(cache)
    return cache


def install(models_dir: Path, spec: ModelSpec, fetch: Callable[[Path], None] | None = None) -> Path:
    final = models_dir / spec.directory
    if final.exists():
        raise ValueError(f"{final} уже есть: сверить — models verify; заменить — удалить каталог и загрузить заново")
    incoming = models_dir / f"{spec.directory}.incoming"
    shutil.rmtree(incoming, ignore_errors=True)          # прошлая загрузка прервана
    incoming.mkdir(parents=True)
    (fetch or spec.fetch)(incoming)
    # Служебные файлы huggingface_hub — в корне и в каталоге каждой модели (Docling качает несколько в подкаталоги):
    # это не поставка, и в манифесте их быть не должно.
    for cache in sorted(incoming.rglob(".cache"), key=lambda path: len(path.parts), reverse=True):
        if cache.is_dir():
            shutil.rmtree(cache, ignore_errors=True)
    manifest = {"source": spec.source, "revision": spec.revision(), "files": _files(incoming)}
    (incoming / MANIFEST).write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8")
    incoming.rename(final)
    return final


def verify(models_dir: Path, spec: ModelSpec) -> list[str]:
    """Каталог — та поставка, которую закрепляет spec: источник и ревизия манифеста, обязательные файлы, sha256
    каждого файла. Самосогласованный каталог прежней ревизии или пустой манифест — тоже провал: это проверка полноты
    и версии поставки, а не защита от того, кто может менять и модель, и манифест."""
    final = models_dir / spec.directory
    if not final.is_dir():
        return ["нет каталога: выполните models download"]
    try:
        manifest = json.loads((final / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = None
    expected = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(expected, dict) or not all(
        isinstance(name, str) and isinstance(digest, str) and _SHA256.fullmatch(digest) for name, digest in expected.items()
    ):
        return ["нет манифеста или он повреждён"]
    problems = []
    if not expected:
        problems.append(f"в манифесте нет файлов: {_REDOWNLOAD}")
    if manifest.get("source") != spec.source:
        problems.append(f"источник {manifest.get('source')} вместо {spec.source}: {_REDOWNLOAD}")
    if manifest.get("revision") != spec.revision():
        problems.append(f"ревизия {manifest.get('revision')} вместо закреплённой {spec.revision()}: {_REDOWNLOAD}")
    problems += [f"в манифесте нет обязательного файла {name}" for name in spec.required if name not in expected]
    actual = _files(final)
    problems += [f"изменён файл {name}" for name in sorted(expected) if name in actual and actual[name] != expected[name]]
    problems += [f"нет файла {name}" for name in sorted(set(expected) - set(actual))]
    problems += [f"лишний файл {name}" for name in sorted(set(actual) - set(expected))]
    return problems
