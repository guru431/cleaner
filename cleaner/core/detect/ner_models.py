"""Модели слоя 4 на процессоре (раздел 5.5): загружаются один раз при первом обращении и работают по одной.

Сеть не нужна: только локальные файлы (local_files_only), служба запущена с HF_HUB_OFFLINE=1.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path

from cleaner.core.detect.base import DetectorError
from cleaner.core.detect.ner import THRESHOLD, Found, NerLayer, windows
from cleaner.models import GLINER_DIR, RUBERT_DIR

log = logging.getLogger("cleaner.ner")

THREADS = 4             # процессор делится с эмбеддингами, распознаванием страниц и речи (NFR-3)
# Ветка B2 проверки начала этапа 2 (задача 3): обе константы — True. Только для rubert: динамическое квантование
# GLiNER ломает (замер 14.10: ноль находок), у него вместо этого — ONNX-файл quint8 из репозитория модели.
QUANTIZE = False
GLINER_ONNX = False
GLINER_ONNX_FILE = "onnx/model_quint8.onnx"
GLINER_LABELS = ("name", "organization", "location address")
_RUN = threading.Lock()  # модели выполняются по одной, чтобы не занимать все ядра


class RubertTagger:
    """redmadrobot-rnd/rubert-base-pii-ner: окно 512 токенов с шагом 128 (раздел 5.5, карточка модели)."""

    def __init__(self, path: Path):
        import torch
        from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

        torch.set_num_threads(THREADS)
        model = AutoModelForTokenClassification.from_pretrained(path, local_files_only=True)
        if QUANTIZE:
            model = torch.ao.quantization.quantize_dynamic(model, {torch.nn.Linear}, dtype=torch.qint8)
        tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
        self._pipe = pipeline(
            "token-classification", model=model, tokenizer=tokenizer,
            aggregation_strategy="simple", stride=128, device="cpu",
        )

    def tag(self, text: str) -> list[Found]:
        if not text.strip():
            return []
        with _RUN:
            entities = self._pipe(text)
        return [Found(int(e["start"]), int(e["end"]), str(e["entity_group"]), float(e["score"])) for e in entities]


class GlinerTagger:
    """knowledgator/gliner-pii-base-v1.0: окна по 200 слов с перекрытием 40 — модель не видит дальше ~512 токенов."""

    def __init__(self, path: Path):
        import torch
        from gliner import GLiNER

        torch.set_num_threads(THREADS)
        if GLINER_ONNX:
            import onnxruntime

            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = THREADS          # по умолчанию ONNX Runtime занял бы все ядра
            options.inter_op_num_threads = 1
            self._model = GLiNER.from_pretrained(
                str(path), local_files_only=True, load_onnx_model=True, onnx_model_file=GLINER_ONNX_FILE,
                session_options=options,
            )
        else:
            self._model = GLiNER.from_pretrained(str(path), local_files_only=True)
            self._model.eval()

    def tag(self, text: str) -> list[Found]:
        found: list[Found] = []
        for start, end in windows(text):
            with _RUN:
                entities = self._model.predict_entities(text[start:end], list(GLINER_LABELS), threshold=THRESHOLD)
            found += [Found(start + int(e["start"]), start + int(e["end"]), str(e["label"]), float(e["score"])) for e in entities]
        return found


class NerModels:
    def __init__(self, models_dir: Path):
        self.models_dir = models_dir
        self._layer: NerLayer | None = None
        self._lock = threading.Lock()

    def layer(self) -> NerLayer:
        with self._lock:
            if self._layer is None:
                missing = [name for name in (RUBERT_DIR, GLINER_DIR) if not (self.models_dir / name).is_dir()]
                if missing:
                    raise DetectorError(f"Слой 4 недоступен: модели не загружены ({', '.join(missing)}); выполните models download")
                try:
                    taggers = [RubertTagger(self.models_dir / RUBERT_DIR), GlinerTagger(self.models_dir / GLINER_DIR)]
                except Exception as exc:
                    log.error("загрузка моделей слоя 4: %s", type(exc).__name__)
                    raise DetectorError("Слой 4 недоступен: модели не загружаются; сверьте их командой models verify") from None
                self._layer = NerLayer(taggers)
            return self._layer
