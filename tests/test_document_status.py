"""Контракт статусов Docling без моделей, исходных документов и импорта тяжёлого конвейера."""
import sys
from types import ModuleType, SimpleNamespace

import pytest

from cleaner.ingest.documents import Docling
from cleaner.ingest.extract import ExtractError


@pytest.mark.parametrize("status", ["partial_success", "failure", "success"])
def test_docling_status_does_not_turn_partial_text_into_complete_import(tmp_path, monkeypatch, caplog, status):
    base = ModuleType("docling.datamodel.base_models")
    base.DocumentStream = lambda **kwargs: SimpleNamespace(**kwargs)
    monkeypatch.setitem(sys.modules, "docling.datamodel.base_models", base)
    document = SimpleNamespace(export_to_markdown=lambda **kwargs: "extracted fragment")
    result = SimpleNamespace(status=SimpleNamespace(value=status), document=document,
                             errors=[SimpleNamespace(error_message="private synthetic canary")])
    parser = Docling(tmp_path)
    parser._converter = SimpleNamespace(convert=lambda stream: result)
    if status == "success":
        assert parser.convert(b"synthetic", "docx") == "extracted fragment"
    else:
        with pytest.raises(ExtractError) as failure:
            parser.convert(b"synthetic", "docx")
        assert "private synthetic canary" not in str(failure.value) + caplog.text
        assert ("не полностью" in str(failure.value)) == (status == "partial_success")
