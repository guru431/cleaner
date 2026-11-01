"""Docling parse + PDFium render: Windows workaround for docling-parse #357.

https://github.com/docling-project/docling-parse/issues/357
The MinGW renderer frees thread-local storage before its destructors run. Keep the parser's text and
geometry (PDFium alone changes extraction), but never construct its renderer. Imports remain lazy in documents.py.
"""
from __future__ import annotations

import io
from functools import cache


@cache
def backend_class():
    """Construct the backend type only when a document actually needs Docling."""
    from docling.backend.docling_parse_backend import ThreadedDoclingParseDocumentBackend, ThreadedDoclingParsePageBackend
    from docling.backend.pypdfium2_backend import PyPdfiumDocumentBackend
    from docling.datamodel.backend_options import ThreadedDoclingParseBackendOptions

    class PdfiumRenderedPage(ThreadedDoclingParsePageBackend):
        def __init__(self, parsed, rendered):
            super().__init__(parsed._result, rendered=False)
            self._pdfium = rendered

        def get_page_image(self, scale=1, cropbox=None):
            return self._pdfium.get_page_image(scale, cropbox)

        def unload(self):
            self._pdfium.unload()

    class WindowsPdfBackend(ThreadedDoclingParseDocumentBackend):
        def __init__(self, in_doc, path_or_stream, options=None):
            options = (options or ThreadedDoclingParseBackendOptions()).model_copy(update={"render_pages": False})
            super().__init__(in_doc, path_or_stream, options)
            # Each backend closes its own stream; neither writes the source document to disk.
            source = io.BytesIO(path_or_stream.getvalue()) if isinstance(path_or_stream, io.BytesIO) else path_or_stream
            try:
                self._pdfium = PyPdfiumDocumentBackend(in_doc, source, options)
            except BaseException:
                super().unload()
                raise

        def iter_pages(self):
            for parsed in super().iter_pages():
                yield PdfiumRenderedPage(parsed, self._pdfium.load_page(parsed.page_no - 1))

        def unload(self):
            try:
                super().unload()
            finally:
                self._pdfium.unload()

    return WindowsPdfBackend
