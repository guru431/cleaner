"""Маленькие PDF для тестов: страница с текстом (Helvetica, латиница), только с изображением — как скан, или с
текстом и изображением — как скан с цифровым заголовком."""
from __future__ import annotations

_FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
_IMAGE = (
    b"<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length 4 >>\n"
    b"stream\n\x00\xff\xff\x00\nendstream"
)


def _text(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("latin-1")
    return b"BT /F1 12 Tf 72 720 Td (" + escaped + b") Tj ET"


def _stream(content: bytes, extra: bytes = b"") -> bytes:
    return b"<< /Length %d%s >>\nstream\n" % (len(content), extra) + content + b"\nendstream"


def make_pdf(pages: list[str | None | tuple[str, int]], form_scale: int = 0) -> bytes:
    """Строка — страница с этим текстом; None — страница, на которой только картинка; (текст, сторона) — текст
    вверху страницы и квадратная картинка с такой стороной в пунктах под ним (страница — 612×792).
    form_scale — картинка рисуется внутри Form XObject, а страница увеличивает форму во столько раз."""
    bodies: dict[int, bytes] = {3: _FONT, 4: _IMAGE}
    kids: list[int] = []
    number = 5
    for page in pages:
        resources = b"/Font << /F1 3 0 R >> /XObject << /Im1 4 0 R >>"
        if page is None:
            stream = b"q 200 0 0 200 100 400 cm /Im1 Do Q"
        elif isinstance(page, tuple):
            text, side = page
            if form_scale:
                drawn = b"q %d 0 0 %d 0 0 cm /Im1 Do Q" % (side // form_scale, side // form_scale)
                bodies[number + 2] = _stream(drawn, b" /Type /XObject /Subtype /Form /BBox [0 0 612 792] "
                                                    b"/Resources << /XObject << /Im1 4 0 R >> >>")
                resources = b"/Font << /F1 3 0 R >> /XObject << /Im1 4 0 R /Fm1 %d 0 R >>" % (number + 2)
                stream = _text(text) + b" q %d 0 0 %d 50 50 cm /Fm1 Do Q" % (form_scale, form_scale)
            else:
                stream = _text(text) + b" q %d 0 0 %d 50 50 cm /Im1 Do Q" % (side, side)
        else:
            stream = _text(page)
        bodies[number] = _stream(stream)
        bodies[number + 1] = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << %s >> >>"
            % (number, resources)
        )
        kids.append(number + 1)
        number = max(bodies) + 1            # номера объектов подряд: на это рассчитана таблица xref ниже
    bodies[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    bodies[2] = b"<< /Type /Pages /Kids [" + b" ".join(b"%d 0 R" % kid for kid in kids) + b"] /Count %d >>" % len(kids)
    out = bytearray(b"%PDF-1.4\n")
    offsets: dict[int, int] = {}
    for key in sorted(bodies):
        offsets[key] = len(out)
        out += b"%d 0 obj\n" % key + bodies[key] + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(bodies) + 1)
    for key in sorted(bodies):
        out += b"%010d 00000 n \n" % offsets[key]
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(bodies) + 1, xref)
    return bytes(out)
