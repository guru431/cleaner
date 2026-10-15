"""Маленькие PDF для тестов: страница с текстом (Helvetica, латиница) или только с изображением — как скан."""
from __future__ import annotations

_FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
_IMAGE = (
    b"<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length 4 >>\n"
    b"stream\n\x00\xff\xff\x00\nendstream"
)


def make_pdf(pages: list[str | None]) -> bytes:
    """Строка — страница с этим текстом; None — страница, на которой только картинка."""
    bodies: dict[int, bytes] = {3: _FONT, 4: _IMAGE}
    kids: list[int] = []
    number = 5
    for text in pages:
        if text is None:
            stream = b"q 200 0 0 200 100 400 cm /Im1 Do Q"
        else:
            escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("latin-1")
            stream = b"BT /F1 12 Tf 72 720 Td (" + escaped + b") Tj ET"
        bodies[number] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        bodies[number + 1] = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R "
            b"/Resources << /Font << /F1 3 0 R >> /XObject << /Im1 4 0 R >> >> >>" % number
        )
        kids.append(number + 1)
        number += 2
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
