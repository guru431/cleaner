"""Decompressed response limits shared by application and agent SSE transports."""
import re

from cleaner.egress import ProviderError

RESPONSE_BYTES = 32 * 1024 * 1024
EVENT_BYTES = 2 * 1024 * 1024
_LINEBREAK = re.compile(rb"\r\n|\r|\n")


class ResponseLimit(ProviderError):
    def __init__(self):
        super().__init__("превышен предел размера ответа или события провайдера")


def bounded_lines(chunks, *, response_bytes=RESPONSE_BYTES, event_bytes=EVENT_BYTES, max_lines=None):
    pending, total, count = b"", 0, 0
    for chunk in chunks:
        total += len(chunk)
        if total > response_bytes:
            raise ResponseLimit()
        pending += chunk
        start = 0
        for boundary in _LINEBREAK.finditer(pending):
            if boundary.group() == b"\r" and boundary.end() == len(pending):
                break  # CRLF may span two chunks.
            count += 1
            if boundary.start() - start > event_bytes or max_lines is not None and count > max_lines:
                raise ResponseLimit()
            yield pending[start:boundary.start()].decode("utf-8", errors="replace")
            start = boundary.end()
        pending = pending[start:]
        if len(pending) > event_bytes:
            raise ResponseLimit()
    if pending:
        if max_lines is not None and count >= max_lines:
            raise ResponseLimit()
        yield pending.rstrip(b"\r").decode("utf-8", errors="replace")
