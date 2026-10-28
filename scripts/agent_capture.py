"""Заглушка провайдера Anthropic для записи настоящих запросов агента (спецификация 2026-10-28, раздел 18).

  python scripts/agent_capture.py --port 8765 --out <каталог записей> --script <сценарий.json>

Агент направляется на заглушку адресом (`ANTHROPIC_BASE_URL=http://127.0.0.1:8765`). Каждый запрос пишется файлом
`NNN.json` в `--out`: метод, путь с параметрами, заголовки (без `authorization` и `x-api-key`), тело — распакованное,
если оно сжато `gzip` или `deflate`, и разобранное, если это JSON.

Ответы:
- `POST /v1/messages` с инструментами (`tools`) — поток событий Anthropic очередного шага сценария; шаги идут по кругу.
  Сценарий — JSON-список шагов, шаг — список событий (`{"type": "message_start", …}`); событие уходит строкой SSE
  `event: <type>` / `data: <json>`. Аргументы вызова инструмента в сценарии пишутся одной дельтой `input_json_delta`.
- `POST /v1/messages` без инструментов (служебные запросы агента: заголовок сессии и т. п.) — короткий ответ «ok»,
  шаг сценария не расходуется; без `"stream": true` — ответ JSON.
- `POST /v1/messages/count_tokens` — 404 (агент считает сам); `HEAD /api/hello` — 204; остальное — 404.

Только стандартная библиотека: заглушка идёт и системным python3 сервера. Сеть — только 127.0.0.1.
"""
from __future__ import annotations

import argparse
import gzip
import itertools
import json
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DROPPED = {"authorization", "x-api-key"}


def _plain(text: str, stream: bool) -> tuple[str, bytes]:
    """Ответ «ok» служебному запросу: поток событий или JSON."""
    message = {"id": "msg_capture_ok", "type": "message", "role": "assistant", "model": "capture-model",
               "content": [], "stop_reason": None, "stop_sequence": None,
               "usage": {"input_tokens": 1, "output_tokens": 1}}
    if not stream:
        done = dict(message, content=[{"type": "text", "text": text}], stop_reason="end_turn")
        return "application/json", json.dumps(done).encode()
    events = [
        {"type": "message_start", "message": message},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
         "usage": {"output_tokens": 1}},
        {"type": "message_stop"},
    ]
    return "text/event-stream", sse(events)


def sse(events: list[dict]) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e, ensure_ascii=False)}\n\n" for e in events).encode()


def make_handler(out: Path, steps: list[list[dict]]) -> type[BaseHTTPRequestHandler]:
    counter = itertools.count(1)
    cycle = itertools.cycle(range(len(steps)))
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")

        def _record(self, body: bytes, step: int | None) -> None:
            encoding = self.headers.get("content-encoding", "").lower()
            raw = body
            if encoding == "gzip":
                raw = gzip.decompress(body)
            elif encoding == "deflate":
                raw = zlib.decompress(body)
            try:
                parsed: object = json.loads(raw) if raw else None
            except ValueError:
                parsed = raw.decode("utf-8", "replace")
            record = {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items() if k.lower() not in DROPPED},
                "body_bytes": len(body),
                "step": step,
                "body": parsed,
            }
            with lock:
                n = next(counter)
            (out / f"{n:03d}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

        def _send(self, code: int, ctype: str = "", payload: bytes = b"") -> None:
            self.send_response(code)
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload and self.command != "HEAD":
                self.wfile.write(payload)

        def do_HEAD(self) -> None:
            self._record(b"", None)
            self._send(204 if self.path.split("?")[0] == "/api/hello" else 404)

        def do_GET(self) -> None:
            self._record(b"", None)
            self._send(404, "application/json", b'{"type":"error","error":{"type":"not_found_error","message":"capture"}}')

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("content-length", "0") or 0))
            route = self.path.split("?")[0]
            if route != "/v1/messages":
                self._record(body, None)
                self._send(404, "application/json",
                           b'{"type":"error","error":{"type":"not_found_error","message":"capture"}}')
                return
            encoding = self.headers.get("content-encoding", "").lower()
            raw = gzip.decompress(body) if encoding == "gzip" else zlib.decompress(body) if encoding == "deflate" else body
            request = json.loads(raw)
            stream = bool(request.get("stream"))
            if not request.get("tools") or not stream:
                self._record(body, None)
                self._send(200, *_plain("ok", stream))
                return
            with lock:
                step = next(cycle)
            self._record(body, step)
            self._send(200, "text/event-stream", sse(steps[step]))

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Заглушка Anthropic для записи запросов агента")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    args = parser.parse_args(argv)
    steps = json.loads(args.script.read_text(encoding="utf-8"))
    args.out.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.out, steps))
    print(f"слушаю 127.0.0.1:{args.port}, записи — {args.out}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
