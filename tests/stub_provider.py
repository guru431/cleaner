"""Заглушка облачного провайдера на петле (AC-3.2…AC-3.6, AC-4.3): запоминает запросы и отвечает событиями
протокола, по которому её спросили; без "stream": true — обычным ответом OpenAI-совместимого шлюза."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class StubProvider:
    def __init__(self) -> None:
        self.requests: list[dict] = []          # path, headers, body
        self.pieces: list[str] = ["Ответ"]
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> StubProvider:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()

    def bodies(self) -> str:
        return json.dumps([request["body"] for request in self.requests], ensure_ascii=False)

    def _events(self, path: str, body: dict) -> tuple[list[dict], str] | None:
        if path.endswith("/chat/completions"):
            return [{"choices": [{"delta": {"content": piece}}]} for piece in self.pieces], "data: [DONE]\n\n"
        if path.endswith("/v1/messages"):
            events = [{"type": "message_start", "message": {}}]
            events += [{"type": "content_block_delta", "delta": {"type": "text_delta", "text": p}} for p in self.pieces]
            return events + [{"type": "message_stop"}], ""
        return None

    def _handler(stub) -> type[BaseHTTPRequestHandler]:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
                stub.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if not body.get("stream"):
                    payload = {"choices": [{"message": {"content": "".join(stub.pieces)}, "finish_reason": "stop"}]}
                    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                found = stub._events(self.path, body)
                if found is None:
                    self.send_error(404)
                    return
                events, tail = found
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.end_headers()
                for event in events:
                    self.wfile.write(f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8"))
                    self.wfile.flush()
                self.wfile.write(tail.encode("utf-8"))

        return Handler
