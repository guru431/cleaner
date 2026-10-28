"""Заглушка облачного провайдера на петле (AC-3.2…AC-3.6, AC-4.3, AC-5.1): запоминает запросы и отвечает событиями
протокола, по которому её спросили; без "stream": true — обычным ответом OpenAI-совместимого шлюза.

script — ответы шлюзу агентов (план 5Б) на POST /v1/messages по шагам, очередной шаг на каждый запрос: список событий
Anthropic (уходят строками «event: …» / «data: …»; без message_stop — поток оборван) или словарь —
{"status": 429, "body": {…}, "headers": {…}} (ответ ошибкой), {"message": {…}} (ответ без потока).
count_tokens — 404, как у провайдера без этого маршрута."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class StubProvider:
    def __init__(self, script: list | None = None) -> None:
        self.requests: list[dict] = []          # path, headers, body
        self.pieces: list[str] = ["Ответ"]
        self.script: list = list(script or [])
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        # Опрос раз в 0,05 с, а не в 0,5: остановка заглушки иначе добавляет полсекунды каждому тесту.
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.lock = threading.Lock()

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

    def headers(self, number: int = -1) -> dict[str, str]:
        """Заголовки запроса number — в нижнем регистре."""
        return {name.lower(): value for name, value in self.requests[number]["headers"].items()}

    def _events(self, path: str, body: dict) -> tuple[list[dict], str] | None:
        if path.endswith("/chat/completions"):
            return [{"choices": [{"delta": {"content": piece}}]} for piece in self.pieces], "data: [DONE]\n\n"
        if path.endswith("/v1/messages"):
            events = [{"type": "message_start", "message": {}}]
            events += [{"type": "content_block_delta", "delta": {"type": "text_delta", "text": p}} for p in self.pieces]
            return events + [{"type": "message_stop"}], ""
        return None

    def _step(self) -> dict:
        with self.lock:
            step = self.script.pop(0)
        return {"events": step} if isinstance(step, list) else step

    def _handler(stub) -> type[BaseHTTPRequestHandler]:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def _json(self, status: int, payload: object, headers: dict | None = None) -> None:
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
                stub.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                route = self.path.split("?")[0]
                if stub.script and route.endswith("/v1/messages"):
                    self._scripted(stub._step())
                    return
                if not body.get("stream"):
                    self._json(200, {"choices": [{"message": {"content": "".join(stub.pieces)}, "finish_reason": "stop"}]})
                    return
                found = stub._events(route, body)
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

            def _scripted(self, step: dict) -> None:
                if "status" in step:
                    self._json(step["status"], step.get("body", {}), step.get("headers"))
                    return
                if "message" in step:
                    self._json(200, step["message"])
                    return
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("request-id", "req_stub")
                self.end_headers()
                for event in step["events"]:
                    line = f"event: {event['type']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                    self.wfile.write(line.encode("utf-8"))
                    self.wfile.flush()

        return Handler
