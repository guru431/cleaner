"""Заглушка провайдера для записи настоящих запросов агента (спецификация 2026-10-28, раздел 18): Anthropic Messages,
OpenAI Chat Completions и OpenAI Responses — по пути запроса.

  python scripts/agent_capture.py --port 8765 --out <каталог записей> [--script <сценарий.json>] [--headers-only]

Агент направляется на заглушку адресом (`ANTHROPIC_BASE_URL=http://127.0.0.1:8765`, `base_url` провайдера Codex и
OpenCode — `http://127.0.0.1:8765/v1`). Каждый запрос пишется файлом `NNN.json` в `--out`: метод, путь с параметрами,
заголовки (без `authorization` и `x-api-key`), тело — распакованное, если оно сжато `gzip` или `deflate`, и разобранное,
если это JSON. С `--headers-only` тело не пишется (в нём личные инструкции профиля), а у `authorization` остаются
только схема и длина значения — так записываются запросы по подписке из настоящего профиля.

Ответы:
- `POST /v1/messages` (Anthropic), `POST …/chat/completions` (Chat Completions), `POST …/responses` (Responses) с
  инструментами (`tools`) — поток событий очередного шага сценария; шаги идут по кругу. Сценарий — JSON-список шагов,
  шаг — список событий: у Anthropic и Responses событие уходит строкой SSE `event: <type>` / `data: <json>`, у Chat
  Completions — `data: <json>` (часть `chat.completion.chunk`), после шага — `data: [DONE]`. Аргументы вызова в
  сценарии пишутся одной частью: дельтой `input_json_delta`, частью `tool_calls` или `arguments`/`input` в
  `response.output_item.done`.
- Те же пути без инструментов (служебные запросы агента: заголовок сессии и т. п.) или без сценария — короткий ответ
  «ok» в виде протокола, шаг сценария не расходуется; без `"stream": true` — ответ JSON.
- `POST /v1/messages/count_tokens` — 404 (агент считает сам); `HEAD /api/hello` — 204; остальное — 404.

Подстановки в строках шага — из результатов инструментов в запросе (`tool_result`, сообщения `tool`, элементы
`…_output`), начиная с последнего: `{{line:<начало>}}` — строка, которая так начинается (без номера строки, который
ставит Read у Claude Code), `{{re:<выражение>}}` — первое совпадение. Так сценарий «прочитать файл → правка» берёт строку
файла в том виде, в каком её увидела модель за шлюзом. В `partial_json` и `arguments` (строки JSON) подставленное
экранируется для JSON. Подставить нечего — строка остаётся как есть.

Только стандартная библиотека: заглушка идёт и системным python3 сервера. Сеть — только 127.0.0.1.
"""
from __future__ import annotations

import argparse
import gzip
import itertools
import json
import re
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DROPPED = {"authorization", "x-api-key"}
_JSON_STRINGS = ("partial_json", "arguments")      # строки JSON: подставленное в них экранируется


def _protocol(route: str) -> str | None:
    if route == "/v1/messages":
        return "anthropic"
    if route.endswith("/chat/completions"):
        return "chat"
    return "responses" if route.endswith("/responses") else None


def _has_tools(request: dict) -> bool:
    """Запрос с инструментами — ход агента; Codex в «code mode» шлёт их элементом input вида additional_tools."""
    items = request.get("input") if isinstance(request.get("input"), list) else ()
    return bool(request.get("tools")) or any(isinstance(i, dict) and i.get("type") == "additional_tools" for i in items)


def _plain_chat(text: str, stream: bool) -> tuple[str, bytes]:
    head = {"id": "chatcmpl-capture-ok", "created": 0, "model": "capture-model"}
    usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    if not stream:
        done = dict(head, object="chat.completion", usage=usage, choices=[
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"},
        ])
        return "application/json", json.dumps(done).encode()
    chunks = [
        dict(head, object="chat.completion.chunk", choices=[
            {"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None},
        ]),
        dict(head, object="chat.completion.chunk", choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}]),
        dict(head, object="chat.completion.chunk", choices=[], usage=usage),
    ]
    return "text/event-stream", sse(chunks, "chat")


def _plain_responses(text: str, stream: bool) -> tuple[str, bytes]:
    item = {"type": "message", "id": "msg_capture_ok", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}]}
    response = {"id": "resp_capture_ok", "object": "response", "created_at": 0, "status": "completed",
                "model": "capture-model", "output": [item],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
    if not stream:
        return "application/json", json.dumps(response).encode()
    events = [
        {"type": "response.created", "response": dict(response, status="in_progress", output=[], usage=None)},
        {"type": "response.output_item.added", "output_index": 0, "item": dict(item, status="in_progress", content=[])},
        {"type": "response.output_text.delta", "item_id": item["id"], "output_index": 0, "content_index": 0,
         "delta": text},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": response},
    ]
    return "text/event-stream", sse(events)


def _plain(text: str, stream: bool, protocol: str = "anthropic") -> tuple[str, bytes]:
    """Ответ «ok» служебному запросу: поток событий или JSON."""
    if protocol == "chat":
        return _plain_chat(text, stream)
    if protocol == "responses":
        return _plain_responses(text, stream)
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


_SUBSTITUTION = re.compile(r"\{\{(line|re):(.+?)\}\}")
_LINE_NUMBER = re.compile(r"^\s*\d+\t")


def _joined(content: object) -> str:
    if isinstance(content, str):
        return content
    return "\n".join(part.get("text", "") for part in content or () if isinstance(part, dict))


def _results(request: dict) -> list[str]:
    """Тексты результатов инструментов в запросе, последний — первым: блоки tool_result (Anthropic), сообщения tool
    (Chat Completions), элементы input вида …_output (Responses)."""
    texts = []
    for message in request.get("messages") or ():
        if message.get("role") == "tool":
            texts.append(_joined(message.get("content")))
            continue
        for block in message.get("content") if isinstance(message.get("content"), list) else ():
            if isinstance(block, dict) and block.get("type") == "tool_result":
                texts.append(_joined(block.get("content")))
    items = request.get("input")
    for item in items if isinstance(items, list) else ():
        if isinstance(item, dict) and str(item.get("type", "")).endswith("_output"):
            texts.append(_joined(item.get("output")))
    return texts[::-1]


def _find(kind: str, argument: str, results: list[str]) -> str | None:
    for text in results:
        if kind == "re":
            m = re.search(argument, text)
            if m:
                return m.group()
            continue
        for line in text.splitlines():
            line = _LINE_NUMBER.sub("", line)
            if line.startswith(argument):
                return line
    return None


def render(step: list[dict], request: dict) -> list[dict]:
    """Шаг сценария с подстановками из запроса (см. описание модуля)."""
    results = _results(request)

    def walk(value: object, key: str = "") -> object:
        if isinstance(value, str):
            def substitute(m: re.Match[str]) -> str:
                argument = m.group(2)
                if key in _JSON_STRINGS:        # подстановка стоит внутри строки JSON — и её аргумент экранирован
                    try:
                        argument = json.loads(f'"{argument}"')
                    except ValueError:
                        pass
                found = _find(m.group(1), argument, results)
                if found is None:
                    return m.group()
                return json.dumps(found, ensure_ascii=False)[1:-1] if key in _JSON_STRINGS else found
            return _SUBSTITUTION.sub(substitute, value)
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, dict):
            return {name: walk(item, name) for name, item in value.items()}
        return value

    return walk(step)


def sse(events: list[dict], protocol: str = "anthropic") -> bytes:
    if protocol == "chat":
        return "".join(f"data: {json.dumps(e, ensure_ascii=False)}\n\n" for e in events).encode() + b"data: [DONE]\n\n"
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e, ensure_ascii=False)}\n\n" for e in events).encode()


def _scheme(value: str) -> str:
    """Значение authorization для записи: схема и длина, без самого токена."""
    scheme, _, token = value.partition(" ")
    return f"{scheme} ({len(token)})" if token else f"({len(value)})"


def make_handler(out: Path, steps: list[list[dict]], *, headers_only: bool = False) -> type[BaseHTTPRequestHandler]:
    counter = itertools.count(1)
    cycle = itertools.cycle(range(len(steps)))
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")

        def _record(self, body: bytes, step: int | None, raw: bytes | None = None) -> None:
            raw = body if raw is None else raw
            try:
                parsed: object = json.loads(raw) if raw else None
            except ValueError:
                parsed = raw.decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in self.headers.items() if k.lower() not in DROPPED}
            if headers_only and "authorization" in self.headers:
                headers["authorization"] = _scheme(self.headers["authorization"])
            record = {"method": self.command, "path": self.path, "headers": headers, "body_bytes": len(body), "step": step}
            if not headers_only:
                record["body"] = parsed
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
            protocol = _protocol(self.path.split("?")[0])
            encoding = self.headers.get("content-encoding", "").lower()
            raw = body
            try:
                raw = gzip.decompress(body) if encoding == "gzip" else zlib.decompress(body) if encoding == "deflate" else body
                request = json.loads(raw)
                if not isinstance(request, dict):
                    raise ValueError("request is not an object")
            except (ValueError, OSError, EOFError, zlib.error):
                self._record(body, None, raw)
                self._send(400 if protocol else 404, "application/json", b'{"error":{"message":"capture: body is not JSON"}}')
                return
            if protocol is None:
                self._record(body, None, raw)
                self._send(404, "application/json",
                           b'{"type":"error","error":{"type":"not_found_error","message":"capture"}}')
                return
            stream = bool(request.get("stream"))
            if not _has_tools(request) or not stream or not steps:
                self._record(body, None, raw)
                self._send(200, *_plain("ok", stream, protocol))
                return
            with lock:
                step = next(cycle)
            self._record(body, step, raw)
            self._send(200, "text/event-stream", sse(render(steps[step], request), protocol))

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Заглушка провайдера для записи запросов агента")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--script", type=Path)
    parser.add_argument("--headers-only", action="store_true", help="не писать тело, у authorization — схема и длина")
    args = parser.parse_args(argv)
    try:
        steps = json.loads(args.script.read_text(encoding="utf-8")) if args.script else []
    except (OSError, ValueError) as exc:
        parser.error(f"Не удалось прочитать сценарий: {type(exc).__name__}")
    if not isinstance(steps, list) or any(
        not isinstance(step, list) or any(not isinstance(event, dict) for event in step) for step in steps
    ):
        parser.error("Сценарий должен быть списком шагов, каждый шаг — список объектов событий")
    args.out.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port), make_handler(args.out, steps, headers_only=args.headers_only),
    )
    print(f"слушаю 127.0.0.1:{args.port}, записи — {args.out}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
