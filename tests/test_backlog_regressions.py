"""Regression cases from the November 14 review; all contents are synthetic."""
import asyncio
import json
import urllib.error
from types import SimpleNamespace

import httpx
import pytest

from cleaner.agent_service import AgentService
from cleaner.egress.forward import Upstream
from cleaner.ingest import extract
from cleaner.service import ChatService
from cleaner.storage import codec
from cleaner.storage.repo import CheckpointBusy, Item
from cleaner.web import routes_api
from scripts import agent_capture
from scripts.checks import ocr_check
from tests.test_extract import Documents, Ocr
from pdfgen import make_pdf


@pytest.mark.parametrize("chunks,limit,expected", [
    ([b"safe:synthetic-secret:end"], 10, b"safe:***"),
    ([b"safe:synt", b"hetic-", b"secret:end"], 10, b"safe:***"),
    ([b"synthetic-secret" * 10], 10, b"***"),
])
def test_error_body_masks_a_secret_crossing_the_output_limit(chunks, limit, expected):
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield from chunks

    with httpx.Client() as client:
        response = httpx.Response(503, stream=Stream())
        upstream = Upstream(client, response, ("synthetic-secret",), owns_client=False)
        try:
            assert upstream.read(limit) == expected
        finally:
            upstream.close()


def test_error_body_masks_overlapping_credentials():
    with httpx.Client() as client:
        upstream = Upstream(client, httpx.Response(503, content=b"abcde"), ("abc", "bcd"), owns_client=False)
        try:
            assert upstream.read(5) == b"***e"
        finally:
            upstream.close()


def test_events_wait_for_a_queued_answer_and_find_the_late_live_stream(repo, monkeypatch):
    user = repo.create_user("synthetic", "hash", "user")
    chat = repo.create_chat(user, "test")
    repo.add_item(chat, Item("answer", 0, "answer", "", None, source="api", status="queued"))
    service = ChatService(repo)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(repo=repo, service=service)))

    async def connected():
        return False

    request.is_disconnected = connected
    monkeypatch.setattr(routes_api, "api_chat", lambda *args: None)
    sleeps = []

    async def advance(_):
        sleeps.append(1)
        assert len(sleeps) <= 2, "stream never reaches the stored terminal answer"
        if len(sleeps) == 1:
            service.live.start("answer").append("part")
            repo.set_item_status(chat, "answer", "running")
        else:
            repo.finish_answer(chat, "answer", "complete", "done", {})
            service.live.finish("answer")

    monkeypatch.setattr(routes_api.asyncio, "sleep", advance)

    async def collect():
        response = routes_api.answer_events(request, chat, "answer", None)
        return [event async for event in response.body_iterator]

    events = asyncio.run(collect())
    assert len(sleeps) == 2 and any(event.startswith("event: text\n") for event in events)
    assert '"status": "done"' in events[-1] and '"text": "complete"' in events[-1]


def test_single_input_view_does_not_build_the_answer_restorer(repo, monkeypatch):
    from cleaner import service as module

    user = repo.create_user("synthetic", "hash", "user")
    chat = repo.create_chat(user, "test")
    service = ChatService(repo)
    item = service.add_input(chat, user, "safe text")
    monkeypatch.setattr(module, "restore_answers", lambda *args: pytest.fail("unneeded restorer"))
    assert service.view(chat, item.id).items[0].item.id == item.id


def test_busy_pruning_does_not_report_a_negative_deletion_count(repo, clock, monkeypatch):
    service = AgentService(repo, None, clock)

    def busy(*args):
        raise CheckpointBusy()

    monkeypatch.setattr(repo, "prune_agent", busy)
    service._prune()
    assert repo.audit_events("agent_pruned") == []


@pytest.mark.integration
def test_scan_document_is_not_reopened_for_each_page(monkeypatch):
    opened = []
    original = extract._open_pdf

    def counted(data):
        document = original(data)
        opened.append(document)
        return document

    monkeypatch.setattr(extract, "_open_pdf", counted)
    result = extract.Extractor(Documents(), Ocr()).extract("scan.pdf", make_pdf([None] * 3))
    assert result.ocr_pages == (1, 2, 3)
    assert len(opened) <= 2
    assert all(not pdf.raw for pdf in opened)


def test_ocr_busy_retry_with_zero_delay_is_bounded(monkeypatch):
    def busy(*args, **kwargs):
        raise urllib.error.HTTPError("http://ocr.example", 503, "busy", {"Retry-After": "0"}, None)

    delays = []
    monkeypatch.setattr(ocr_check.urllib.request, "urlopen", busy)
    monkeypatch.setattr(ocr_check.time, "sleep", delays.append)
    assert ocr_check.ocr("http://ocr.example", "synthetic", b"image") == {"error": 503}
    assert delays and all(1 <= delay <= 60 for delay in delays)


@pytest.mark.parametrize("steps", [{}, ["step"], [["event"]]])
def test_capture_rejects_a_malformed_script_before_starting(tmp_path, monkeypatch, capsys, steps):
    script = tmp_path / "script.json"
    script.write_text(json.dumps(steps), encoding="utf-8")
    monkeypatch.setattr(agent_capture, "ThreadingHTTPServer", lambda *args: pytest.fail("server started"))
    with pytest.raises(SystemExit) as stopped:
        agent_capture.main(["--port", "8765", "--out", str(tmp_path / "out"), "--script", str(script)])
    assert stopped.value.code == 2
    assert "сценар" in capsys.readouterr().err.lower()
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("field,value", [
    ("rules", [["mask", "value", None, "none", "extra"]]),
    ("net_key", "%%%"),
    ("entities", [{"type": "UNKNOWN"}]),
])
def test_invalid_chat_state_has_a_safe_diagnostic(state, field, value):
    data = json.loads(codec.state_to_json(state))
    data[field] = value
    with pytest.raises(ValueError, match="Повреждено состояние чата"):
        codec.state_from_json(json.dumps(data).encode())
