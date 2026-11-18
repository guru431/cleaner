import asyncio
import io
import threading

import httpx
import pytest
from fastapi.responses import StreamingResponse

from cleaner.web.app import UpdateAdmission
from deploy import drain_cleaner


class Installer:
    """Управляющее соединение той же формы, что у Unix-сокета."""

    def __init__(self):
        self.status = asyncio.Queue()
        self.reader = asyncio.StreamReader()

    def write(self, data):
        self.status.put_nowait(data)

    async def drain(self):
        pass

    def close(self):
        self.reader.feed_eof()


def test_installation_waits_for_accepted_work_and_reopens_admission_on_disconnect(app):
    drain = next(m.kwargs["drain"] for m in app.user_middleware if m.cls is UpdateAdmission)
    connection_started = threading.Event()
    connection_done = threading.Event()

    def detached_agent_cleanup():
        connection_started.set()
        connection_done.wait(3)

    async def scenario():
        stream_started = asyncio.Event()
        stream_done = asyncio.Event()

        async def stream():
            stream_started.set()
            await stream_done.wait()
            yield b"data: complete\n\n"

        app.add_api_route("/test/stream", lambda: StreamingResponse(stream()), methods=["GET"])
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http:
            accepted = asyncio.create_task(http.get("/test/stream"))
            await stream_started.wait()
            reservation = app.state.jobs.budget.reserve("owner")
            future = app.state.agent_pool.submit(detached_agent_cleanup)
            await asyncio.to_thread(connection_started.wait, 3)
            installer = Installer()
            preparing = asyncio.create_task(drain._serve(installer.reader, installer))
            try:
                assert await installer.status.get() == b"3\n"
                new = await http.post("/agent/openai/v1/chat/completions", json={})
                assert new.status_code == 503 and new.headers["retry-after"] == "5"
                assert new.json()["error"]["message"].startswith("Cleaner:")
                assert (await http.post("/api/v1/chats", json={})).status_code == 503

                second = Installer()
                await drain._serve(second.reader, second)
                assert await second.status.get() == b"busy\n"

                stream_done.set()
                assert (await accepted).content == b"data: complete\n\n"
                assert await installer.status.get() == b"2\n"
                reservation.release()
                assert await installer.status.get() == b"1\n"
                connection_done.set()
                await asyncio.wrap_future(future)
                assert await installer.status.get() == b"0\n"
                assert (await http.get("/login")).status_code == 503
            finally:
                installer.close()
                reservation.release()
                stream_done.set()
                connection_done.set()
                await accepted
                await preparing
            assert (await http.get("/login")).status_code == 200

            # Установщик может уйти по таймауту до готовности. Приём снова
            # открывается, даже если фоновое задание ещё не завершено.
            reservation = app.state.jobs.budget.reserve("owner")
            installer = Installer()
            preparing = asyncio.create_task(drain._serve(installer.reader, installer))
            try:
                assert await installer.status.get() == b"1\n"
                installer.close()
                await preparing
                assert (await http.get("/login")).status_code == 200
            finally:
                installer.close()
                reservation.release()
                await preparing

    asyncio.run(scenario())


class PendingSocket:
    def makefile(self, mode):
        return io.BytesIO(b"3\n2\n")

    def settimeout(self, timeout):
        assert timeout > 0


def test_drain_timeout_reports_last_unfinished_count(monkeypatch):
    clock = iter((10, 10, 11, 13))
    monkeypatch.setattr(drain_cleaner.time, "monotonic", lambda: next(clock))
    with pytest.raises(RuntimeError, match="незавершённых операций: 2"):
        drain_cleaner.wait_until_idle(PendingSocket(), timeout=2)
