"""Приватный сокет установщика: приём закрыт, пока установщик держит соединение."""
from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from cleaner.queueing import Budget


class AgentExecutor(ThreadPoolExecutor):
    """Считает также закрытие потоков агента после разрыва HTTP-соединения."""

    def __init__(self, max_workers: int):
        super().__init__(max_workers=max_workers, thread_name_prefix="cleaner-agent")
        self._work_lock = threading.Lock()
        self._pending_work = 0

    def submit(self, fn, /, *args, **kwargs):
        with self._work_lock:
            self._pending_work += 1
        try:
            future = super().submit(fn, *args, **kwargs)
        except BaseException:
            self._finished()
            raise
        future.add_done_callback(self._finished)
        return future

    def _finished(self, _future=None) -> None:
        with self._work_lock:
            self._pending_work -= 1

    def pending(self) -> int:
        with self._work_lock:
            return self._pending_work


class UpdateDrain:
    def __init__(self, budget: Budget, agents: AgentExecutor, socket_path: str):
        self.budget = budget
        self.agents = agents
        self.path = Path(socket_path) if socket_path else None
        self.requests = 0
        self.client: asyncio.StreamWriter | None = None

    def count(self) -> int:
        jobs, _ = self.budget.usage()
        # Запрос может держать задания, а поток агента — потоки пула. Это сумма операций,
        # которые надо дождаться, включая уже отсоединившихся HTTP-клиентов.
        return self.requests + jobs + self.agents.pending()

    @asynccontextmanager
    async def listen(self):
        if self.path is None:
            yield
            return
        # Родительский каталог создаёт systemd с правами 0700. При запуске нового
        # экземпляра старый разъём мог остаться после аварийной остановки.
        self.path.unlink(missing_ok=True)
        server = await asyncio.start_unix_server(self._serve, path=self.path)
        try:
            yield
        finally:
            server.close()
            if self.client is not None:
                self.client.close()
            await server.wait_closed()
            self.path.unlink(missing_ok=True)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            if self.client is not None:
                writer.write(b"busy\n")
                await writer.drain()
                return
            self.client = writer
            while True:
                pending = self.count()
                writer.write(f"{pending}\n".encode("ascii"))
                await writer.drain()
                if not pending:
                    # До остановки приём закрыт. При выходе установщика сокет
                    # закрывается и допуск возобновляется без действий оператора.
                    await reader.read(1)
                    return
                try:
                    await asyncio.wait_for(reader.read(1), timeout=0.25)
                except TimeoutError:
                    continue
                return
        except OSError:
            pass
        finally:
            if self.client is writer:
                self.client = None
            writer.close()
