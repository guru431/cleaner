from datetime import datetime, timedelta, timezone

import pytest

from cleaner.core.types import ChatState, Settings


@pytest.fixture
def state() -> ChatState:
    return ChatState(chat_id="test", net_key=bytes(range(32)))


@pytest.fixture
def settings() -> Settings:
    return Settings()


class FakeClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.current

    def advance(self, **delta: float) -> None:
        self.current += timedelta(**delta)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
