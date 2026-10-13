import pytest

from cleaner.core.types import ChatState, Settings


@pytest.fixture
def state() -> ChatState:
    return ChatState(chat_id="test", net_key=bytes(range(32)))


@pytest.fixture
def settings() -> Settings:
    return Settings()
