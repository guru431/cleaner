"""Вытеснение производных оригиналов при удалении чата. Таблицы без владельца очищаются целиком."""
import threading
from weakref import WeakValueDictionary

from cleaner.core import leakcheck, match, surrogates
from cleaner.core.detect import dictionary
from cleaner.core.entities import hostmap, labels, names, netmap
from cleaner.core.types import CacheLease, ChatState

_leases: WeakValueDictionary[str, CacheLease] = WeakValueDictionary()
_leases_lock = threading.Lock()


def lease_of(state: ChatState) -> CacheLease:
    if state.cache_lease is None:
        with _leases_lock:
            lease = _leases.get(state.chat_id)
            if lease is None:
                lease = CacheLease()
                _leases[state.chat_id] = lease
            state.cache_lease = lease
    return state.cache_lease


def invalidate_chat(chat_id: str) -> None:
    """Все ещё живые состояния и их снимки после удаления больше не заполняют кэши. Оригиналов и списка удалённых
    чатов здесь нет: слабая ссылка исчезает, когда заканчивается работа с последним состоянием."""
    with _leases_lock:
        lease = _leases.pop(chat_id, None)
        if lease is not None:
            lease.active = False
    forget_chat(chat_id)


def forget_chat(chat_id: str) -> None:
    leakcheck.forget_chat(chat_id)
    surrogates.forget_chat(chat_id)
    dictionary.clear_cache()
    clear_strings()


def clear_strings() -> None:
    """В том числе записи, которые успели нормализовать во время удаления, но уже не будут сохранять таблицей."""
    match._NEEDLES.clear()
    netmap._KEYS.clear()
    hostmap.has_known_suffix.cache_clear()
    labels._domain_name.cache_clear()
    for function in (names._word, names._kind, names.part_of_speech, names.animate):
        function.cache_clear()
