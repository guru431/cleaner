from cleaner.core import surrogates
from cleaner.core.types import Surrogate


def test_longer_surrogates_win_and_edges_are_respected(state):
    state.surrogates.update(
        {
            "host-1": Surrogate("a", "srv", "host"),
            "host-10": Surrogate("b", "db", "host"),
            "<PERSON_1>": Surrogate("c"),
            "10.7.3.5": Surrogate("d", "10.1.2.5", "ip"),
        }
    )
    text = "host-10 HOST-1 xhost-1 <PERSON_1> 10.7.3.55 10.7.3.5."
    found = [text[start:end] for start, end in surrogates.find(state, text)]
    assert found == ["host-10", "HOST-1", "<PERSON_1>", "10.7.3.5"]
    assert surrogates.caseless(state)["host-1"].original == "srv"


def test_empty_table_finds_nothing(state):
    assert surrogates.build_pattern(state) is None
    assert surrogates.find(state, "<PERSON_1>") == []
