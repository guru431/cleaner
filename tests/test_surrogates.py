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


def test_composite_host_name_is_found_whole_and_by_parts(state):
    state.surrogates.update(
        {
            "host-1": Surrogate("a", "srv-web01", "host"),
            "domain-1.example": Surrogate("b", "contoso.ru", "host"),
            "host-1.domain-1.example": Surrogate("a", "srv-web01.contoso.ru", "host"),
        }
    )
    text = "host-1.domain-1.example и newbox.domain-1.example"
    hits = surrogates.Finder(state).finditer(text)
    assert [(hit.group(), hit.key) for hit in hits] == [
        ("host-1.domain-1.example", "host-1.domain-1.example"),
        ("domain-1.example", "domain-1.example"),
    ]


def test_loose_search_knows_a_surrogate_in_another_notation(state):
    state.surrogates.update(
        {
            "02:00:00:00:00:01": Surrogate("m", "00:1A:2B:3C:4D:5E", "mac"),
            "S-1-5-21-1111111111-2222222222-3333333331": Surrogate("s", "S-1-5-21-1-2-3", "sid"),
        }
    )
    text = "02-00-00-00-00-01 и S-1-5-21-1111111111-2222222222-3333333331-1104"
    strict = [hit.group() for hit in surrogates.Finder(state).finditer(text)]
    loose = [text[start:end] for start, end in surrogates.find(state, text)]
    assert strict == ["S-1-5-21-1111111111-2222222222-3333333331"]
    assert loose == ["02-00-00-00-00-01", "S-1-5-21-1111111111-2222222222-3333333331-1104"]


def test_empty_table_finds_nothing(state):
    assert surrogates.find(state, "<PERSON_1> host-1 10.7.3.5") == []
