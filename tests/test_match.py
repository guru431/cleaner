from cleaner.core.match import find_forms


def hits(text: str, *forms) -> list[tuple[str, object]]:
    return sorted((text[start:end], payload) for start, end, payload in find_forms(text, forms))


def test_letters_mode_matches_next_to_punctuation_and_digits_but_not_inside_words():
    assert hits("ivanov_backup, Ivanov2 и ivanova", ("ivanov", "letters", 1)) == [("Ivanov", 1), ("ivanov", 1)]


def test_strict_mode_needs_clean_edges():
    text = "srv-dc01 srv-dc012 xsrv-dc01 srv-dc01.corp"
    assert hits(text, ("srv-dc01", "strict", 1)) == [("srv-dc01", 1), ("srv-dc01", 1)]


def test_digit_edges_do_not_match_inside_longer_numbers():
    assert hits("10.1.2.3 и 10.1.2.35 и 110.1.2.3", ("10.1.2.3", "strict", 1)) == [("10.1.2.3", 1)]
    assert hits("17707083893", ("7707083893", "letters", 1)) == []


def test_none_mode_matches_anywhere():
    assert hits("Иванов", ("вано", "none", 1)) == [("вано", 1)]


def test_search_ignores_case_and_returns_original_offsets():
    assert hits("Пишет ИВАНОВ", ("иванов", "letters", "p")) == [("ИВАНОВ", "p")]


def test_any_run_of_whitespace_matches_a_single_space():
    """Обзор 1А, P1: двойной пробел, неразрывный пробел и перевод строки между словами."""
    text = "Иванов  Иван Иванович; Иванов\r\nИван Иванович"
    found = hits(text, ("Иванов Иван Иванович", "letters", 1))
    assert found == sorted([("Иванов  Иван Иванович", 1), ("Иванов\r\nИван Иванович", 1)])


def test_yo_and_decomposed_letters_match_their_plain_forms():
    """Обзор 1А, P1: «ё» и «е» — одна буква; «ё» из двух знаков (NFD) — тоже."""
    text = "Семенов, Семёнов и СЕМЁНОВ"
    found = hits(text, ("Семёнов", "letters", 1))
    assert found == sorted([("Семенов", 1), ("Семёнов", 1), ("СЕМЁНОВ", 1)])
