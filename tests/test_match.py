from cleaner.core.match import find_forms, normalize


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


def test_stress_marks_and_invisible_characters_do_not_stop_a_match():
    """Находка «Merge chains and invisible characters»: знак ударения, мягкий перенос, пробел нулевой ширины."""
    text = "Пишут Ива\u0301нов, Ива\u00adнов и Ива\u200bнов; Петрова\u0301 и Иван \u200b Петров"
    found = hits(text, ("Иванов", "letters", 1), ("Петрова", "letters", 2), ("Иван Петров", "letters", 3))
    # Найденный фрагмент накрывает и невидимые знаки, и ударение на последней букве.
    assert found == sorted([
        ("Ива\u0301нов", 1), ("Ива\u00adнов", 1), ("Ива\u200bнов", 1), ("Петрова\u0301", 2), ("Иван \u200b Петров", 3),
    ])
    assert hits("Пишет Иванов.", ("Ива\u0301\u00adнов", "letters", 1)) == [("Иванов", 1)]
    assert normalize("Ива\u0301\u200bнов") == normalize("Иванов")


def test_invisible_characters_in_a_decomposed_text_drop_out_too():
    text = "Семе\N{COMBINING DIAERESIS}нов и Ива\N{COMBINING ACUTE ACCENT}\N{ZERO WIDTH SPACE}нов"
    found = hits(text, ("Иванов", "letters", 1), ("Семёнов", "letters", 2))
    assert found == sorted([("Семе\N{COMBINING DIAERESIS}нов", 2), ("Ива\N{COMBINING ACUTE ACCENT}\N{ZERO WIDTH SPACE}нов", 1)])


def test_accents_that_are_part_of_a_letter_still_count():
    """Отбрасывается только ударение, не вошедшее в букву: «é» и «й» в любой записи — свои буквы."""
    text = "Jose\u0301, José и Jose; Мои\u0306 и Мои"
    assert hits(text, ("José", "letters", 1)) == sorted([("Jose\u0301", 1), ("José", 1)])
    assert hits(text, ("Мой", "letters", 2)) == [("Мои\u0306", 2)]


def test_yo_and_decomposed_letters_match_their_plain_forms():
    """Обзор 1А, P1: «ё» и «е» — одна буква; «ё» из двух знаков (NFD) — тоже."""
    text = "Семенов, Семёнов и СЕМЁНОВ"
    found = hits(text, ("Семёнов", "letters", 1))
    assert found == sorted([("Семенов", 1), ("Семёнов", 1), ("СЕМЁНОВ", 1)])
