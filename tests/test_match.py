from cleaner.core.match import Forms, find_forms, normalize


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


def test_long_spelling_is_found_like_a_short_one():
    """Написание длиннее 64 знаков ищется по началу и сверяется целиком: те же границы, регистр, «ё» и пробелы, что у
    короткого, и общее начало у разных написаний."""
    name = "ООО «Научно-производственное объединение Северная звезда» филиал Ёлкино"
    text = f"{name.upper()},  {name.replace(' ', chr(10))} и {name}ские, {name[:-1]}"
    assert len(name) > 64
    found = hits(text, (name, "letters", 1), (name.replace("Ёлкино", "Ёлкино-2"), "letters", 2))
    assert found == sorted([(name.upper(), 1), (name.replace(" ", "\n"), 1)])
    assert hits("srv-" + "a" * 70 + "-02 и x" + "srv-" + "a" * 70, ("srv-" + "a" * 70, "strict", 1)) == []


def test_long_spellings_sharing_whole_chunks_are_told_apart():
    """Длинные написания лежат деревом кусков по 64 знака: написания длиной ровно в кусок, на знак длиннее, в несколько
    кусков и одно — начало другого находятся каждое на своём месте."""
    base = "token-" + "a1" * 61       # 128 знаков — два куска
    forms = [base, base + "b", base + "b" * 70, base[:100], base[:65]]
    text = " ".join(form.upper() for form in forms) + " " + base[:-1] + " " + base + "c"
    assert hits(text, *((form, "strict", i) for i, form in enumerate(forms))) == sorted(
        (form.upper(), i) for i, form in enumerate(forms)
    )


def test_escaped_dot_is_a_dot_and_an_escaped_backslash_is_not():
    """Наблюдение раунда 3 имён узлов, P1: имя в регулярном выражении пишут через «\\.» («^srv01\\.contoso\\.ru$»), и
    известное «contoso.ru» в нём не находилось. «\\.» — точка, и написание с ним находит то же. Второе ревью, P3: в строке
    JSON, Java, C# то же выражение пишут через «\\\\.» («"^www\\\\.contoso\\\\.ru$"») — это тоже точка; три и четыре
    обратные косые перед точкой («\\\\\\\\.» в JSON — «\\\\.» выражения) — нет. Путь Windows («C:\\Users\\ivanov\\.ssh») и
    он же в JSON читаются, как прежде."""
    text = r'^srv01\.contoso\.ru$, CONTOSO\.RU, "contoso\\.ru", C:\Users\ivanov\.ssh, "C:\\Users\\ivanov\\.ssh"'
    found = hits(text, ("contoso.ru", "strict", 1), ("ivanov", "letters", 2), ("srv01\\.contoso", "strict", 3))
    assert found == sorted([
        (r"contoso\.ru", 1), (r"CONTOSO\.RU", 1), (r"contoso\\.ru", 1), ("ivanov", 2), ("ivanov", 2), (r"srv01\.contoso", 3),
    ])
    assert hits("srv01.contoso.ru", ("srv01\\.contoso.ru", "strict", 1)) == [("srv01.contoso.ru", 1)]
    assert hits(r"contoso\\\.ru contoso\\\\.ru", ("contoso.ru", "strict", 1)) == []


def test_escaped_at_is_an_at_and_a_doubled_backslash_is_not():
    """Ревью раунда 5, P3: в строке Perl и PHP и в выражении Perl «@» пишут через «\\» («ivanov\\@contoso.ru»): одна
    обратная косая перед «@» — то же «@», и известный адрес в такой записи находится; написание с ней — тоже. Две — нет:
    «\\\\@» в строке Perl — обратная косая и массив."""
    text = r'"ivanov\@contoso.ru", /^IVANOV\@contoso\.ru$/, "ivanov\\@contoso.ru", ivanov@contoso.ru'
    assert hits(text, ("ivanov@contoso.ru", "letters", 1)) == sorted([
        (r"ivanov\@contoso.ru", 1), (r"IVANOV\@contoso\.ru", 1), ("ivanov@contoso.ru", 1),
    ])
    assert hits("ivanov@contoso.ru", (r"ivanov\@contoso.ru", "letters", 1)) == [("ivanov@contoso.ru", 1)]


def test_extended_table_is_the_table_of_all_forms_and_the_old_one_stays_as_it_was():
    """Задача 5a плана 5Г: таблица прежних написаний дополняется новыми (новые сущности чата) — находки те же и в том же
    порядке, что у таблицы, собранной из всех написаний сразу; по прежней таблице ищут другие потоки, и она не меняется.
    Новые написания делят с прежними первое слово, длину, само написание и куски длинного написания."""
    long = "token-" + "a1" * 61
    first = [("ivanov", "letters", 1), ("user00001", "strict", 2), (long, "strict", 3), ("вано", "none", 4)]
    more = [("Ivanov", "strict", 5), ("user00002", "strict", 6), (long + "b", "strict", 7), (long[:100], "strict", 8),
            ("ово", "none", 9), ("user", "letters", 10)]
    text = f"ivanov, user00001 user00002 {long} {long}b {long[:100]} Иванов вово user"
    table = Forms(first)
    before = table.find(text)
    extended = table.extended(more)
    assert extended.find(text) == Forms(first + more).find(text)
    assert {payload for _, _, payload in extended.find(text)} == set(range(1, 11))
    assert table.find(text) == before == Forms(first).find(text)
    assert extended.extended([("vovo", "none", 11)]).find("vovo") == [(0, 4, 11)] and extended.find("vovo") == []


def test_yo_and_decomposed_letters_match_their_plain_forms():
    """Обзор 1А, P1: «ё» и «е» — одна буква; «ё» из двух знаков (NFD) — тоже."""
    text = "Семенов, Семёнов и СЕМЁНОВ"
    found = hits(text, ("Семёнов", "letters", 1))
    assert found == sorted([("Семенов", 1), ("Семёнов", 1), ("СЕМЁНОВ", 1)])
