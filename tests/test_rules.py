import pytest

from cleaner.core.detect import rules
from cleaner.core.detect.base import DetectContext
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import restore
from cleaner.core.types import EntityType as T
from cleaner.core.types import Settings

CTX = DetectContext(Settings())


def found(text: str) -> set[tuple[T, str]]:
    return {(span.type, text[span.start:span.end]) for span in rules.detect(text, CTX)}


def types(text: str) -> set[T]:
    return {type_ for type_, _ in found(text)}


def test_email_without_trailing_dot():
    assert (T.EMAIL, "i.ivanov@corp.example") in found("Пишите на i.ivanov@corp.example.")


@pytest.mark.parametrize("text, email", [
    ("пишите ivanov@<TERM_1>.fabrikam.ru.", "ivanov@<TERM_1>.fabrikam.ru"),
    ("пишите ivanov@host-1.[[ORG_1]], ответит", "ivanov@host-1.[[ORG_1]]"),
    ("пишите ivanov@<ORG_1>", "ivanov@<ORG_1>"),
    ("пишите ivanov@<PERSON_1>", None),
    ("пишите ivanov@localhost, a@b@c.example", "b@c.example"),
    ("пишите ivanov@contoso.ru.<TERM_1> завтра", "ivanov@contoso.ru"),
    ("пишите ivanov@srv02.contoso.ru.<ORG_1>.", "ivanov@srv02.contoso.ru.<ORG_1>"),
    ("пишите ivanov@host-1.<TERM_1>", "ivanov@host-1.<TERM_1>"),
], ids=["label-first", "label-last", "domain-label", "other-label", "no-dot", "label-after", "domain-label-after", "label-only-after"])
def test_email_with_a_label_in_its_domain(text, email):
    """FINDINGS «Retyping a host name part: what it leaves» (2): часть домена бывает меткой — части дали другой тип.
    Метка сама по себе — домен, только если выдана домену в имени (<org_1> из host-1.<ORG_1>). Обзор пакета, отклонённое:
    метка не домена после имени с точкой — уже не часть адреса («ivanov@contoso.ru.<TERM_1>» — адрес и метка за ним)."""
    ctx = DetectContext(Settings(), issued_domains=frozenset({"domain-1.example", "<org_1>"}))
    emails = [text[span.start:span.end] for span in rules.detect(text, ctx) if span.type is T.EMAIL]
    assert emails == ([email] if email else [])


@pytest.mark.parametrize("text, expected", [
    (r"if address :regex :all " + '"from" "^ivanov@contoso\\.ru$"', {(T.EMAIL, r"ivanov@contoso\.ru")}),
    (r"^i\.ivanov@mail\.contoso\.ru$", {(T.EMAIL, r"i\.ivanov@mail\.contoso\.ru")}),
    (r"^ivanov@contoso\.ru\.<TERM_1>", {(T.EMAIL, r"ivanov@contoso\.ru")}),
    (r"ssh ivanov@10\.1\.2\.5", {(T.ACCOUNT, "ivanov")}),
    (r'{"from": "^i\\.ivanov@contoso\\.ru$"}', {(T.EMAIL, r"i\\.ivanov@contoso\\.ru")}),
], ids=["sieve", "escaped-login", "label-after", "address", "json"])
def test_email_written_with_escaped_dots_is_found(text, expected):
    """Второе ревью, P2: в «^ivanov@contoso\\.ru$» (правило почты, регулярное выражение) слой 3 скрывал домен, а имя входа
    уходило открытым: шаблон e-mail брал только точки. «\\.» — точка и в домене, и в имени входа; в строке JSON, Java,
    C# то же выражение пишут через «\\\\.» (P3)."""
    assert found(text) == expected


@pytest.mark.parametrize("text", [
    r"ivanov@contoso\\\\.ru", r"C:\Users\ivanov\.ssh\id_rsa", r"user@ и @media", "a\\." * 3 + "@",
], ids=["escaped-backslash", "path", "no-domain", "no-login"])
def test_backslash_and_dot_elsewhere_make_no_email(text):
    """Та же находка с другой стороны: «\\\\\\\\.» (в JSON — обратная косая и любой знак выражения) — не точка; без
    домена с точкой адреса нет."""
    assert T.EMAIL not in types(text)


@pytest.mark.parametrize("text, expected", [
    (r'my $to = "ivanov\@contoso.ru";', {(T.EMAIL, r"ivanov\@contoso.ru")}),
    (r'$to = "i.ivanov\@mail.contoso.ru";', {(T.EMAIL, r"i.ivanov\@mail.contoso.ru")}),
    (r"if ($from =~ /^ivanov\@srv02\.contoso\.ru$/)", {(T.EMAIL, r"ivanov\@srv02\.contoso\.ru")}),
    (r'"ssh ivanov\@10.1.2.5"', {(T.ACCOUNT, "ivanov")}),
], ids=["perl", "dotted-login", "regex", "address"])
def test_email_with_an_escaped_at_is_found(text, expected):
    """Ревью раунда 5, P3: в строке Perl и PHP в двойных кавычках и в выражении Perl «@» пишут через «\\» — домен скрывал
    слой 3, а имя входа уходило открытым. Одна обратная косая перед «@» — часть адреса и остаётся в его значении."""
    assert found(text) == expected


@pytest.mark.parametrize("text", [
    r'"ivanov\\@contoso.ru"', r'print "user\@ ok"', r"C:\Users\@admin",
], ids=["escaped-backslash", "no-domain", "path"])
def test_escaped_at_elsewhere_makes_no_email(text):
    """Обратная сторона: «\\\\@» — обратная косая и массив Perl, не «@»; без домена с точкой адреса нет."""
    assert T.EMAIL not in types(text)


def test_phone_in_two_notations():
    result = found("Тел. +7 (916) 123-45-67, запасной 89161234567")
    assert (T.PHONE, "+7 (916) 123-45-67") in result
    assert (T.PHONE, "89161234567") in result


def test_local_phone_needs_a_context_word():
    assert (T.PHONE, "(495) 123-45-67") in found("телефон (495) 123-45-67")
    assert T.PHONE not in types("код (495) 123-45-67")


def test_inn_with_correct_checksum_needs_no_context():
    assert (T.INN, "7707083893") in found("Контрагент 7707083893 оплатил")


def test_number_with_wrong_checksum_is_not_inn():
    assert T.INN not in types("Заказ 500100732258 отправлен")


def test_snils_ogrn_and_card():
    result = found("СНИЛС 112-233-445 95, ОГРН 1027700132195, карта 4111 1111 1111 1111")
    assert (T.SNILS, "112-233-445 95") in result
    assert (T.OGRN, "1027700132195") in result
    assert (T.CARD, "4111 1111 1111 1111") in result
    assert T.CARD not in types("карта 4111 1111 1111 1112")


def test_bank_account_is_confirmed_by_a_bik_nearby():
    assert (T.BANK_ACCOUNT, "40702810200000000001") in found(
        "Перевод на 40702810200000000001, БИК 044525225"
    )
    assert T.BANK_ACCOUNT not in types("Номер 40702810200000000001 в журнале")


def test_iban():
    assert (T.BANK_ACCOUNT, "GB82 WEST 1234 5698 7654 32") in found("IBAN GB82 WEST 1234 5698 7654 32")


def test_kpp_and_passport_need_context():
    assert (T.KPP, "770701001") in found("КПП 770701001")
    assert T.KPP not in types("строка 770701001")
    assert (T.PASSPORT, "45 08 123456") in found("паспорт 45 08 123456")
    assert (T.PASSPORT, "4508 номер 123456") in found("серия 4508 номер 123456")


def test_numbers_next_to_a_comma_are_checked():
    """Обзор 1А, P1: запятая рядом с номером (CSV) не должна прятать его от проверки."""
    result = found("ИНН,КПП\nООО Ромашка,7707083893,770701001\nОГРН,1027700132195,\nСНИЛС,11223344595,")
    assert (T.INN, "7707083893") in result
    assert (T.KPP, "770701001") in result
    assert (T.OGRN, "1027700132195") in result
    assert (T.SNILS, "11223344595") in result


def test_phone_with_any_grouping_of_ten_digits():
    """Обзор 1А, P1: код города из четырёх цифр и группы 2-2-2."""
    assert (T.PHONE, "8 (4852) 12-34-56") in found("тел. 8 (4852) 12-34-56")
    assert (T.PHONE, "+7 916 1234567") in found("звоните +7 916 1234567")


@pytest.mark.parametrize("text, phone", [
    ("id:x+7 916 123-45-67", "+7 916 123-45-67"), ("тел+79161234567", "+79161234567"), ("call:x+44 20 7946 0958", "+44 20 7946 0958"),
])
def test_phone_with_a_plus_is_found_right_after_a_letter(text, phone):
    """Аудит 21.10.2026: «+» сам отделяет номер, и буква перед ним не мешает — а «Abc+7 916 123-45-67» после «пароль:»
    давал <SECRET_1> 916 123-45-67: секрет кончался на «+7», и десять цифр номера оставались открытыми. Перед «8»
    буква по-прежнему мешает: «x8…» — часть обозначения, а не телефон."""
    assert (T.PHONE, phone) in found(text)
    assert T.PHONE not in types("модель x89161234567")


def test_lone_eight_before_a_date_is_not_a_phone():
    assert T.PHONE not in types("pid 8 2024-10-14 12:00:01 запуск")


@pytest.mark.parametrize("text", ["8-916-123-45-67", "+7 (916) 123 45 67", "8 (34396) 5-12-34", "89161234567"])
def test_phone_groups_after_the_code(text):
    """Одна цифра в группе — только в местном номере после кода в скобках."""
    assert (T.PHONE, text) in found("тел. " + text)


def test_list_of_numbers_after_an_eight_is_not_a_phone():
    """FINDINGS P2 «false … PHONE, CARD …»: у телефона после «8» код от трёх цифр и группы от двух."""
    assert T.PHONE not in types("Счёт по сетам: 8 10 12 9 11 7 15")
    assert T.PHONE not in types("Счёт по сетам: 8 10 12 19 11 17 15")
    assert T.PHONE not in types("Счёт по сетам: 8 10 12 9\n11 7 15")


def test_phone_does_not_cross_a_line_break():
    assert T.PHONE not in types("Итого строк: 8\n916 123 45 67 — код заказа")
    assert T.PHONE not in types("Итого: +7\n916 123 45 67")
    assert T.PHONE not in types("Телефонов в справочнике: 495\n123 45 67")


def test_card_next_to_an_expiry_date_a_cvv_or_another_group():
    """Обзор 1А, P1: хвост после номера или группа перед ним не должны срывать проверку Луна."""
    assert (T.CARD, "4111 1111 1111 1111") in found("карта 4111 1111 1111 1111 12/27")
    assert (T.CARD, "4111 1111 1111 1111") in found("карта 4111 1111 1111 1111 123")
    assert (T.CARD, "4111 1111 1111 1111") in found("от 2024 4111 1111 1111 1111")
    assert (T.CARD, "4111 1111 1111 1111") in found("4111 1111 1111 1111 12/27 123")


def test_card_window_inside_a_list_of_four_digit_numbers_needs_card_words():
    """FINDINGS P2: в списке портов окно «1521 3306 5432 6379» проходит проверку Луна случайно."""
    assert T.CARD not in types("порты: 1433 1521 3306 5432 6379")
    assert T.CARD not in types("порты: 1521 3306 5432 6379 1433")
    assert (T.CARD, "4111 1111 1111 1111") in found("по карте 3306 4111 1111 1111 1111")
    assert (T.CARD, "4111 1111 1111 1111") in found("Visa 4111 1111 1111 1111 3306")


@pytest.mark.parametrize(
    "text, cards",
    [
        ("4111 1111 1111 1111 5500 0000 0000 0004", ["4111 1111 1111 1111", "5500 0000 0000 0004"]),
        ("от 2024 4111 1111 1111 1111 5500 0000 0000 0004 12/27", ["4111 1111 1111 1111", "5500 0000 0000 0004"]),
        ("4111 1111 1111 1111 5500 0000 0000 0004 2222 4000 7000 0005",
         ["4111 1111 1111 1111", "5500 0000 0000 0004", "2222 4000 7000 0005"]),
        ("4111 - 1111 - 1111 - 1111 - 5500 - 0000 - 0000 - 0004",
         ["4111 - 1111 - 1111 - 1111", "5500 - 0000 - 0000 - 0004"]),
        ("4111.1111.1111.1111.5500.0000.0000.0004", ["4111.1111.1111.1111", "5500.0000.0000.0004"]),
        ("4111/1111/1111/1111/5500/0000/0000/0004", ["4111/1111/1111/1111", "5500/0000/0000/0004"]),
        ("3782 822463 10005 4111 1111 1111 1111", ["3782 822463 10005", "4111 1111 1111 1111"]),
    ],
)
def test_cards_in_a_row_are_all_found_without_card_words(text, cards):
    """Финальный обзор партии: после правки списка портов две карты подряд без слов о карте не находились вовсе."""
    assert {(T.CARD, card) for card in cards} <= found(text)


@pytest.mark.parametrize(
    "text",
    ["порты: 1521 3306 5432 6379 1433 1434 8080 8443", "коды 1433 1521 3306 5432 6379 5500 0000 0000 0004"],
)
def test_chain_of_card_windows_inside_a_longer_list_needs_card_words(text):
    """Цепочка окон с проверкой Луна принимается, только если с обеих сторон за ней нет чужой четырёхзначной группы."""
    assert T.CARD not in types(text)
    assert T.CARD in types("карты: " + text.split(" ", 1)[1])


@pytest.mark.parametrize("card",["5859 - 0413 - 9685 - 9907", "5859.0413.9685.9907", "5859/0413/9685/9907"])
def test_card_groups_after_a_spaced_dash_a_dot_or_a_slash(card):
    """FINDINGS P3 «valid numbers in spaced notations…»."""
    assert (T.CARD, card) in found("оплата " + card)


@pytest.mark.parametrize(
    "text, type_, value",
    [
        ("Держи ИНН: 28 49 15 49 35.", T.INN, "28 49 15 49 35"),
        ("ИНН 52 50 96 69 28 77, КПП 770701001", T.INN, "52 50 96 69 28 77"),
        ("наш ИНН: № 28\u20114915\u20114935", T.INN, "28\u20114915\u20114935"),
        ("ИНН ( 52 - 5096692877 )", T.INN, "52 - 5096692877"),
        ("ИНН 52/50/966/928/77", T.INN, "52/50/966/928/77"),
        ("СНИЛС 96 18 44 77 86 1", T.SNILS, "96 18 44 77 86 1"),
    ],
)
def test_grouped_inn_and_snils_next_to_their_word(text, type_, value):
    assert (type_, value) in found(text)


def test_passport_next_to_an_inn_is_not_an_inn():
    """Серия и номер паспорта, 4-6 или 2-2-6, проходят проверку ИНН в одном случае из десяти."""
    for passport in ("2849 154935", "28 49 154935"):
        result = found(f"Паспорт {passport}, ИНН 7707083893")
        assert (T.PASSPORT, passport) in result
        assert (T.INN, passport) not in result


@pytest.mark.parametrize("value", ["10.10.100.101", "2026-01-01 02", "01.01.2026 06"])
def test_address_or_date_next_to_an_inn_is_not_an_inn(value):
    """Цифры адреса и даты со временем проходят проверку ИНН, а в реквизитах слово «ИНН» рядом."""
    assert (T.INN, value) not in found(f"ИНН 7707083893, сервер и выписка: {value}:00")


def test_snils_with_spaced_dashes_or_dots():
    assert (T.SNILS, "961 - 844 - 778 61") in found("номер 961 - 844 - 778 61")
    assert (T.SNILS, "961.844.778.61") in found("номер 961.844.778.61")


@pytest.mark.parametrize(
    "text",
    ["заказ 28 49 15 49 35", "ряды 96 18 44 77 86 1", "сборка 2.849.154.935", "узел 192.168.100.65",
     "встреча 12.10.2026", "архив 2024/10/14", "диапазон 2019 - 2024"],
)
def test_grouped_look_alikes_stay_open(text):
    """Пары цифр, версия и IP проходят контрольную сумму ИНН или СНИЛС, но без слова рядом это не номера."""
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, value",
    [
        ("полис ОМС 1111 - 2222 - 3333 - 4444", "1111 - 2222 - 3333 - 4444"),
        ("Полис: 1111 2222 3333 4444", "1111 2222 3333 4444"),
        ("ОМС 1111222233334444", "1111222233334444"),
        ("номер 1111.2222.3333.4444 (полис)", "1111.2222.3333.4444"),
    ],
)
def test_oms_policy_passing_luhn_is_oms_not_a_card(text, value):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: контрольный разряд ЕНП — Mod10, тот же алгоритм
    Луна, поэтому настоящий полис рядом со словом «полис» скрывался как карта."""
    assert found(text) == {(T.OMS, value)}


@pytest.mark.parametrize("text", ["оплата 1111 - 2222 - 3333 - 4444", "карта 1111222233334444", "1111.2222.3333.4444"])
def test_same_number_without_oms_words_is_a_card(text):
    assert types(text) == {T.CARD}


@pytest.mark.parametrize(
    "text",
    [
        "оплатил полис ОСАГО картой 4111 1111 1111 1111",
        "полис ОМС оплачен, списано с карты 4111 1111 1111 1111",
        "полис ОСАГО 4111 1111 1111 1111",
        "продлили полиса КАСКО: 4111 1111 1111 1111",
        "4111 1111 1111 1111 (Visa), полис",
    ],
)
def test_card_word_nearer_than_the_policy_word_or_a_car_policy_makes_a_card(text):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: слово «полис» в окне делало ОМС любую карту рядом,
    даже оплату полиса ОСАГО картой. Номер полиса ОСАГО и КАСКО — не шестнадцать цифр."""
    assert found(text) == {(T.CARD, "4111 1111 1111 1111")}


@pytest.mark.parametrize(
    "text",
    [
        "медицинская карта, полис ОМС 1111 2222 3333 4444",
        "полис ОМС из медицинской карты: 1111 2222 3333 4444",
        "Полис ОМС (см. медкарту) 1111 2222 3333 4444",
        "ОМС 1111 2222 3333 4444, оплата картой не нужна",
    ],
)
def test_medical_card_next_to_the_policy_keeps_it_oms(text):
    """«Медицинская карта» — не банковская: она часто стоит рядом с полисом ОМС и ближе к номеру."""
    assert found(text) == {(T.OMS, "1111 2222 3333 4444")}


@pytest.mark.parametrize(
    "text", ["pi = 3.14159265358984", "x = 4111111111111111.5", "доля 0.4111111111111111 от", "v1.2.4111111111111111"],
)
def test_part_of_a_decimal_number_is_not_a_card(text):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: дробная часть числа проходила проверку Луна."""
    assert T.CARD not in types(text)


@pytest.mark.parametrize("text", ["карта 4111111111111111.", "4111111111111111. Дальше", "4111.1111.1111.1111 и 1.5"])
def test_card_before_a_full_stop_is_still_a_card(text):
    assert T.CARD in types(text)


def test_card_is_not_cut_out_of_a_longer_digit_group():
    assert T.CARD not in types("счёт 40702810200000000001")


def test_passport_number_after_the_number_sign():
    assert (T.PASSPORT, "4508 №123456") in found("Паспорт 4508 №123456")


def test_birthdate_needs_context_and_a_real_date():
    assert (T.BIRTHDATE, "01.02.1980") in found("Дата рождения: 01.02.1980")
    assert (T.BIRTHDATE, "01.02.1980") in found("Иванов, 01.02.1980 г.р.")
    assert T.BIRTHDATE not in types("Встреча 01.02.2026")
    assert T.BIRTHDATE not in types("31.02.1980 г.р.")


def test_birthdate_with_a_two_digit_year():
    """FINDINGS P3 «false positives that damage the text, and smaller recall gaps»: «д.р. 01.02.90»."""
    assert (T.BIRTHDATE, "01.02.90") in found("Петров П. П., д.р. 01.02.90")
    assert (T.BIRTHDATE, "29.02.00") in found("д.р. 29.02.00")
    assert T.BIRTHDATE not in types("д.р. 31.02.90")
    assert T.BIRTHDATE not in types("Встреча 01.02.26")
    assert T.BIRTHDATE not in types("Проект родился в 2019, версия 1.2.10")


def test_card_grouped_four_six_five():
    """Тот же обзор: «карты 4-6-5 не находятся» — не воспроизвелось, проверка остаётся."""
    assert (T.CARD, "3717 860313 72159") in found("оплата 3717 860313 72159")


def test_login_in_a_url_is_an_account_not_an_email():
    """Обзор пакета исправлений 1А, P1: «схема://ivanov@хост» — вход, и его скрывают."""
    for text, login in (
        ("git clone https://ivanov@git.contoso.ru/team/repo.git", "ivanov"),
        ("ssh://ivanov@srv-db01.contoso.ru:22", "ivanov"),
        ("ftp://petrov@files.contoso.ru", "petrov"),
        (r'$url = "https://ivanov\@git.contoso.ru/team/repo.git";', "ivanov"),
        (r'"ssh://petrov\\@srv-db01"', "petrov"),
    ):
        assert found(text) == {(T.ACCOUNT, login)}, text


def test_address_in_url_parameters_is_an_email_and_url_credentials_are_not():
    assert found("https://portal.contoso.ru?mail=ivanov@contoso.ru") == {(T.EMAIL, "ivanov@contoso.ru")}
    assert found('post' 'gres://app:S3cr3t@db01.contoso.ru:5432/app') == set()  # secret-scan:allow -- synthetic test fixture


def test_standard_and_service_logins_in_a_url_are_not_masked():
    """Финальный обзор 1В: «ssh://git@…» и «ssh://root@…» не выдают человека (раздел 5.4)."""
    for text in (
        "ssh://git@gitlab.contoso.ru/team/repo.git",
        "ssh://root@srv-db01.contoso.ru",
        "ftp://anonymous@files.contoso.ru",
        "https://oauth2@git.contoso.ru/team/repo.git",
    ):
        assert found(text) == set(), text


def test_login_before_a_url_password_is_masked():
    """FINDINGS P1 «Logins and hosts in URLs…»: в «схема://логин:пароль@хост» логин оставался открытым."""
    assert found('mong' 'odb://petrov:Qwerty12@db01.contoso.ru/app') == {(T.ACCOUNT, "petrov")}  # secret-scan:allow -- synthetic test fixture
    assert found('post' 'gres://app:S3cr3t@db01.contoso.ru:5432/app') == set()  # secret-scan:allow -- synthetic test fixture


@pytest.mark.parametrize(
    "text, login",
    [
        ("mongodb://petrov:Qwerty123!@db01.contoso.ru/app", "petrov"),
        ("mongodb://petrov:Pa$$w0rd$@db01.contoso.ru/app", "petrov"),
        ("redis://petrov:YWJjZGVm==@cache.contoso.ru", "petrov"),
        ("https://petrov:abc=def@git.contoso.ru", "petrov"),
        ("ftp://petrov:@files.contoso.ru", "petrov"),
        ("ssh://ivanov@srv-db01", "ivanov"),
    ],
)
def test_url_login_is_masked_whatever_the_password_and_host(text, login):
    """Обзор партии P1: вход в адресе находится сам, а не через шаблон e-mail."""
    assert (T.ACCOUNT, login) in found(text), text


@pytest.mark.parametrize("login", ["user", "root", "git", "Administrator", "ubuntu"])
def test_service_login_on_an_address_is_left_open(login):
    """Финальный обзор партии: в «user@10.1.2.5» скрывался «user», хотя в «ssh://user@…» он открыт.
    Адрес скрывает слой 3."""
    assert found(f"ssh {login}@10.1.2.5 -p 22") == set()


def test_personal_login_on_an_address_is_masked():
    assert found("ssh ivanov@10.1.2.5 -p 22") == {(T.ACCOUNT, "ivanov")}


def test_placeholder_logins_in_a_url_are_not_masked():
    for text in ("https://имя:пароль@host.contoso.ru/", "https://login:password@host.contoso.ru/",
                 "https://username:secret@host.contoso.ru/"):
        assert T.ACCOUNT not in types(text), text


@pytest.mark.parametrize("text, type_, value", [
    ("Оплата картой 4111\xa01111\xa01111\xa01111", T.CARD, "4111\xa01111\xa01111\xa01111"),
    ("карта 4111–1111–1111–1111", T.CARD, "4111–1111–1111–1111"),
    ("паспорт 45\xa008\xa0123456", T.PASSPORT, "45\xa008\xa0123456"),
    ("СНИЛС 112-233-445\xa095", T.SNILS, "112-233-445\xa095"),
    ("СНИЛС 112‐233‐445 95", T.SNILS, "112‐233‐445 95"),
    ("ИНН 77\u202f07\u202f08\u202f38\u202f93", T.INN, "77\u202f07\u202f08\u202f38\u202f93"),
    ("IBAN GB82\u2007WEST\u20071234\u20075698\u20077654\u200732", T.BANK_ACCOUNT, "GB82\u2007WEST\u20071234\u20075698\u20077654\u200732"),
    ("Дата рождения: 01–02–1980", T.BIRTHDATE, "01–02–1980"),
], ids=["card-nbsp", "card-en-dash", "passport-nbsp", "snils-nbsp", "snils-hyphen", "inn-narrow-nbsp", "iban-figure-space",
        "birthdate-en-dash"])
def test_numbers_with_non_breaking_spaces_and_typographic_dashes(text, type_, value):
    """FINDINGS «Слой 1: номера карт, паспортов, СНИЛС, ИНН и счетов с неразрывным пробелом не находятся»: Word и Outlook
    ставят U+00A0 и U+202F между группами, автозамена — тире; найденное значение — как в оригинале."""
    assert (type_, value) in found(text)


@pytest.mark.parametrize("text, phone", [
    ("тел. +7 916 123\u201145\u201167", "+7 916 123\u201145\u201167"),
    ("тел. +7 (916) 123–45–67", "+7 (916) 123–45–67"),
    ("тел. 8.916.123.45.67", "8.916.123.45.67"),
    ("тел. +7.916.123.45.67", "+7.916.123.45.67"),
    ("тел. 8\u2011916\u2011123\u201145\u201167", "8\u2011916\u2011123\u201145\u201167"),
    ("ул. Ленина, д. 7, кв. 88. 8 812 682 53 49.", "8 812 682 53 49"),
], ids=["nb-hyphen", "en-dash", "dots", "plus-dots", "nb-hyphen-eight", "flat-number-before"])
def test_phone_with_typographic_dashes_or_dots(text, phone):
    """FINDINGS «Слой 1: телефон с неразрывным дефисом, коротким тире или точками не находится»."""
    assert (T.PHONE, phone) in found(text)


@pytest.mark.parametrize("text", [
    "версия 1.8.916.123.45.67", "сборка 8.916.123.45.67.2", "DNS 8.8.8.8 и 8.8.4.4", "релиз 8.10.2024.12.30",
    "узел 10.8.123.45.67",
], ids=["version-before", "version-after", "ip", "date", "ip-like"])
def test_dotted_digits_that_are_not_a_phone(text):
    """Точка — разделитель телефона только у отдельной записи: цепочка версии или адреса через точку — не номер."""
    assert T.PHONE not in types(text)


@pytest.mark.parametrize("text, value", [
    ("Дата рождения: 12 марта 1985 г.", "12 марта 1985"),
    ("родился 12 марта 1985 года", "12 марта 1985"),
    ("д.р. 1 янв. 1990", "1 янв. 1990"),
    ("DOB: March 12, 1985", "March 12, 1985"),
    ("born 12 Mar 1985", "12 Mar 1985"),
    ("Date of birth: Sept. 3rd, 1979", "Sept. 3rd, 1979"),
], ids=["ru", "ru-genitive", "ru-short", "en", "en-day-first", "en-ordinal"])
def test_birthdate_with_the_month_in_words(text, value):
    """FINDINGS «Слой 1: дата рождения, записанная месяцем словом, не скрывается»."""
    assert (T.BIRTHDATE, value) in found(text)


@pytest.mark.parametrize("text", [
    "Встреча 12 марта 2026 г.", "родился 31 февраля 1985 года", "DOB: Feb 30, 1985", "родился 12 марс 1985",
])
def test_month_in_words_needs_context_and_a_real_date(text):
    assert T.BIRTHDATE not in types(text)


@pytest.mark.parametrize("text, email", [
    ("GET /x?email=ivanov%40contoso.ru HTTP/1.1", "ivanov%40contoso.ru"),
    ("return=/a?to=ivan%2Btest%40contoso.ru&x=1", "ivan%2Btest%40contoso.ru"),
], ids=["at", "plus"])
def test_url_encoded_email_is_found(text, email):
    """FINDINGS «E-mail и `DOMAIN\\login` в URL-кодировке…»: «%40» — «@» в журналах веб-серверов и адресах возврата."""
    assert found(text) == {(T.EMAIL, email)}


def test_url_encoded_email_keeps_the_domain_and_the_login_hidden(state, settings):
    """Та же находка: домен получал значение «40contoso.ru», а «ivanov» уходил открытым."""
    text = "GET /x?email=ivanov%40contoso.ru HTTP/1.1, потом contoso.ru"
    result = sanitize(state, text, settings)
    assert "ivanov" not in result.sanitized and "contoso" not in result.sanitized
    assert all(not entity.restore_value.startswith("40") for entity in state.entities.values())
    assert restore(state, result.sanitized, settings).text == text


def test_email_does_not_start_inside_a_percent_escape():
    assert T.EMAIL not in types("path=%40ivanov.contoso.ru")
    assert found("x=%2Fivanov@contoso.ru") == {(T.EMAIL, "ivanov@contoso.ru")}


@pytest.mark.parametrize("text, email", [
    ("пишите ivan.o'brien@contoso.ru", "ivan.o'brien@contoso.ru"),
    ("пишите d’artagnan@contoso.ru", "d’artagnan@contoso.ru"),
    ("адрес 'ivanov@contoso.ru'", "ivanov@contoso.ru"),
], ids=["apostrophe", "typographic", "quoted"])
def test_apostrophe_inside_the_mailbox_name(text, email):
    """FINDINGS «Слой 1: апостроф в имени ящика оставляет часть адреса открытой»: «ivan.o» уходил открытым."""
    assert found(text) == {(T.EMAIL, email)}


@pytest.mark.parametrize("text, value", [
    ("Загранпаспорт 75 1234567", "75 1234567"),
    ("заграничный паспорт № 751234567", "751234567"),
    ("водительское удостоверение 99 12 345678", "99 12 345678"),
    ("ВУ 77 АА 123456", "77 АА 123456"),
    ("СТС 77 УХ 123456", "77 УХ 123456"),
    ("ПТС: 77 ОР 123456", "77 ОР 123456"),
    ("ЭПТС 164301001234567", "164301001234567"),
], ids=["foreign", "foreign-compact", "license", "license-old", "registration", "vehicle-passport", "electronic"])
def test_other_identity_documents_are_passports(text, value):
    """IDEAS «Номера документов слоем 1: загранпаспорт, водительское удостоверение, СТС/ПТС»: тип — PASSPORT, как
    у документов в открытых наборах и у метки «document» слоя 4."""
    assert (T.PASSPORT, value) in found(text)


@pytest.mark.parametrize("text", [
    "заказ 75 1234567", "вуз 99 12 345678", "паспорт 75 1234567", "склад 77 АА 123456", "ЭТС 164301001234567",
])
def test_document_numbers_need_their_words(text):
    assert T.PASSPORT not in types(text)


def test_inn_next_to_a_driving_licence_stays_an_inn():
    result = found("Водительское удостоверение 5023 987654, ИНН 7707083893")
    assert {(T.PASSPORT, "5023 987654"), (T.INN, "7707083893")} <= result
    assert (T.PASSPORT, "7707083893") not in result
