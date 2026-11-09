"""Обзор 1А, P2: длинная цепочка без пробелов не должна давать квадратичное время.

Очистка не ограничена по времени, поэтому одна такая вставка заняла бы обработчик на минуту.
"""
import itertools
import re
import time

import pytest

from cleaner.core import leakcheck
from cleaner.core.detect import rules
from cleaner.core.detect.base import DetectContext, load_builtin
from cleaner.core.detect.merge import MergedSpan
from cleaner.core.entities import ops
from cleaner.core.entities.resolve import Resolver
from cleaner.core.match import find_forms
from cleaner.core.pipeline import DETECTORS, sanitize
from cleaner.core.restore import StreamRestorer, restore
from cleaner.core.types import ChatState, DictEntry, Entity, Settings, Surrogate
from cleaner.core.types import EntityType as T

# Модуль — в полном наборе, как норма скорости слоёв 1–3 (раздел 17): обход всех слоёв по сотне длинных рядов (17 с) — с
# 16.10.2026, остальные сторожа линейности — с 18.10: 20 с из 63–70 быстрого набора на dev-workstation при норме 60 с, и пороги
# в секундах краснели от нагрузки машины. Упавший по порогу тест — перезапустить по имени на свободной машине. Правку
# слоёв 1–3 и восстановления проверяют модулем отдельно: pytest tests/test_long_input.py -m integration.
pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "text",
    [
        "a.b." * 5000, "CN=a," * 5000, "x" * 20000, "1," * 10000, "a:" * 10000, "token" * 20000 + "=Zx81kLmN02pQ",
        "token" * 4000, "pwd" * 7000, "a_pass" * 3500, "8 " * 50000, "/home/" + "a'" * 10000,
        "CORP\\" + "и\\" * 10000, "Source" * 5000 + ":1:2", "1 - " * 25000, "123.456/" * 12500,
        "д.р. 11.11.11 " * 7000, "4111 1111 1111 1111 " * 5000, "schtasks " * 10000,
        # Правила detect-secrets: «//…» (NpmDetector), пробелы после слова ключа (IBM, Cloudant, Softlayer),
        # «eyJ» и «sk-» без начала слова (JWT, OpenAI), один токен много раз на строке выгрузки JSON.
        "/home/" * 10000, " token" + " " * 5000 + "!", " secret_key" + " " * 5000 + "!", "eyJ" * 30000,
        "sk-" * 15000, '{"account_sid":"AC' + "0123456789abcdef" * 2 + '","n":1},' * 2000, "token=" * 5000,
        "password=P;" + "Ab " * 30000, "password=P" + ";Ab Cd" * 15000, "PWD=/" * 20000, "token=${a}" * 2500,
        "net use \\\\a\\b" + " /x" * 30000 + " ", "mysql -u " * 10000, '<add key="pass" value="x"' * 4000,
        # Тысячи разных токенов одного правила detect-secrets на одной строке: каждое значение искалось по всей строке.
        "".join('{"account_sid":"AC%032x","n":1},' % i for i in range(5000)), "".join("=AKC%010d " % i for i in range(10000)),
        # Слова перед тире после «пароль», «--» и связка «это» перед значением.
        "пароль а б в г д е " * 5000, "пароль " + "a-" * 50000 + " — x", "пароль -- " * 10000, "пароль — это " * 8000,
        "".join("пароль — слово%d " % i for i in range(5000)),
        # Связка после «:» и до шести слов перед «:».
        "пароль: это " * 8000, "пароль а б в г: это " * 5000, "password " + "a " * 50000 + ": x",
        # Токен или код в прозе: слова после «токен», длинный ряд без цифр или без букв, ряд вида токена.
        "токен " * 20000, "код a " * 30000, "ключ " * 4 + "a" * 100000, "код " + "1" * 100000, "token " + "a1" * 100000,
        # Слово кода ошибки перед «код» (поиск назад до начала текста — 4,6 с) и имя из тысяч частей.
        "код 1234567 " * 10000, "token " + "a1_" * 50000,
        # Слова после «пин» (без предела их числа — 3,6 с) и группы ключа BitLocker.
        "пин а " * 5000, "123456-" * 5000,
        # Скобки в конце значения, атрибут и вызов с именами после ключа.
        "password=" + ")" * 100000, "password=" + "a." * 50000 + "1", "password=f(" + "a," * 50000 + "1)",
        "pwd=" + "(a)" * 30000, "password = self." + "aB" * 50000, "password=" + "(" * 50000 + "a" + ")" * 50000,
        # Заголовок ключа с рядами дефисов или тире, без них и тело ключа.
        "BEGIN " * 20000, "-" * 100000, "—–BEGIN PRIVATE KEY—–\n" * 5000, "BEGIN PRIVATE KEY\n" * 10000,
        "BEGIN PRIVATE KEY\nMIIEowIBAAKCAQEA\n" + "-" * 100000, "BEGIN PRIVATE KEY\nMIIEowIBAAKCAQEA\nEND PRIVATE KEY\n" * 5000,
        # Строки «Имя: значение» перед телом ключа, ряды через пробел (SSH2), ключи PuTTY, токены GitLab.
        # Строк немного: правила detect-secrets сами стоят около 12 мкс на строку.
        "BEGIN PRIVATE KEY\nA: b\n" * 5000, "BEGIN PRIVATE KEY\n" + "X: BEGIN PRIVATE KEY\n" * 10000,
        "BEGIN PRIVATE KEY\nA: " + "b" * 200000 + "\n", "---- BEGIN PRIVATE KEY ----\nMIIEowIBAAKCAQEA\n" * 5000,
        "- " * 50000 + "BEGIN PRIVATE KEY\nMIIEowIBAAKCAQEA", "PuTTY-User-Key-File-2: x\n" * 8000,
        "PuTTY-User-Key-File-2:" + "\nA: b" * 15000, "PuTTY-User-Key-File-2" * 10000,
        "PuTTY-User-Key-File-2: x\n" + ("AAAAB3NzaC1yc2EA" * 8 + "\n") * 2000, "gldt-" * 20000,
        # Строки заголовка, продолженные обратной косой чертой (RFC 4716): строки первого заголовка идут до конца текста.
        "BEGIN PRIVATE KEY\nA: \\\n" * 3000,
        # Имя, часть которого — метка (5.7, шаг 4).
        "<ORG_1>." * 20000, "a.<ORG_1>." * 10000, "<ORG_1>a." * 15000, "<ORG_1" * 20000, "<ORG_1>." + "a.b." * 25000,
        # Цепочка частей через точку, которая кончается не однобуквенной частью: её суффиксы сверяются со списками.
        "abc.def." * 20000,
        # Адрес e-mail с меткой в домене; метки не домена после имени отрезаются.
        "a@<ORG_1>." * 15000, "a@<ORG_1>.<ORG_1" * 10000, "a@b.c" + ".<ORG_1>" * 10000,
        # Имя через «\.»: цепочка вперемешку с точками, начала после знаков выражения, «\b» без пары, метки.
        "a\\.b." * 10000, ".*\\.a" * 10000, "\\ba\\." * 10000, "\\b" + "ab\\." * 15000, "x\\.<ORG_1>\\." * 4000,
        # Части в смешанном регистре: имя с выданной заменой внутри проверяется по частям.
        "Ab.Cd." * 10000 + "ru",
        # Имя после ведущей точки, «*.» и «@» (второе ревью, P1): начало только после точки за знаком не из имени.
        ".a" * 15000, "*.ab" * 8000, ">.ab.cd" * 5000,
        # «\\.» — выражение в строке JSON (второе ревью, P3): имя входа e-mail не начинается со второй «\».
        "a\\\\.b." * 4000, "1\\\\.2\\\\.3\\\\.4\\\\." * 2000,
        # «\@» — «@» адреса в строке Perl (ревью раунда 5, P3): цепочки адресов, ряды без домена и «\\@».
        "a\\@b.c." * 8000, "a\\@" * 30000, "a.b\\@" * 15000, "a\\\\@b.c" * 10000,
        # Экранированный знак LDAP-имени (RFC 4514), список узлов после ключа, адрес IPv4 в конце IPv6.
        "CN=a\\," * 5000, "CN=a" + "\\" * 50000, "-ComputerName a" + ",a" * 10000, "-ComputerName " + "'a', " * 5000,
        "1:1:1.1.1." * 5000,
        # Узлы без точек в командах и поле syslog: команды без узла, список узлов, метки времени подряд.
        "sc psexec mstsc " * 5000, "psexec \\\\a" + ",a" * 10000, "Nov 9 10:01:02 " * 5000,
        # Пустое поле перед следующей строкой, пароль в известных командах, поле auth Docker (идея «Учётные данные по
        # контексту»).
        "password=\n" * 20000, "curl -u " * 10000, "curl " + "a " * 50000 + "-u x:y", "sqlcmd -P " * 10000,
        "psexec -p " * 10000, "plink -pw " * 10000, "schtasks /p " * 10000, "net user a " * 10000,
        "docker login -p " * 10000, '"auth":"' * 20000,
        # Учётная запись по контексту: ключи входа, слово «логин», журнал Windows, sshd, пары после «доступ».
        "user=" * 20000, "a_user:" * 15000, "ab" * 50000 + "user=x", "логин " * 20000, "Account Name: a\n" * 8000,
        "Account Domain:" * 10000, "Failed password for " * 6000, "Invalid user a " * 8000, "доступ " * 20000,
        "доступ a:" * 15000, "доступ " + "a/" * 50000,
        # Адрес в URL-кодировке («%40», «%2B»), точки телефона и месяц словом в дате рождения (аудит 09.11.2026).
        "a%2B" * 20000, "%2Fa." * 15000, "a%40" * 20000, "8.916.123." * 10000, "родился 12 марта " * 5000,
        # Поле на следующей строке с «=», уровень журнала после метки времени ISO, переменная кода после ключа входа
        # (ревью 09.11.2026).
        "token:\nAb1=" * 15000, "2026-11-09T10:01:02Z INFO " * 5000, "user = a_id\n" * 10000,
    ],
    ids=[
        "dotted", "dn", "letters", "commas", "colons", "long_key", "token", "pwd", "a_pass", "eights", "apostrophes",
        "cyrillic_logins", "label_colons", "spaced_dashes", "dots_slashes", "short_dates", "cards_in_a_row",
        "remote_commands", "slashes", "spaced_key", "spaced_secret_key", "eyj", "sk", "same_token", "token_pairs",
        "spaced_field", "spaced_fields", "pwd_paths", "token_templates", "net_use", "mysql", "add_key",
        "distinct_tokens", "distinct_short_tokens",
        "password_words", "password_hyphenated_word", "password_double_hyphens", "password_copulas",
        "password_distinct_words", "password_colon_copulas", "password_long_leads", "password_long_lead_run",
        "token_words", "code_words", "key_letters", "code_digits", "token_run",
        "digit_codes", "identifier_parts", "pin_words", "bitlocker_groups",
        "closing_brackets", "attribute_chain", "call_names", "bracket_pairs",
        "camel_attribute", "nested_brackets", "pem_begins", "dashes", "pem_dashed_headers", "pem_bare_headers", "pem_dashed_body",
        "pem_bare_blocks",
        "pem_header_lines", "pem_nested_headers", "pem_long_header_line", "pem_spaced_runs", "pem_spaced_hyphens",
        "putty_headers", "putty_fields", "putty_names", "putty_body", "gitlab_prefixes", "pem_continued_headers",
        "labels", "labels_parts", "labels_glued", "labels_open", "labels_tail", "dotted_words", "email_labels",
        "email_labels_open", "email_labels_after",
        "escaped_mixed", "escaped_after_expressions", "escaped_word_bounds", "escaped_open_word_bound", "escaped_labels",
        "mixed_case_parts", "leading_dots", "wildcards", "after_label_signs", "json_mixed", "json_addresses",
        "escaped_at_chain", "escaped_at_run", "escaped_at_logins", "escaped_backslash_at",
        "dn_escaped_commas", "dn_backslashes", "computer_list", "computer_quoted_list", "ipv6_v4_tails",
        "remote_tools", "psexec_list", "syslog_stamps",
        "empty_fields", "curl_users", "curl_words", "sqlcmd_passwords", "psexec_passwords", "plink_passwords",
        "schtasks_passwords", "net_users", "docker_logins", "docker_auths",
        "user_keys", "user_key_prefixes", "glued_user_key", "login_words", "event_names", "event_domains",
        "sshd_failed", "sshd_invalid", "access_words", "access_pairs", "access_slashes",
        "encoded_plus_run", "encoded_slash_run", "encoded_at_run", "dotted_phone_run", "month_dates",
        "next_line_equals", "iso_log_levels", "code_identifier_logins",
    ],
)
def test_every_layer_is_fast_on_a_long_run_without_spaces(text):
    ctx = DetectContext(Settings())
    for detector in DETECTORS:
        started = time.perf_counter()
        detector.detect(text, ctx)
        assert time.perf_counter() - started < 0.5, detector.name


@pytest.mark.parametrize(
    "text",
    [
        "abc.def." * 2500, "abc.def." * 2500 + "ru", "srv-01." * 2500 + "contoso.ru", "a." * 10000 + "ru",
        "a@b.c." * 3000,
    ],
    ids=["words", "words_suffix", "parts_suffix", "letters_suffix", "email_chain"],
)
def test_sanitize_again_and_restore_are_fast_on_a_long_dotted_run(text):
    """FINDINGS P2 «Layer 3 takes quadratic time on a long dotted run»: суффиксы цепочки сверялись со списками
    квадратичное время, а цепочка с настоящим суффиксом становилась одним именем из тысяч частей — и поиск замен в
    следующем тексте и в ответе перебирал цепочки частей до его длины. Цепочка пересекающихся адресов e-mail
    становилась искомым написанием длиной в текст (test_pipeline, цепочка адресов)."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    for step in ("sanitize", "again", "restore", "link"):
        started = time.perf_counter()
        if step == "restore":
            restore(state, sanitized, Settings())
        elif step == "link":
            restore(state, f"https://{sanitized}/", Settings())
        else:
            sanitized = sanitize(state, text, Settings()).sanitized
        assert time.perf_counter() - started < 0.5, step


@pytest.mark.parametrize("name, type_", [("h{}.contoso.ru", T.HOST), ("u{}@contoso.ru", T.EMAIL)], ids=["hosts", "emails"])
def test_new_replacements_are_checked_against_the_text_once(name, type_):
    """Подмена имени и метка не должны совпасть со строкой текста (FR-5.7): каждая новая искалась по всему тексту, и
    тысячи новых имён или адресов в длинном тексте давали квадратичное время."""
    text = "слово " * 80000 + " ".join(name.format(i) for i in range(4000))
    spans = [MergedSpan(m.start(), m.end(), type_, ("infra",)) for m in re.finditer(r"\S+[.@]\S+", text)]
    resolver = Resolver(ChatState(chat_id="long", net_key=bytes(32)), Settings(), text, load_builtin().generic_labels)
    started = time.perf_counter()
    resolver.run(text, spans)
    assert time.perf_counter() - started < 0.5


def test_many_new_people_in_one_text_are_resolved_in_linear_time():
    """Ревью 24.10.2026: новое имя сверялось с каждым написанием и каждым человеком чата — 2000 разных людей в одном
    тексте (список сотрудников) разбирались 40 с. Имена латиницей: pymorphy их не разбирает, замеряется сопоставление."""
    first = ["John", "Peter", "Mary", "Anna", "Paul", "Kate", "Mark", "Lena", "Oleg", "Igor"]
    surnames = ["".join(parts).capitalize() for parts in itertools.product(["ba", "ve", "go", "du", "zi", "ko", "lo", "mu"], repeat=4)]
    text = ", ".join(f"{surname} {first[n % 10]}" for n, surname in enumerate(surnames))
    spans = [MergedSpan(m.start(), m.end(), T.PERSON, ("ner",)) for m in re.finditer(r"\w+ \w+", text)]
    state = ChatState(chat_id="long", net_key=bytes(32))
    resolver = Resolver(state, Settings(), text, load_builtin().generic_labels)
    started = time.perf_counter()
    resolver.run(text, spans)
    assert time.perf_counter() - started < 1
    assert len(state.entities) == len(surnames) == 4096


def test_run_of_eights_gives_no_phones():
    """FINDINGS P2 «false … PHONE, CARD …»: «8 8 8 …» давал тысячи ложных телефонов, очистка шла две секунды."""
    assert rules.detect("8 " * 50000, DetectContext(Settings())) == []


@pytest.mark.parametrize(
    "text",
    [
        "010.001.002.005 " * 12000, "10.1.2.5/24 " * 15000, "2a00:1450:4010:0:0:0:0:65 " * 7000,
        "".join("10.%d.%d.%d " % (i >> 16, i >> 8 & 255, i & 255) for i in range(15000)), "a:" * 100000,
        "Source" * 30000 + ":1:2", "1.2.3.4." * 25000, "2a00::" * 30000,
        # Адреса через «\.» (второе ревью, P2): цепочка чисел и записи с нулями впереди.
        "1\\.2\\.3\\.4\\." * 4000, "010\\.001\\.002\\.005 " * 3000,
    ],
    ids=[
        "padded", "written_with_prefix", "full_ipv6", "distinct_addresses", "colons", "label", "dotted_numbers",
        "ipv6_runs", "escaped_dotted_numbers", "escaped_padded",
    ],
)
def test_leak_check_is_fast_on_many_addresses(text):
    """Раздел 8: записи адресов сравниваются с ключами сущностей словарём, а находки написаний — двоичным поиском."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "узел 10.1.2.5 и 2a00:1450:4010::65", Settings())
    started = time.perf_counter()
    leakcheck.check(text, state, Settings())
    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize("host", ["a." * 20000 + "x", "www." * 20000 + "domain-1.example"], ids=["parts", "generic"])
def test_restore_is_fast_on_a_host_name_of_many_parts(host):
    """Обзор пакета исправлений 1А, P2: проверка хоста ссылки шла квадратичное время. Служебные части перед выданным
    доменом делают начало цепочки возможным с каждой из них."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "узел srv-dc01.corp.contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, "https://" + host, Settings())
    assert time.perf_counter() - started < 0.5


def test_restore_is_fast_on_many_reference_brackets():
    """Обзор партии P1: «]: <» по всей строке давал квадратичное время восстановления."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, "]: <" * 25000, Settings())
    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize(
    "text",
    [
        'url("' * 20000, "url(" * 25000, "@import '" * 12000, 'url("\\' * 16000, "url(\\" * 20000, "url('\\'" * 12000,
        "image-set(" * 10000, 'image-set("' * 10000, "src(/*" * 15000, "image-set((((()" * 6000,
        "src(" + "(" * 20000 + ")" * 20000, "image-set(a)" * 8000, "@import '" + "\\'url(\"" * 15000,
        'u\\72l("' * 12000, "\\75\\72\\6c(" * 10000, "@\\69mport '" * 8000, "image-s\\65t(" * 8000,
        "\\000075 " * 12000, "s\\000072" * 12000, "\\2d webkit\\2d " * 6000,
        "@import/*" * 15000, "@import /**/" * 8000, "@import " + "/**/ " * 20000, "@import/*'*/'" * 6000,
    ],
    ids=[
        "quoted", "unquoted", "import", "quoted_escape", "unquoted_escape", "escaped_quotes",
        "image_sets", "image_set_strings", "src_comments", "deep_image_sets", "deep_balanced_src", "closed_image_sets",
        "string_to_the_end", "escaped_url_strings", "escaped_urls", "escaped_imports", "escaped_image_sets",
        "spaced_escapes", "six_digit_escapes", "escaped_prefixes",
        "import_comments", "closed_import_comments", "many_import_comments", "import_comment_quotes",
    ],
)
def test_restore_is_fast_on_unclosed_css_urls(text):
    """CSS url(), @import, image-set() и src() без закрывающей кавычки или скобки, с глубокой вложенностью или
    во множестве, с экранированными именами и @import с незакрытыми комментариями не дают квадратичного времени."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, text + "<EMAIL_1>", Settings())
    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize(
    "text",
    [
        "<" * 50000, "<a>, data='x' " * 10000, "<a " * 20000 + "f(a, data='x')",
        "EMAIL_1" + " " * 50000, "//x:<EMAIL_1> " * 5000, "file:///" * 20000, "//" * 50000,
        "\\" * 100000, "/\\" * 50000, " \\\\x" * 10000, "https:" * 20000, "!http:a:" * 15000, "//a:wss:" * 15000,
        "file:\\" * 20000, "//" + "a@" * 50000, "https:@" * 20000, "//@:" * 25000,
        '<a href="https:' + " a" * 50000 + '">', '<a href="' + "https: @" * 20000 + '">', '<a href="' + "//a b " * 20000 + '">',
        # Голый адрес с «\» читается и с «\» как «%5C» (_readings): имя пользователя тянется через неё.
        "https://a\\x@" * 10000, "https:a\\" * 15000, "file:\\\\C:" * 12000,
        # Имя без схемы, с которого ссылка linkify-it не начинается: путь читается только у ссылки (4,7 с, квадратично).
        "/a.ru" * 20000,
        # Ссылки linkify-it внутри пути прежней: путь у всех кончается на одном знаке, а неизвестные метки делят его на куски.
        "a.ru/[" * 20000, "a.ru/[<PERSON_99>" * 6000,
        # Хост за первым «@» ссылки linkify-it (_FIRST_AT): незакрытая «[» и длинный хост без второго «@».
        "//a@[x" * 15000, "//a@" + "b" * 100000, "//<EMAIL_1>@a@" * 5000,
        # Голые адреса e-mail: у каждого оригинал в имени и чужой домен, «\@» в прочтении CommonMark, домен marked с отступом.
        "<EMAIL_1>@b.ru " * 2000, "a\\@b.c" * 10000, "a@" + "b.c-" * 25000,
    ],
    ids=[
        "brackets", "arguments", "open_tags", "spaced_label", "bare_links", "file_links", "slashes",
        "backslashes", "mixed_slashes", "unc_paths", "schemes", "schemes_without_slashes", "schemes_in_userinfo",
        "file_backslashes", "at_signs", "schemes_with_at_signs", "empty_users",
        "spaced_user", "spaced_schemes_with_at_signs", "spaced_slashes",
        "encoded_backslashes", "schemes_with_backslashes", "drive_letters", "linkify_names",
        "linkify_paths", "linkify_paths_with_labels", "first_at_brackets", "first_at_long_host", "first_at_labels",
        "foreign_emails", "escaped_emails", "marked_email_domains",
    ],
)
def test_restore_is_fast_on_many_tags_arguments_and_bare_links(text):
    """Участки вне тегов считаются один раз на ответ, а не для каждого атрибута; метка без ограничителей,
    адреса без схемы и «file:///» проверяются за линейное время."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, text + "<EMAIL_1>", Settings())
    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize(
    "text", [
        'href="' * 20000, "](" * 30000, "url(" * 25000, "@import " * 12000, "[a]: <\n" * 15000,
        "u\\72 l( " * 12000, "@\\69mport " * 10000,
    ],
    ids=["attributes", "markdown", "css_url", "import", "definitions", "escaped_css_url", "escaped_import"],
)
def test_stream_restore_is_fast_on_many_unclosed_link_openers(text):
    """Обзор этапа 3: поиск незакрытой ссылки в показываемом префиксе линеен."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    restorer = StreamRestorer(state, Settings())
    started = time.perf_counter()
    restorer.feed(text + " <EMAIL_1> ")
    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize(
    "text",
    [
        '<a href="&#' + "0" * 100000 + '47;">', '<a href="' + "&#47;" * 20000 + '">',
        '<a style="' + "&abcdefghijklmnopqrstuvwxyzabcde" * 2000 + '">', '<a href="&' + "a" * 100000 + '">',
        "href=&#47;&#47;a" * 5000, "href=" * 20000, "[1]: &#47;\n" * 5000, '"//a&#46;' * 2000,
    ],
    ids=["zeros", "slashes", "unknown_names", "long_name", "unquoted", "empty_unquoted", "definitions", "dots"],
)
def test_restore_is_fast_on_character_references(text):
    """Ссылки на знаки в цели ссылки раскрываются за линейное время: тысячи нулей в числовой ссылке, длинные
    незнакомые имена, атрибуты без кавычек и определения ссылок без угловых скобок."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, text + "<EMAIL_1>", Settings())
    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize(
    "text",
    [
        "https&colon;&sol;&sol;" * 7000, "www&period;" * 15000, "https\\:\\/\\/a." * 10000, "\\" * 200000,
        "&amp;" * 30000, "a&amp;b " * 20000, "https&colon;&sol;&sol;a.b/ " * 5000, "&#104;ttps&colon;//a.b " * 5000,
    ],
    ids=["starts", "www", "escaped_starts", "backslashes", "references", "words", "links", "letter_references"],
)
def test_restore_is_fast_on_links_written_with_references_in_prose(text):
    """Слово простого текста раскрывается один раз (_prose): тысячи начал адреса в одном слове, десятки тысяч слов со
    ссылками на знаки и экранированиями."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "почта ivanov@contoso.ru", Settings())
    started = time.perf_counter()
    restore(state, text + "<EMAIL_1>", Settings())
    assert time.perf_counter() - started < 0.5


def test_long_known_value_is_not_sliced_at_every_word():
    """Найдено в раунде имён узлов: длинное написание («a@bbb…b.ru» — слой 1 длину адреса не ограничивает) поиск
    известных значений вырезал из текста с каждого вхождения его первого слова — 180 КБ за 0,8 с, квадратично.
    Длинное написание ищется по началу и сверяется с текстом до первого несовпавшего знака."""
    form = "a@" + "b" * 60000 + ".ru"
    started = time.perf_counter()
    assert len(find_forms(form + " a" * 60000, [(form, "letters", None)])) == 1
    assert time.perf_counter() - started < 0.3


def test_many_long_spellings_with_a_shared_beginning_are_found_in_linear_time():
    """Второе ревью, Important: каждое вхождение начала из 64 знаков сверялось со всеми длинными написаниями с этим
    началом — 6000 токенов вида JWT с общим началом из 74 знаков (486 КБ) искались 2,65 с. Один текст создаёт их сам:
    первый проход делает их написаниями, второй ищет. Длинные написания лежат деревом по 64 знака."""
    prefix = "eyjhbgcioijiuzi1niisinr5cci6ikpxvcj9.eyjzdwiioiixmjm0nty3odkwiiwibmftzsi6"
    forms = [prefix + "%06x" % i for i in range(3000)]
    started = time.perf_counter()
    found = find_forms(" ".join(forms), [(form, "strict", i) for i, form in enumerate(forms)])
    assert time.perf_counter() - started < 0.15
    assert sorted(payload for _, _, payload in found) == list(range(3000))


def test_link_host_check_walks_a_tree_of_parts():
    """Наблюдение раунда имён узлов, P3: проверка хоста ссылки собирала все цепочки частей до числа частей самой длинной
    записанной подмены — после имени из 125 частей хост из 20 000 частей проверялся 2,2 с. Части проходятся по дереву,
    как в поиске замен (surrogates.Finder)."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "узел " + "a." * 125 + "ru", Settings())
    started = time.perf_counter()
    restore(state, "https://" + "host-1." * 5000 + "x/", Settings())
    assert time.perf_counter() - started < 0.3


def test_names_longer_than_a_dns_name_kept_by_older_chats_are_found_by_parts():
    """Чаты, сохранённые до 15.10.2026, хранят целиком и имена длиннее 253 знаков: поиск замен и проверка хоста ссылки
    проходили бы такое имя по дереву на всю его глубину с каждой части. В деревья оно не берётся и находится, и
    восстанавливается по частям (6.4)."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    name = "a." * 3000 + "ru"
    whole = sanitize(state, "узел " + name, Settings()).sanitized.removeprefix("узел ")
    state.surrogates[whole] = Surrogate(state.surrogates["host-1"].entity_id, name, "host")    # как в старом чате
    assert restore(state, whole, Settings()).text == name
    assert sanitize(state, whole, Settings()).sanitized == whole
    for step in ("sanitize", "restore"):
        started = time.perf_counter()
        if step == "sanitize":
            sanitize(state, "host-1." * 3000 + "x", Settings())
        else:
            restore(state, "https://" + "host-1." * 3000 + "x/", Settings())
        assert time.perf_counter() - started < 0.3, step


@pytest.mark.parametrize(
    "text, always, rule",
    [
        ("Иван Иван " * 1000, ("Иван Иван",), None), ("la la " * 1000, (), "la la"),
        ("Иванов Петров " * 500, ("Иванов", "Петров"), None),
    ],
    ids=["dictionary_pairs", "rule_pairs", "surnames"],
)
def test_overlapping_known_values_and_runs_of_names_are_fast_and_not_one_spelling(text, always, rule):
    """Наблюдение раунда имён узлов, P2: пересекающиеся известные значения и ряд фамилий через пробел сливались в
    фрагмент длиной в текст, и он становился написанием чата: раздувал состояние и сверялся с каждым словом текстов.
    Искомы написания находок, ряд длиннее имени не сливается (5.7)."""
    settings = Settings(always=tuple(DictEntry(T.PERSON, value) for value in always))
    state = ChatState(chat_id="long", net_key=bytes(32))
    if rule:
        ops.mask(state, rule, T.TERM)
    sanitize(state, "Иван", settings)       # разбор имён загружается один раз на процесс
    for step in ("sanitize", "again"):
        started = time.perf_counter()
        sanitize(state, text, settings)
        assert time.perf_counter() - started < 0.3, step
    assert max(len(form) for entity in state.entities.values() for form in entity.forms) < 20


@pytest.mark.parametrize(
    "text",
    [
        "host-1\\." * 3000 + "x", "a\\." * 10000, "\\." * 15000, "<EMAIL_1>\\." * 3000,
        # Имя через «\.» при очистке (раунд 3, P1): вперемешку с точками, после знаков выражения, между «\b», рядом с
        # меткой, папки на точку в путях, известное имя, экранированная обратная косая.
        "a\\.b." * 4000, ".*\\.ab" * 5000, "\\bab\\.cd\\b" * 1000, "\\b" + "ab\\." * 6000, "x\\.<ORG_1>\\." * 2000,
        "C:\\Users\\a\\.local\\" * 1000, "contoso\\.ru " * 1500, "a\\\\." * 6000,
        # Имя в смешанном регистре с выданной заменой внутри (раунд 3, P3).
        "Petrov\\.host-1\\." * 2000 + "ru", "Petrov.host-1." * 2000 + "Ru",
        # «\\.» — выражение в строке JSON (второе ревью, P3): после знаков выражения, между «\\b», части замены.
        ".*\\\\.ab" * 2000, "\\\\bab\\\\.cd\\\\b" * 600, "host-1\\\\." * 1500 + "x",
    ],
    ids=[
        "parts", "letters", "separators", "labels",
        "mixed", "after_expressions", "word_bounds", "open_word_bound", "label_parts", "dot_folders", "known",
        "escaped_backslashes", "issued_inside_escaped", "issued_inside",
        "json_after_expressions", "json_word_bounds", "json_parts",
    ],
)
def test_names_written_with_escaped_dots_are_found_in_linear_time(text):
    """Наблюдение раунда имён узлов, P3: имя через «\\.» (регулярное выражение) ищется своим выражением; цепочка из
    тысяч частей проходится по дереву записанных имён, как через точку, — и при очистке, и при восстановлении."""
    state = ChatState(chat_id="long", net_key=bytes(32))
    sanitize(state, "узел " + "srv-01." * 30 + "contoso.ru, почта ivanov@contoso.ru", Settings())
    for step in ("sanitize", "restore"):
        started = time.perf_counter()
        (sanitize if step == "sanitize" else restore)(state, text, Settings())
        assert time.perf_counter() - started < 0.3, step


def test_restorer_setup_is_fast_on_a_chat_with_many_dotted_labels(settings):
    """Второе ревью: сборка восстановления на чате с 20 000 метками, значение которых — имя с точкой («i.ivanov»): ответ
    списка суффиксов запоминается (test_restore.py считает вызовы), и сборка не дороже 30 мс. С пределом сравнивается
    медиана сборки; из быстрого набора — с 21.10.2026: под нагрузкой машины медиана выходила за предел без ошибки."""
    state = ChatState(chat_id="many", net_key=bytes(32))
    for n in range(1, 20001):
        entity = Entity(f"e{n}", T.ACCOUNT, n, f"i.ivanov{n}", f"i.ivanov{n}", "detector")
        state.entities[entity.id] = entity
        state.surrogates[f"<ACCOUNT_{n}>"] = Surrogate(entity.id)
    times = []
    for _ in range(20):
        started = time.perf_counter()
        assert restore(state, "ответ про <ACCOUNT_1>", settings).text == "ответ про i.ivanov1"
        times.append(time.perf_counter() - started)
    assert sorted(times)[10] * 20 < 0.6
