import pytest

from cleaner.core.detect import secrets
from cleaner.core.detect.base import DetectContext
from cleaner.core.detect.merge import merge
from cleaner.core.pipeline import sanitize
from cleaner.core.types import EntityType, Settings, Span

CTX = DetectContext(Settings())


def found(text: str) -> set[str]:
    return {text[span.start:span.end] for span in secrets.detect(text, CTX)}


def test_key_value_forms():
    assert found("password=Qwerty123!") == {"Qwerty123!"}
    assert found('{"db_password": "s3cr3t-Value"}') == {"s3cr3t-Value"}
    assert found("Server=sql01;User Id=app;Password=P@ssw0rd!2024;") == {"P@ssw0rd!2024"}


def test_non_secrets_are_left_alone():
    for text in (
        "max_tokens: 4096",
        "bypass=true",
        "password: ${DB_PASS}",
        "PasswordAuthentication yes",
        "token_type: Bearer",
        "пароль изменён вчера",
        "maxTokens: 4096",
        "tokenizer: cl100k_base",
        "pwdLastSet: 133497216000000000",
        "password_policy: strict",
        "password: $DB_PASS",
        "Пароль — это набор символов",
    ):
        assert found(text) == set(), text


def test_glued_and_camel_case_key_names():
    """Обзор 1А, P1: имя ключа содержит слово, а не обязательно отделяет его знаком."""
    assert found("dbpass=Qwerty123") == {"Qwerty123"}
    assert found("userpwd=Qwerty123") == {"Qwerty123"}
    assert found('"accessToken": "abc123def456ghi"') == {"abc123def456ghi"}
    assert found("authToken=abc123def456ghi") == {"abc123def456ghi"}
    assert found("refreshToken: abc123def456ghi") == {"abc123def456ghi"}
    assert found("passphrase: Tr0ub4dor&3") == {"Tr0ub4dor&3"}


def test_password_after_a_spaced_hyphen():
    assert found("Пароль - Qwerty123!") == {"Qwerty123!"}


def test_value_keeps_inner_punctuation_and_stops_at_the_next_field():
    assert found("password: P@ss,w0rd!") == {"P@ss,w0rd!"}
    assert found("https://api.example/x?token=abc123def&user=ivanov") == {"abc123def"}
    assert found("пароль: Qwerty123, логин: ivanov") == {"Qwerty123"}


def test_value_that_starts_with_a_dollar_sign():
    assert found("password: $ecret123") == {"$ecret123"}


def test_pgp_private_key_block_is_one_fragment():
    block = "REDACTED_PRIVATE_KEY"
    assert found(f"ключ:\n{block}\n") == {block}


def test_authorization_header_values():
    assert found("Authorization: Bearer abc123def456ghi789") == {"abc123def456ghi789"}
    assert found("Authorization: Basic YWRtaW46UXdlcnR5MTIz") == {"YWRtaW46UXdlcnR5MTIz"}


def test_credentials_in_url_command_line_and_powershell():
    assert found("REDACTED_DB_URL_CREDENTIALSdb01:5432/crm") == {"Sup3rSecret"}
    assert found("mysqldump --password Tr0ub4dor crm") == {"Tr0ub4dor"}
    assert found('$p = ConvertTo-SecureString "Pl@inText1" -AsPlainText -Force') == {"Pl@inText1"}


def test_private_key_block_is_one_fragment():
    block = "REDACTED_PRIVATE_KEY"
    assert found(f"ключ:\n{block}\nдальше") == {block}


def test_tokens_by_shape():
    jwt = "REDACTED_JWT"
    github = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    assert found(f"Authorization: Bearer {jwt}") == {jwt}
    assert found(f"export GH={github}") == {github}


GITLAB_BODY = "a1B2c3D4e5F6g7H8i9J0"            # 20 знаков, как Devise.friendly_token


@pytest.mark.parametrize(
    "prefix",
    ["glpat-", "gldt-", "glft-", "glsoat-", "glrt-", "glrtr-", "glcbt-", "glcbt-64_", "glffct-", "glimt-", "glptt-",
     "glagent-", "gloas-"],
)
def test_gitlab_tokens_of_every_kind_are_found(prefix):
    """Находка «Layer 2 misses PuTTY and SSH2 private keys and GitLab tokens»: у правила detect-secrets значение — группа
    префикса короче 8 знаков, а правила с точной длиной (glimt-, glptt-, gloas-) не видят токен другой длины."""
    token = prefix + GITLAB_BODY
    assert found(f"в CI лежит {token} для сборки") == {token}


def test_gitlab_prefix_in_prose_is_not_a_token():
    for text in ("префиксы glrt- и glcbt- выдаёт GitLab", "gldt-abc12 короче двадцати знаков", "glft-токен"):
        assert found(text) == set(), text


def test_password_in_prose():
    assert found("Временный пароль Qwerty123 действует сутки") == {"Qwerty123"}
    assert found("Пароль администратора: Summer2024") == {"Summer2024"}


SENDGRID = "SG." + "Xk2pQ9vLm4Rt7Wz1Bc8Ny3" + "." + "Hd6Js0Ua5Ef2Gi9Ko4Lp7Mq1Nr8Os3Pt6Qu0Rv5Sw2Y"


def test_library_rules_cover_tokens_our_own_rules_do_not_know():
    assert len(SENDGRID) == 3 + 22 + 1 + 43
    assert found(f"sendgrid: {SENDGRID}") == {SENDGRID}


def test_library_rules_do_not_read_process_wide_plugin_settings(monkeypatch):
    """Обзор 1А, P1: глобальные настройки detect-secrets меняет любой параллельный вызов."""
    from detect_secrets.core import scan

    monkeypatch.setattr(scan, "get_plugins", lambda: [])
    assert found(f"sendgrid: {SENDGRID}") == {SENDGRID}


def test_allowlist_pragma_does_not_switch_the_library_rules_off():
    assert found(f"sendgrid: {SENDGRID}  # pragma: allowlist secret") == {SENDGRID}


UNSIGNED_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."


@pytest.mark.parametrize(
    "text, value",
    [
        ('//registry.npmjs.org/:_au' 'thToken=0f1e2d3c-4b5a-6978' '-8796-a5b4c3d2e1f0',
         '0f1e2d3c-4b5a-6978' '-8796-a5b4c3d2e1f0'),
        ("//registry.npmjs.org/:_authToken=npm_" + "a1B2c3D4e5F6" * 3, "npm_" + "a1B2c3D4e5F6" * 3),
        ("ключ REDACTED_OPENAI_KEY в логе",
         "REDACTED_OPENAI_KEY"),
        (f"заголовок {UNSIGNED_JWT} в логе", UNSIGNED_JWT),
    ],
)
def test_tokens_of_the_slow_library_rules_are_found_by_own_rules(text, value):
    """Находка «NpmDetector is quadratic…»: правила npm, OpenAI и JWT из detect-secrets квадратичны
    на длинной строке и выключены; их токены находят свои правила."""
    assert found(text) == {value}


AWS_SECRETS = [f"{n:04d}" + "Ab" * 18 for n in range(60)]          # 40 знаков, как секретный ключ AWS


@pytest.mark.parametrize("separator", [",", "   "], ids=["commas", "runs_of_spaces"])
def test_every_token_of_a_line_with_hundreds_of_distinct_tokens_is_found(separator):
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: на такой строке значения больше не ищутся
    по всей строке, а берутся там, где их нашли правила (ряды пробелов перед правилами сжимаются)."""
    sids = ["AC%032x" % n for n in range(300)]
    text = separator.join(f'"account_sid":"{sid}"' for sid in sids)
    spans = secrets.detect(text, CTX)
    assert sorted(text[s.start:s.end] for s in spans) == sorted(sids)


def test_repeat_of_a_token_without_its_context_is_found_on_an_ordinary_line():
    """Правило AWS видит ключ только рядом со словом «aws»; повтор того же значения дальше по строке скрывается."""
    value = AWS_SECRETS[0]
    text = f'aws_key="{value}"; echo {value} | base64'
    assert [text[s.start:s.end] for s in secrets.detect(text, CTX)] == [value, value]


def test_repeat_on_a_line_with_many_distinct_tokens_is_found_by_the_second_pass(state, settings):
    """Дальше _REPEATS разных значений строки повтор без контекста слой 2 не ищет; его находит второй проход
    очистки по известным значениям чата."""
    text = "".join(f'aws_key="{value}";' for value in AWS_SECRETS) + " echo " + AWS_SECRETS[-1]
    assert len(secrets.detect(text, CTX)) == len(AWS_SECRETS)
    sanitized = sanitize(state, text, settings).sanitized
    assert not any(value in sanitized for value in AWS_SECRETS), sanitized[-80:]


def test_library_rules_still_see_a_key_after_a_run_of_spaces():
    """Ряд пробелов сжимается перед правилами detect-secrets, а значение ищется в настоящей строке."""
    key = "Zx81kLmN02pQ" * 3 + "Ab1-Cd2_"
    assert len(key) == 44
    text = "ibm_cloud_iam_key" + " " * 40 + key
    assert found(text) == {key}


@pytest.mark.parametrize("line_break", ["\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x85", " "])
def test_library_rule_anchored_at_a_line_start_is_found_after_any_line_break(line_break):
    """Правила detect-secrets идут по строкам только после совпадения во всём тексте; «^» и «(?<=^)» начала строки
    там видят знак конца предыдущей строки как «\\s» и «\\W»."""
    key = "Zx81kLmN02pQ" * 3 + "Ab1-Cd2_"
    for value, line in ((ARTIFACTORY, ARTIFACTORY), (key, f"ibm_cloud_iam_key = {key}")):
        assert found(f"первая строка{line_break}{line}{line_break}") == {value}, repr(line)


@pytest.mark.parametrize(
    "text, value",
    [
        ("bypass_token=Zx81kLmN02pQ", "Zx81kLmN02pQ"),
        ("passthrough_secret: Zx81kLmN02pQ", "Zx81kLmN02pQ"),
        ("compass_api_key=Zx81kLmN02pQ", "Zx81kLmN02pQ"),
        ("context_token: Zx81kLmN02pQ", "Zx81kLmN02pQ"),
        ("password_reset_token: 9f8e7d6c5b4a3f2e", "9f8e7d6c5b4a3f2e"),
        ("passwordResetToken=9f8e7d6c5b4a3f2e", "9f8e7d6c5b4a3f2e"),
        ("password_resetKey=Zx81kLmN02pQ", "Zx81kLmN02pQ"),
        ("VERCEL_AUTOMATION_BYPASS_SECRET=Zx81kLmN02pQ", "Zx81kLmN02pQ"),
    ],
)
def test_key_ending_in_a_secret_word_is_never_skipped(text, value):
    """Обзор пакета исправлений 1А, P1: стоп-слово в начале ключа не отменяет секрет в конце."""
    assert found(text) == {value}


def test_stop_listed_keys_still_hold_no_secret():
    for text in ("bypass=Zx81kLmN02pQ", "context_tokens: 8192", "token_url: https://login.example/t",
                 "password_reset: weekly", "compass_heading: 270", "Argon2-Passes: 13", "num_passes=3"):
        assert found(text) == set(), text
    assert found("passes_secret: Zx81kLmN02pQ") == {"Zx81kLmN02pQ"}


@pytest.mark.parametrize(
    "text, value",
    [
        ("Пароль от Wi-Fi — sunflower", "sunflower"),
        ("Пароль — qwertyuiop", "qwertyuiop"),
        ("Пароль - Summer", "Summer"),
        ("Пароль — sunflower, логин ivanov", "sunflower"),
        ("Пароль — Qwerty123 действует сутки", "Qwerty123"),
        ("Пароль от Wi-Fi — sunflower для гостей", "sunflower"),
        ("Пароль — sunflower логин ivanov", "sunflower"),
        ("пароль – qwerty", "qwerty"),
        ("password - sunflower for guests", "sunflower"),
        ("Пароль от роутера — Ромашка, как обычно", "Ромашка"),
        ("Пароль — йцукен для всех", "йцукен"),
        ('Пароль — "временный"', "временный"),
    ],
    ids=["wifi", "letters", "hyphen", "comma", "clause_after_password_like", "wifi_clause", "login_clause",
         "en_dash", "english_clause", "russian_noun", "unknown_russian", "quoted_adjective"],
)
def test_word_after_a_dash_is_a_password_unless_it_is_a_prose_word(text, value):
    """Находка «Password after a dash followed by prose stays open»: продолжение фразы за словом
    больше не причина его открыть (решение владельца 15.10.2026)."""
    assert found(text) == {value}


def test_prose_after_a_dash_is_left_alone():
    for text in (
        "Пароль — это строка из 8 символов", "password - see vault", "Пароль — тот же, что и раньше",
        "Пароль — минимум 8 символов", "Пароль — это строка из букв", "Пароль — от 8 знаков",
        "Пароль — такой же, как у почты", "Пароль — временный, смените его", "password — the same as before",
        "Password - not required", "Пароль — Минимум 8 символов", "Пароль от почты — прежний",
        "Пароль — изменен вчера", "Пароль — по-прежнему не подходит", "Пароль — кто-то сменил",
        "Пароль — один для всех", "Пароль — ваш номер телефона", "Пароль — дата рождения",
        "Забыл пароль — что делать?", "Сменил пароль — теперь не входит", "password - your birthday",
        "password — minimum 8 characters", "Password - never expires",
    ):
        assert found(text) == set(), text


@pytest.mark.parametrize(
    "text, value",
    [
        ("Пароль — это Qwerty123", "Qwerty123"),
        ("пароль — это: Zx81kLmN", "Zx81kLmN"),
        ("Password - is Summer2024", "Summer2024"),
        ("Пароль — это sunflower", "sunflower"),
        ('Пароль — это "временный"', "временный"),
        ("Пароль для входа в систему — sunflower", "sunflower"),
        ("Пароль от учётной записи в новой системе — sunflower", "sunflower"),
        ("Пароль -- qwerty", "qwerty"),
        ("password -- Summer2024 for guests", "Summer2024"),
        ("Пароль - Qwerty - временный", "Qwerty"),
        ("Пароль - sunflower - для гостей", "sunflower"),
        ("Пароль — Qwerty123!", "Qwerty123!"),
    ],
    ids=["copula", "copula_colon", "english_copula", "copula_word", "copula_quoted", "four_words", "six_words",
         "double_hyphen", "double_hyphen_clause", "second_hyphen", "second_hyphen_clause", "trailing_mark"],
)
def test_password_after_a_copula_a_long_lead_or_a_double_hyphen_is_found(text, value):
    """Ревью правила тире: после «это» значение — следующее слово, перед тире до шести слов, «--» — тоже тире.
    Слово перед тире не начинается с дефиса: иначе «Пароль - Qwerty - временный» брал значение после второго."""
    assert found(text) == {value}


def test_prose_after_a_copula_a_long_lead_or_a_double_hyphen_is_left_alone():
    for text in (
        "Пароль — это не важно", "Пароль — это просто", "Пароль — это ваша дата рождения", "Пароль — это",
        "Password - is required", "Password — is still the same",
        "Пароль для входа в систему — тот же, что и раньше", "Сбросил пароль в личном кабинете вчера вечером — не помогло",
        "Password for the shared mailbox — see below", "password for the VPN account — expired",
        "Пароль -- см. выше", "Password -- please ask the admin", "mysqldump --password --verbose crm",
        "Password - here!", "Пароль — какой?", "Пароль — неверный!", "Пароль от почты — прежний…", "Пароль — ???",
    ):
        assert found(text) == set(), text


def finds(text: str) -> set[tuple[str, bool]]:
    return {(text[span.start:span.end], span.searchable) for span in secrets.detect(text, CTX)}


@pytest.mark.parametrize(
    "text, value, searchable",
    [
        ("Пароль: это Zx81kLmN", "Zx81kLmN", True), ("password: is Summer2024", "Summer2024", True),
        ("Пароль: это: Zx81kLmN", "Zx81kLmN", True), ("пароль = это sunflower", "sunflower", False),
        ('Пароль: это "временный"', "временный", True), ("password: isAdmin1", "isAdmin1", True),
    ],
    ids=["copula", "english", "copula_colon", "equals_word", "quoted", "no_copula"],
)
def test_value_after_a_colon_and_a_copula_is_the_next_word(text, value, searchable):
    """Находка «Review fixes round of 15.10: small leftovers»: после «:» значением бралась связка — «Пароль: это строка»
    скрывал «это» во всём чате. Слово после связки проверяется, как после тире."""
    assert finds(text) == {(value, searchable)}


def test_prose_after_a_colon_and_a_copula_is_left_alone():
    for text in (
        "Пароль: это строка из 8 символов", "Пароль: это", "password: is required", "Пароль: это ваша дата рождения",
        "Password: was changed yesterday", "пароль = это тот же",
    ):
        assert found(text) == set(), text


@pytest.mark.parametrize(
    "text, value, searchable",
    [
        ("Пароль для входа в систему: sunflower", "sunflower", False),
        ("Пароль от учётной записи в новой системе: Zx81kLmN", "Zx81kLmN", True),
        ("Password for the shared mailbox account: Summer2024!", "Summer2024!", True),
        ('Пароль для входа в систему: "временный"', "временный", True),
        ("Пароль для входа в систему: это Qwerty123", "Qwerty123", True),
    ],
    ids=["four_words", "six_words", "english", "quoted", "copula"],
)
def test_password_after_four_to_six_words_and_a_colon_is_found(text, value, searchable):
    """Находка «Review fixes round of 15.10: small leftovers»: перед «:» бралось не больше трёх слов. Дальше — до шести,
    с проверкой прозы, как после тире: обычное слово скрывается только на своём месте."""
    assert finds(text) == {(value, searchable)}


def test_prose_or_a_time_after_four_to_six_words_and_a_colon_is_left_alone():
    for text in (
        "Password policy for domain users: minimum 8 characters", "Пароль для входа в систему: тот же, что и раньше",
        "Password for the shared mailbox: see below", "Password reset for user ivanov at 10:30",
        "Password change failed for user ivanov at 10:30:15", "Пароль для входа в систему=sunflower",
        "Пароль от учётной записи пользователя в новой системе: sunflower",
    ):
        assert found(text) == set(), text


HEX32 = "3f8e9a1b2c4d5e6f7a8b9c0d1e2f3a4b"                       # вымышленный токен
API_KEY = "api_3f8e9a1b2c4d5e6f7a8b9c0d1e2f"


@pytest.mark.parametrize(
    "text, value, searchable",
    [
        (f"пришёл код восстановления {HEX32}, не могу войти", HEX32, True),
        (f"Подтвердите действие токеном {HEX32}", HEX32, True),
        (f"Используйте API ключ {API_KEY} для доступа", API_KEY, True),
        (f"токен для верификации личности: {HEX32}", HEX32, True),
        ("API-ключ для доступа к эндпоинту Zx81kLmN02pQZx81kLmN02pQ", "Zx81kLmN02pQZx81kLmN02pQ", True),
        (f"токен {HEX32} для пользователя ivanov", HEX32, True),
        (f"verification token for the account {HEX32}", HEX32, True),
        ("получил смс с кодом 847593, всё верно?", "847593", False),
        ("recovery code 73921456", "73921456", False),
        (f"вот токн подтверждения {HEX32}", HEX32, True),
    ],
    ids=["code_word", "instrumental", "api_key", "colon", "hyphenated_key", "nearest", "english", "sms_code",
         "english_code", "typo"],
)
def test_token_or_code_after_its_word_in_prose_is_found(text, value, searchable):
    """Находка «Layers 2 and 4 leftovers round: what it leaves»: токены и коды в прозе после «токен», «код
    восстановления» не находились (полнота секретов на hivetrace — 0,179). Код из цифр скрывается только на своём месте."""
    assert finds(text) == {(value, searchable)}


def test_numbers_and_words_after_token_or_code_in_prose_are_left_alone():
    for text in (
        "код ошибки 1603", "код события 4625 в журнале", "код ошибки 18456 при входе", "код 0x80070005",
        "токен истёк, выпустите новый", "код 2024 года", "штрихкод 46012345", "ключ реестра HKLM\\SOFTWARE\\Microsoft",
        "ключ /etc/ssh/ssh_host_ed25519_key на месте", "токен abcdefghijklmnopqrstuvwxyz", "код товара 4601234567890",
        f"токен в файле token.{HEX32}.json", f"ключ 12345678 и {HEX32[:12]}", "token type Bearer",
        f"токен нужно срочно обновить потому что {HEX32}",
    ):
        assert found(text) == set(), text


def test_error_event_or_classifier_code_of_six_to_eight_digits_is_left_alone():
    """Ревью правила «токен или код в тексте»: восьмизначный код ошибки Windows (HRESULT) и код классификатора скрывались
    на своём месте, а это суть вопроса в поддержке."""
    for text in (
        "код ошибки 80070005 при обновлении", "error code 80244022", "Windows Update error code 80244022",
        "ошибка с кодом 80070005", "Установка завершилась с кодом ошибки 80073712", "exited with status code 13370001",
        "Код ОКТМО 45380000", "код по ОКПО 12345678", "код по окуд 0710001", "код события 1000001 в журнале",
    ):
        assert found(text) == set(), text


@pytest.mark.parametrize(
    "text, value",
    [
        ("код подтверждения 847593", "847593"), ("ошибка входа, пришёл код 847593", "847593"),
        ("Error: verification code 73921456", "73921456"), ("Ошибка: код 847593 не подходит", "847593"),
        ("в ответ пришёл код 847593", "847593"),
    ],
    ids=["confirmation", "error_far_before", "error_before_another_word", "error_before_a_colon", "reply"],
)
def test_one_time_code_next_to_an_error_word_is_still_hidden_in_its_place(text, value):
    assert finds(text) == {(value, False)}


def test_identifier_of_words_after_token_key_or_code_is_left_alone():
    """Ревью правила «токен или код в тексте»: имя из слов через «_», «/», «-» (столбец, модуль, модель) было токеном
    и скрывалось во всём чате."""
    for text in (
        "The primary key is customer_order_line_v2_id", "код в модуле cleaner/core/detect/secrets2",
        "tokens for model gpt4o_mini_2024_07_18", "the key column order_items_2024_archive",
        "ключ настройки Security-Policy-Level-2-Strict", "код функции getUserById_v2_handler",
        "ключ API_KEY_2024_PRODUCTION_V2 в файле .env", "tokens for gpt-4o-mini-2024-07-18",
    ):
        assert found(text) == set(), text


@pytest.mark.parametrize(
    "text, value",
    [
        ("токен доступа token_c5b6a7f8e9d0c1b2a3f4", "token_c5b6a7f8e9d0c1b2a3f4"),
        ("токен Zx81kLmN02pQ-aB_cD3eF4gH", "Zx81kLmN02pQ-aB_cD3eF4gH"),
        ("ключ продукта W269N-WFGWX-YVC9B-WJ6CQ-T83GX", "W269N-WFGWX-YVC9B-WJ6CQ-T83GX"),
        ("пароль от почты Summer_Holidays_2024", "Summer_Holidays_2024"),
        ("Password for the mailbox correct-horse-battery-42", "correct-horse-battery-42"),
    ],
    ids=["random_part", "base64url", "product_key", "password_words", "password_passphrase"],
)
def test_token_with_a_random_part_or_a_password_of_words_is_still_found(text, value):
    """Имя из слов открыто только после «токен», «ключ», «код»: после «пароль» это пароль из слов, а часть без вида слова
    (шестнадцатеричная, base64, группа ключа продукта с цифрами между заглавными) делает значение токеном."""
    assert finds(text) == {(value, True)}


def test_english_state_and_pointer_words_after_a_dash_are_left_alone():
    """Ревью правила тире: частые английские слова состояния и указания — проза, а не пароль."""
    for text in (
        "Password - here is the new link", "Password — there in the vault", "password - below", "Password - above",
        "Password - attached", "password — sent by SMS", "Password - needs to be changed", "Password — needed",
        "Password - please contact IT", "password - incorrect", "Password - wrong again", "password — invalid",
        "Password - error 401", "password - unknown", "Password — expires tomorrow", "Password - expired",
        "Password - n/a", "Password - TBD", "password — TODO", "Password - see above", "Password - same as before",
        "Password - as usual", "Password - doesn't work", "Password - isn't set",
    ):
        assert found(text) == set(), text


@pytest.mark.parametrize(
    "text, searchable",
    [
        ("Пароль — Windows не принимает", False), ("Пароль — 2024 года не менялся", False),
        ("Пароль от Wi-Fi — sunflower для гостей", False), ("Пароль — Zx81kLmN", True), ('Пароль — "Windows"', True),
        ("Пароль — это sunflower", False), ("password: sunflower", True), ("пароль = sunflower", True),
    ],
    ids=["product", "year", "word", "password_like", "quoted", "copula_word", "colon", "equals"],
)
def test_only_a_password_like_or_quoted_value_after_a_dash_is_searchable(text, searchable):
    """Ревью правила тире: обычное слово после тире скрывается на своём месте, но не ищется в других текстах чата."""
    assert {span.searchable for span in secrets.detect(text, CTX)} == {searchable}


@pytest.mark.parametrize(
    "first, second",
    [
        ("Пароль — Windows не принимает", "После обновления Windows не стартует служба."),
        ("Password — Outlook keeps asking", "Outlook не запускается, перезапустите Outlook."),
        ("Пароль — 2024 года не менялся", "Отчёт за 2024 год готов."),
    ],
    ids=["windows", "outlook", "year"],
)
def test_ordinary_word_after_a_dash_is_hidden_only_in_its_place(state, settings, first, second):
    """Ревью правила тире: ложный SECRET после тире становился известным написанием на весь чат и не восстанавливался."""
    word = first.split()[2]
    assert word not in sanitize(state, first, settings).sanitized
    assert sanitize(state, second, settings).sanitized == second
    assert sanitize(state, f"{first}. {second}", settings).sanitized.count(word) == second.count(word)


def test_password_after_a_colon_makes_the_dash_value_searchable(state, settings):
    """То же слово, найденное потом после «:», — та же сущность, и с этого места оно ищется во всех текстах."""
    first = sanitize(state, "Пароль от Wi-Fi — sunflower для гостей", settings).sanitized
    assert sanitize(state, "Цветок sunflower на заставке", settings).sanitized == "Цветок sunflower на заставке"
    assert sanitize(state, "Пароль: sunflower1", settings).sanitized == "Пароль: <SECRET_2>"
    assert sanitize(state, "Цветок sunflower на заставке", settings).sanitized == "Цветок sunflower на заставке"
    assert sanitize(state, "password: sunflower", settings).sanitized == "password: <SECRET_1>"
    assert first == "Пароль от Wi-Fi — <SECRET_1> для гостей"
    assert sanitize(state, "Цветок sunflower на заставке", settings).sanitized == "Цветок <SECRET_1> на заставке"


def test_merged_dash_value_is_searchable_if_any_find_of_its_type_is():
    """Слияние (5.7): искомым значение делает находка того же типа (словарь чата), а не другого (имя слоя 4)."""
    weak = Span(9, 15, EntityType.SECRET, "secrets", searchable=False)
    assert merge("Пароль — Иванов", [weak, Span(9, 15, EntityType.PERSON, "ner")], CTX)[0].searchable is False
    assert merge("Пароль — Иванов", [weak, Span(9, 15, EntityType.SECRET, "dict")], CTX)[0].searchable is True


def test_password_like_value_after_a_dash_stays_searchable(state, settings):
    sanitize(state, "Пароль — Zx81kLmN", settings)
    assert sanitize(state, "повторю: Zx81kLmN", settings).sanitized == "повторю: <SECRET_1>"


@pytest.mark.parametrize(
    "text, value",
    [
        ("pwd=Qw,er7y retries=3", "Qw,er7y"),
        ("mysql --password=Pa,ss1 --host=db01", "Pa,ss1"),
        ("export DB_PASSWORD=S3cr,et user=app", "S3cr,et"),
        ("token=ab&cd ef=1", "ab&cd"),
    ],
)
def test_comma_before_a_spaced_word_belongs_to_the_value(text, value):
    """Обзор пакета исправлений 1А, P1: в имени следующего поля нет пробелов."""
    assert found(text) == {value}


def test_value_still_stops_at_the_next_field():
    assert found("Password=Pa;ss1;Server=db") == {"Pa;ss1"}
    assert found("https://api.example/x?token=abc123def&user=ivanov") == {"abc123def"}


def test_short_value_under_a_key_is_kept():
    assert found("password=Q7") == {"Q7"}
    assert found("mysql --password Q7 db") == {"Q7"}
    for text in ("password: no", "Пароль: да", "Пароль: нет"):
        assert found(text) == set(), text


def test_short_counter_or_word_under_a_key_is_not_a_secret():
    """Находка «Small regressions … plan 1В»: после minimum=2 счётчик и «ok» становились секретом."""
    for text in ("max_token: 2048", '"maxToken": 4096', "pass: ok"):
        assert found(text) == set(), text
    assert found("pass: Qwerty1") == {"Qwerty1"}


@pytest.mark.parametrize(
    "text, value",
    [
        ("Password=P@ss1;Persist Security Info=False", "P@ss1"),
        ("Server=db01;Password=P@ss1;User ID=sa", "P@ss1"),
        ("Password=P@ss1;Initial Catalog=crm;Integrated Security=True", "P@ss1"),
        ("pwd=Qw;er ty=3", "Qw;er"),
        ("Password=Pa;Ss Word", "Pa;Ss"),
    ],
)
def test_spaced_field_name_of_capitalised_words_ends_the_value(text, value):
    """Находка «Small regressions … plan 1В»: в строках ADO.NET имя поля из слов с заглавной буквы
    («Persist Security Info», «User ID») — следующее поле, а не продолжение пароля."""
    assert found(text) == {value}


def test_long_key_names_still_hold_secrets():
    """Финальный обзор 1В: предел длины имени ключа пропускал длинные ключи Spring и переменных окружения."""
    for text in (
        "spring.security.oauth2.client.registration.keycloak-corporate.client-secret=Zx81kLmN02pQ",
        "SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CORPORATE_CLIENT_SECRET=Zx81kLmN02pQ",
    ):
        assert found(text) == {"Zx81kLmN02pQ"}, text


def test_pair_inside_another_value_is_still_found():
    assert found("id:token=Zx81kLmN02pQ") == {"Zx81kLmN02pQ"}


def test_password_without_a_login_in_a_url_is_found():
    """Обзор партии P1: стандартная запись Redis «redis://:пароль@хост»."""
    assert found("redis://:Qwerty12@cache.contoso.ru") == {"Qwerty12"}


@pytest.mark.parametrize("text", ["Сервер 85.143.10.20", "сборка 5.0.10.12", "listen 0.0.0.0:443"])
def test_ip_addresses_are_left_to_layer_3(text):
    """Находка «false SECRET … hits»: правило IP из detect-secrets делало адрес секретом без восстановления,
    а адреса получают подмену в слое 3 (спецификация 6.2)."""
    assert found(text) == set()


@pytest.mark.parametrize(
    "text",
    [
        '"max_new_tokens": 1024', '"maxNewTokens": "1024"', "cached_tokens: 12",
        "cancellationToken: cancellationToken", "accessToken: AccessToken;", "db_password = db_password",
        "$pwd1 = Read-Host -AsSecureString", "$env:DB_PASSWORD = Get-Content .\\pass.txt",
        "Authorization: bearer authentication", "Bearer authentication-scheme",
        "bearer authentication/authorization",
    ],
)
def test_counters_and_code_under_secret_keys_are_left_alone(text):
    """Находка «false SECRET … hits»: счётчик токенов, имя той же переменной, вызов команды и слова
    после «bearer» — не секреты, а каждое такое число потом скрывалось во всём чате."""
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, value",
    [
        ("password=123456", "123456"),
        ("password: password", "password"),
        ("accessToken: AccessToken1;", "AccessToken1"),
        ("$pwd1 = Qwerty123", "Qwerty123"),
        ("$pwd1 = Read-Host1", "Read-Host1"),
        ("api_token=9f8e7d6c5b4a", "9f8e7d6c5b4a"),
        ("Authorization: Bearer Zx81kLmN02pQ", "Zx81kLmN02pQ"),
        ("bearer Zx81kLmNoPqRsTuVwX", "Zx81kLmNoPqRsTuVwX"),
    ],
)
def test_values_next_to_counters_and_code_are_still_found(text, value):
    assert found(text) == {value}


@pytest.mark.parametrize(
    "text",
    [
        "password = input()", 'token = os.environ["TOKEN"]', "secret = getpass.getpass()", 'api_key=config.get("key")',
        "password = getpass('Пароль: ')", "self.token = kwargs['token']", "token = os.environ.get(TOKEN_NAME)",
        "$password = $cred.GetNetworkCredential().Password", 'password: request.form["password"]',
    ],
)
def test_call_or_subscript_under_a_secret_key_is_code(text):
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: вызов и индекс после ключа становились секретом
    («input(», «os.environ[»), и этот обрывок кода потом скрывался во всём чате."""
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, value",
    [
        ('password = "Qwerty1("', "Qwerty1("), ("password = 'getpass()'", "getpass()"), ("password=Ab(1", "Ab(1"),
        ("password=Summer2024(", "Summer2024("), ("password=Qw!7(", "Qw!7("), ("Пароль: Ab(1", "Ab(1"),
    ],
)
def test_passwords_with_brackets_are_still_found(text, value):
    """Значение в кавычках — строка, а не код; скобка внутри пароля или в его конце без закрытого вызова — пароль."""
    assert found(text) == {value}


@pytest.mark.parametrize(
    "text",
    [
        "password = self.password", "token = settings.SECRET_KEY", 'api_key = os.environ.get("K", "d")',
        "password = get_secret(name)", "password = get_secret(name, default)", "token = tokens[i]",
        "$password = $cred.Password", "secret: config.oauth.client_secret", "pwd = decrypt(blob,key)",
    ],
    ids=["self", "settings", "environ_get", "call_name", "call_two_names", "index_name", "powershell", "chain",
         "call_no_space"],
)
def test_attribute_or_call_with_names_under_a_secret_key_is_code(text):
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: атрибут через точку и вызов с аргументами после ключа
    становились секретом («self.password», «get_secret(name»)."""
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, value",
    [
        ("password = Summer.2024", "Summer.2024"), ("pwd=Ab.Cd", "Ab.Cd"), ("password: summer.night", "summer.night"),
        ("password: My.Password", "My.Password"), ('password = "self.password"', "self.password"),
        ("password=Ab(1)", "Ab(1)"), ("password=Pass(word)", "Pass(word)"), ("Пароль: Ivan.Petrov", "Ivan.Petrov"),
    ],
    ids=["dot_digits", "dot_words", "lower_words", "secret_word", "quoted", "call_digit", "capital_call", "phrase"],
)
def test_passwords_with_a_dot_or_brackets_that_are_no_code_are_still_found(text, value):
    """Атрибут — код, только если первое имя со строчной буквы, «_» или «$» и последнее содержит слово секрета;
    вызов с аргументами — если имя функции такое же, а аргументы — имена."""
    assert found(text) == {value}


@pytest.mark.parametrize(
    "text, value",
    [
        ("redis://:my.pass@cache.local:6379", "my.pass"), ("sshpass -p top.secret ssh host", "top.secret"),
        ("mysql -uroot -pmy.secret db", "my.secret"), (r"net use \\srv\share top.secret /user:x", "top.secret"),
        ("<password>top.secret</password>", "top.secret"), ("Пароль: top.secret", "top.secret"),
        ("Пароль — top.secret", "top.secret"), ("password is my.secret", "my.secret"),
        ("--password top.secret", "top.secret"), ("sshpass -p qwerty(abc) ssh host", "qwerty(abc)"),
        ("Пароль: qwerty(abc)", "qwerty(abc)"),
        ("password=admin.secret", "admin.secret"), ("password: my.pass", "my.pass"), ("pwd=north.compass", "north.compass"),
        ("Password=my.Password;", "my.Password"), ("$password = $ecret.Pass", "$ecret.Pass"),
        ("password = self.compass", "self.compass"), ("Server=db;Password=config.Password;", "config.Password"),
        ("Password=self.password;User ID=app", "self.password"),
    ],
    ids=["url", "sshpass", "mysql", "net_use", "xml", "ru_colon", "ru_dash", "is", "cli", "sshpass_call", "ru_call",
         "plain_object", "pass", "compass", "conn_end", "ps_pass", "word_inside", "conn_key", "conn_next"],
)
def test_dotted_or_called_value_outside_an_assignment_in_code_is_a_secret(text, value):
    """Обзор раунда слоёв 2 и 4: правило «это код» действовало во всех шаблонах, и пароль с точкой или скобками
    открывался в адресе, команде, XML, прозе, строке подключения и после «password=»."""
    assert found(text) == {value}


@pytest.mark.parametrize(
    "text",
    [
        "password = db_config.password", "token = appSettings.Token", "password = this.password;",
        "api_key: opts.api_key", "password: process.env.DB_PASSWORD", "Password = cfg.secretKey",
    ],
    ids=["underscore", "camel", "statement", "opts", "process", "secret_key"],
)
def test_attribute_of_a_code_object_under_a_secret_key_is_code(text):
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, value",
    [
        ("pwd=Ab[1]", "Ab[1]"), ("password=(Qw1)", "(Qw1)"), ("f(password=abc)", "abc"), ("pwd=Ab{1}", "Ab{1}"),
        ("connect(pwd=Ab[1])", "Ab[1]"), ("password=(Qw1).", "(Qw1)"), ("token=Ab(1)]", "Ab(1)"),
    ],
    ids=["square", "round", "call_end", "curly", "inside_call", "full_stop", "foreign_square"],
)
def test_closing_bracket_stays_with_the_value_when_its_pair_is_inside(text, value):
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: закрывающая скобка отрезалась всегда («Ab[1»)."""
    assert found(text) == {value}


@pytest.mark.parametrize("text", ["password = (input())", "pwd = (get_secret(name))", "token = (os.environ[KEY])"])
def test_code_in_brackets_under_a_secret_key_is_code(text):
    """Находка «Layers 2 and 4 leftovers round: what it leaves»: вызов или индекс в скобках («(input())») был секретом
    и скрывался во всём чате."""
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, value",
    [("password=((Qw1))", "((Qw1))"), ("password=(Ab(1))", "(Ab(1))"), ("password=(a)(b)", "(a)(b)"),
     ("password=(Ab()", "(Ab()"), ("Пароль: (input())", "(input())")],
)
def test_password_in_brackets_is_still_found(text, value):
    assert found(text) == {value}


def test_word_or_number_in_brackets_is_still_prose():
    for text in (
        "password: (optional)", "Пароль (временный) действует сутки", "password: (empty)", "token: (N/A)",
        "Requirements for password: (1) eight characters", "Пароль: (см. выше)", "password = (none)",
    ):
        assert found(text) == set(), text


def test_private_key_header_in_prose_is_not_a_secret():
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: правило detect-secrets брало фразу заголовка за секрет."""
    for text in (
        "Файл начинается со строки BEGIN RSA PRIVATE KEY", "ключ BEGIN OPENSSH PRIVATE KEY, а не PuTTY-User-Key-File-2",
    ):
        assert found(text) == set(), text


def test_private_key_block_after_its_header_in_prose_is_one_fragment():
    block = "REDACTED_PRIVATE_KEY"
    assert found(f"Файл начинается со строки BEGIN RSA PRIVATE KEY:\n{block}\n") == {block}


@pytest.mark.parametrize(
    "text, value",
    [
        ("ключ:\n----BEGIN RSA PRIVATE KEY----\nMIIEowIBAAKCAQEA\n----END RSA PRIVATE KEY----\nдальше",
         "----BEGIN RSA PRIVATE KEY----\nMIIEowIBAAKCAQEA\n----END RSA PRIVATE KEY----"),
        ("ключ:\n—–BEGIN RSA PRIVATE KEY—–\nMIIEowIBAAKCAQEA\n—–END RSA PRIVATE KEY—–\nдальше",
         "—–BEGIN RSA PRIVATE KEY—–\nMIIEowIBAAKCAQEA\n—–END RSA PRIVATE KEY—–"),
        ("ключ:\n----BEGIN RSA PRIVATE KEY----\nMIIEowIBAAKCAQEA\n\nдальше",
         "----BEGIN RSA PRIVATE KEY----\nMIIEowIBAAKCAQEA\n\nдальше"),
        ("ключ:\nBEGIN RSA PRIVATE KEY\nMIIEowIBAAKCAQEA\nAAKCAQEAMIIEowIB\nEND RSA PRIVATE KEY\nдальше",
         "BEGIN RSA PRIVATE KEY\nMIIEowIBAAKCAQEA\nAAKCAQEAMIIEowIB\nEND RSA PRIVATE KEY"),
        ("ключ: BEGIN RSA PRIVATE KEY\r\nMIIEowIBAAKCAQEA\r\nAAKCAQEAMIIEowIB\r\n\r\nдальше",
         "BEGIN RSA PRIVATE KEY\r\nMIIEowIBAAKCAQEA\r\nAAKCAQEAMIIEowIB"),
        ("-----BEGIN OPENSSH PRIVATE KEY\nb3BlbnNzaC1rZXktdjEAAAAA\n\nдальше",
         "-----BEGIN OPENSSH PRIVATE KEY\nb3BlbnNzaC1rZXktdjEAAAAA"),
    ],
    ids=["four_dashes", "typographic", "dashes_to_the_end", "bare_end", "bare_blank_line", "one_side"],
)
def test_private_key_block_with_a_damaged_header_is_one_fragment(text, value):
    """Обзор раунда слоёв 2 и 4: после выключения PrivateKeyDetector заголовок с другим числом дефисов, с тире или
    без них не помечался ничем, и тело ключа уходило открытым."""
    assert found(text) == {value}


def test_bare_private_key_header_without_a_body_is_not_a_secret():
    for text in (
        "Строка BEGIN RSA PRIVATE KEY\nа за ней тело ключа", "BEGIN PRIVATE KEY\nthen the body follows",
        "BEGIN RSA PRIVATE KEY-----", "Ключ: XBEGIN RSA PRIVATE KEY\nMIIEowIBAAKCAQEA",
    ):
        assert found(text) == set(), text


KEY_LINE = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCx" * 2                 # строка тела ключа, 64 знака base64 (вымышленная)
PPK_2 = (
    "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: rsa-key-20261015\nPublic-Lines: 2\n"
    f"{KEY_LINE}\n{KEY_LINE[:20]}\nPrivate-Lines: 2\n{KEY_LINE}\n{KEY_LINE[:24]}\n"
    "Private-MAC: 0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"
)
PPK_3 = (
    "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: eddsa-key-20261015\nPublic-Lines: 2\n"
    f"{KEY_LINE}\n{KEY_LINE[:8]}\nKey-Derivation: Argon2id\nArgon2-Memory: 8192\nArgon2-Passes: 13\n"
    f"Argon2-Parallelism: 1\nArgon2-Salt: 0f1e2d3c4b5a69788796a5b4c3d2e1f0\nPrivate-Lines: 1\n{KEY_LINE}\n"
    "Private-MAC: 0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
)
SSH2_KEY = (
    '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: "rsa-key-20261015"\n'
    f"P2/56wAAAi4AAAA3aWYtbW9kbntzaWdu\n{KEY_LINE}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----"
)


@pytest.mark.parametrize(
    "text, value",
    [
        (f"ключ:\n{PPK_2}\nдальше", PPK_2), (f"ключ:\n{PPK_3}\nдальше", PPK_3), (f"ключ:\n{SSH2_KEY}\nдальше", SSH2_KEY),
        ("ключ:\r\n" + PPK_2.replace("\n", "\r\n") + "\r\nдальше", PPK_2.replace("\n", "\r\n")),
        (PPK_2.rsplit("\n", 1)[0] + "\n\nдальше", PPK_2.rsplit("\n", 1)[0]),
        ("ключ:\n" + SSH2_KEY.replace("---- ", "").replace(" ----", "") + "\nдальше",
         SSH2_KEY.replace("---- ", "").replace(" ----", "")),
    ],
    ids=["putty_2", "putty_3", "ssh2", "putty_crlf", "putty_without_mac", "ssh2_without_runs"],
)
def test_putty_and_ssh2_private_keys_are_one_fragment(text, value):
    """Находка «Layer 2 misses PuTTY and SSH2 private keys and GitLab tokens»: ключ PuTTY не скрывало ни одно правило,
    а у заголовка SSH2 ряды отделены пробелом, и шаблон PEM его не видел."""
    assert found(text) == {value}


def test_putty_and_ssh2_headers_without_a_key_body_are_not_secrets():
    for text in (
        "Файл начинается со строки PuTTY-User-Key-File-3: ssh-ed25519, за ней идут поля",
        "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: тело ключа не вставлено",
        "Формат ---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ---- открывает PuTTYgen",
        "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nа дальше идёт тело ключа",
        f'---- BEGIN SSH2 PUBLIC KEY ----\nComment: "rsa-key"\n{KEY_LINE}\n---- END SSH2 PUBLIC KEY ----',
    ):
        assert found(text) == set(), text


PGP_LINE = "lQOYBF0abcdEFGHlQOYBF0abcdEFGH"


@pytest.mark.parametrize(
    "text, value",
    [
        (f"ключ:\nBEGIN PGP PRIVATE KEY BLOCK\nVersion: GnuPG v2\n\n{PGP_LINE}\n=AbCd\nEND PGP PRIVATE KEY BLOCK\nдальше",
         f"BEGIN PGP PRIVATE KEY BLOCK\nVersion: GnuPG v2\n\n{PGP_LINE}\n=AbCd\nEND PGP PRIVATE KEY BLOCK"),
        (f"BEGIN PGP PRIVATE KEY BLOCK\r\n\r\n{PGP_LINE}\r\n\r\nдальше", f"BEGIN PGP PRIVATE KEY BLOCK\r\n\r\n{PGP_LINE}"),
        ("-----BEGIN RSA PRIVATE KEY\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0F1E2D3C4B5A6978\n\n"
         "MIIEowIBAAKCAQEA\n\nдальше",
         "-----BEGIN RSA PRIVATE KEY\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0F1E2D3C4B5A6978\n\nMIIEowIBAAKCAQEA"),
    ],
    ids=["pgp_armour", "pgp_empty_line", "pem_headers"],
)
def test_key_body_after_armour_headers_and_an_empty_line_is_one_fragment(text, value):
    """Находка «Layers 2 and 4 review round: small leftovers»: заголовок без рядов, за которым идут строки «Имя: значение»
    брони PGP или шифрованного PEM и пустая строка, не находился, и тело ключа уходило открытым."""
    assert found(text) == {value}


def test_key_header_followed_by_prose_after_an_empty_line_is_not_a_secret():
    for text in (
        "BEGIN PGP PRIVATE KEY BLOCK\n\nЭто строка заголовка брони, за ней пустая строка",
        "BEGIN PGP PRIVATE KEY BLOCK\nVersion: GnuPG v2\n\nа дальше идёт тело",
        "BEGIN RSA PRIVATE KEY\nNote: the body follows\n\nsee the attachment",
        f"BEGIN PGP PRIVATE KEY BLOCK\n\n\n{PGP_LINE}",
    ):
        assert found(text) == set(), text


ARTIFACTORY = "AKC" + "p8Xk2pQ9vLm4Rt7Wz1"


@pytest.mark.parametrize(
    "text, value",
    [
        (f'"artifactory": "{ARTIFACTORY}"', ARTIFACTORY), (f"токен {ARTIFACTORY} в профиле", ARTIFACTORY),
        ("в профиле указан AP6abcdEFGH12 и всё", "AP6abcdEFGH12"),
        (f"токен {ARTIFACTORY} в профиле", ARTIFACTORY),
    ],
    ids=["quoted", "spaces", "password", "nbsp"],
)
def test_artifactory_value_is_found_without_its_surroundings(text, value):
    """Находка «Layers 2 and 4: what the batch of 15.10 left»: значение правила Artifactory включало кавычки и пробелы
    (и неразрывный пробел: «\\s» в выражении правила — любой пробел Юникода)."""
    assert found(text) == {value}


@pytest.mark.parametrize(
    "text",
    [
        "PWD=/home/ivanov", "OLDPWD=~/src", "msbuild /p:Configuration=Release",
        "dotnet msbuild /p:Configuration=Release;Platform=x64", "mysqldump --password --verbose crm",
        "Пароль по-прежнему не подходит", "пароль кто-то сменил",
    ],
)
def test_paths_properties_flags_and_prose_are_left_alone(text):
    """Находка «false positives that damage the text…»: рабочий каталог оболочки, свойство MSBuild,
    следующий параметр и русское слово через дефис становились секретом без восстановления."""
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, value",
    [
        ("Server=db01;UID=sa;PWD=Qwerty123!;", "Qwerty123!"),
        ("PWD=Qwerty123!", "Qwerty123!"),
        ("runas /p:Qwerty123", "Qwerty123"),
        ("tool /p:dGVzdDE=", "dGVzdDE="),
        ("msbuild /p:CertificatePassword=Secret123", "Secret123"),
        ("mysqldump --password Qwerty123 crm", "Qwerty123"),
        ("mysqldump --password=-Qwerty123 crm", "-Qwerty123"),
        ("Пароль: по-прежнему", "по-прежнему"),
        ("Временный пароль Пароль-2024 действует сутки", "Пароль-2024"),
    ],
)
def test_passwords_next_to_paths_properties_flags_and_prose_are_found(text, value):
    assert found(text) == {value}


@pytest.mark.parametrize(
    "text, value",
    [
        (r"net use \\srv-fs01\share Qwerty123 /user:CONTOSO\ivanov", "Qwerty123"),
        (r"net use Z: \\srv-fs01\share Qwerty123 /user:ivanov", "Qwerty123"),
        (r"NET USE \\srv-fs01\share /user:CONTOSO\ivanov /persistent:no Qwerty123", "Qwerty123"),
        ("mysql -uroot -pQwerty123 crm", "Qwerty123"),
        ("mysqldump -h db01 -u app -p'S3cr3t pass' crm", "S3cr3t pass"),
        ("mariadb-dump -uapp -pS3cr3t crm", "S3cr3t"),
        ("sshpass -p Qwerty123 ssh admin@srv-db01", "Qwerty123"),
        ("sshpass -pQwerty123 scp a.txt srv-db01:", "Qwerty123"),
        ('<add key="DbPassword" value="Qwerty123"/>', "Qwerty123"),
        ("<add key='Smtp.Password' value='Qwerty123' />", "Qwerty123"),
    ],
)
def test_password_at_its_place_in_a_known_command_is_found(text, value):
    """Идея «Command-specific password rules»: пароль без слова-ключа на своём месте в команде."""
    assert found(text) == {value}


@pytest.mark.parametrize(
    "text",
    [
        r"net use \\srv-fs01\share /user:CONTOSO\ivanov", r"net use \\srv-fs01\share * /user:ivanov",
        r"net use Z: \\srv-fs01\share /persistent:yes", "net use \\\\srv-fs01\\share\nдальше текст",
        "mysql -u root -p crm", "mysql -p", "mysql -P3306 -h db01 crm", "mysql -uroot crm | grep -pattern",
        "sshpass -f ~/.pw ssh srv-db01", "sshpass -e ssh srv-db01",
        '<add key="PageSize" value="20"/>', '<add key="PasswordMinLength" value="8"/>',
        '<add key="DbPassword" value="${DB_PASS}"/>',
    ],
)
def test_known_command_without_a_password_is_left_alone(text):
    assert found(text) == set()
