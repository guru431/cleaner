import pytest

from cleaner.core.detect import secrets
from cleaner.core.detect.base import DetectContext
from cleaner.core.pipeline import sanitize
from cleaner.core.types import Settings

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
                 "password_reset: weekly", "compass_heading: 270"):
        assert found(text) == set(), text


@pytest.mark.parametrize(
    "text, value",
    [
        ("Пароль от Wi-Fi — sunflower", "sunflower"),
        ("Пароль — qwertyuiop", "qwertyuiop"),
        ("Пароль - Summer", "Summer"),
        ("Пароль — sunflower, логин ivanov", "sunflower"),
        ("Пароль — Qwerty123 действует сутки", "Qwerty123"),
    ],
)
def test_word_after_a_dash_is_a_password_unless_prose_follows(text, value):
    assert found(text) == {value}


def test_prose_after_a_dash_is_left_alone():
    for text in ("Пароль — это строка из 8 символов", "password - see vault", "Пароль — тот же, что и раньше",
                 "Пароль — минимум 8 символов"):
        assert found(text) == set(), text


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
