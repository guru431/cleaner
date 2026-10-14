from cleaner.core.detect import secrets
from cleaner.core.detect.base import DetectContext
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
