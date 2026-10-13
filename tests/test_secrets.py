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
    ):
        assert found(text) == set(), text


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
