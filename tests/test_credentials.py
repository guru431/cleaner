"""Идея «Учётные данные по контексту: логин рядом с паролем и пароль на своём месте в командах»: учётная запись по
контексту (логин, login, user, username, журнал Windows, sshd) и пара «логин / пароль» после «доступ», «учётка», «креды»."""
import pytest

from cleaner.core.detect import credentials
from cleaner.core.detect.base import DetectContext
from cleaner.core.types import EntityType, Settings

CTX = DetectContext(Settings())


def found(text: str) -> set[tuple[str, str]]:
    return {(span.type.value, text[span.start:span.end]) for span in credentials.detect(text, CTX)}


@pytest.mark.parametrize(
    "text, value",
    [
        ("логин i.petrova, пароль Qwerty123", "i.petrova"),
        ("Логин: ivanov", "ivanov"),
        ("логином petrov_i вход не проходит", "petrov_i"),
        ("login: ivanov", "ivanov"),
        ("login=ivanov&password=x", "ivanov"),
        ('{"username": "ivanov", "role": "dev"}', "ivanov"),
        ("DB_USER=billing_app", "billing_app"),
        ("POSTGRES_USER: crm_app", "crm_app"),
        ("dbUser=ivanov", "ivanov"),
        ("[client]\nuser = ivanov\n", "ivanov"),
        ("Server=sql01;User Id=app_crm;Password=x;", "app_crm"),
        ("User Name: ivanov", "ivanov"),
    ],
)
def test_login_after_its_key_is_an_account(text, value):
    assert ("ACCOUNT", value) in found(text)


@pytest.mark.parametrize(
    "text",
    [
        "user: hello there", "User: Can you help me?", "user: hello", "login: true", "user: str", "user: User",
        "user = request.user", "username = input()", "login: ${LOGIN}", "user: <your-login>", "user: Optional[User]",
        "last_login: 2024-01-02", "user_id: 42", "uid=1000(ivanov) gid=1000(ivanov)", "user: root", "login: admin",
        "user=user", "login: login", "connect(user=db_user, password=pwd)", "f(host, user=current_user)",
        "user: ivanov@contoso.ru", r"user: CONTOSO\ivanov", "user: currentUser", "login = LOGIN_NAME",
        "логин и пароль от почты", "Введите логин Windows", "логин email", "логин admin", "user agent: curl",
        "max_users: 10", "users: [a, b]", '{"user": user_id, "expires": 1}', "setpriv --reuid=svc01 --regid=svc01",
        r"<example>\n\nuser: what is 2+2?\nassistant: 4", ("super" "user: ivanov"), "ansible_user: ubuntu",
        "POSTGRES_USER: postgres", "Server=sql01;User Id=sa;Password=x;", "username = r'(\\w+)'",
        "# abort the login: keep polling until done", "install(\n    user=use_user_site,\n)",
        "def auth(username: bytes | str, password: bytes | str):",
    ],
)
def test_words_types_code_and_service_names_after_a_login_key_are_left_alone(text):
    assert not {value for type_, value in found(text) if type_ == "ACCOUNT"}, text


def test_short_common_login_is_hidden_only_in_its_place():
    """«user: app» — учётная запись, но слово app искомым написанием чата не становится: иначе оно скрывалось бы везде."""
    spans = credentials.detect("db:\n  user: app\n", CTX)
    assert [(s.type, s.searchable) for s in spans] == [(EntityType.ACCOUNT, False)]
    spans = credentials.detect("db:\n  user: billing_app\n", CTX)
    assert [(s.type, s.searchable) for s in spans] == [(EntityType.ACCOUNT, True)]


WINDOWS_EVENT = (
    "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n"
    "\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tivanov\n"
    "\tAccount Domain:\t\tCONTOSO\n"
)
WINDOWS_EVENT_RU = "Субъект:\n\tИмя учетной записи:\t\tpetrov\n\tДомен учетной записи:\t\tCONTOSO\n"


@pytest.mark.parametrize("text", [WINDOWS_EVENT, WINDOWS_EVENT_RU], ids=["english", "russian"])
def test_account_and_domain_of_a_windows_event_are_found(text):
    assert found(text) == {("ACCOUNT", "petrov" if "petrov" in text else "ivanov"), ("DOMAIN", "CONTOSO")}


@pytest.mark.parametrize(
    "text",
    [
        "Account Name: Contoso Retail", "Account Name: ivanov",
        "\tAccount Name:\t\tSRV01$\n\tAccount Domain:\t\tNT AUTHORITY\n",
        "\tAccount Name:\t\tSYSTEM\n\tAccount Domain:\t\tNT AUTHORITY\n",
        "\tAccount Name:\t\tDWM-1\n\tAccount Domain:\t\tWindow Manager\n",
    ],
)
def test_account_name_outside_a_windows_event_or_of_a_service_is_left_alone(text):
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, value",
    [
        ("Failed password for ivanov from 10.1.2.3 port 52144 ssh2", "ivanov"),
        ("Failed password for invalid user oracle1 from 10.1.2.3 port 52144 ssh2", "oracle1"),
        ("Invalid user deploy from 10.1.2.3 port 52144", "deploy"),
        ("Accepted publickey for i.petrova from 10.1.2.3 port 52144 ssh2", "i.petrova"),
        ("pam_unix(sshd:session): session opened for user petrov(uid=1001) by (uid=0)", "petrov"),
    ],
)
def test_login_in_an_sshd_log_line_is_an_account(text, value):
    assert found(text) == {("ACCOUNT", value)}


@pytest.mark.parametrize(
    "text",
    [
        "Failed password for root from 10.1.2.3 port 52144 ssh2", "Invalid user name or password",
        "Failed password for the account", "session opened for user root(uid=0) by (uid=0)",
    ],
)
def test_sshd_service_logins_and_prose_are_left_alone(text):
    assert found(text) == set()


@pytest.mark.parametrize(
    "text, expected",
    [
        ("доступ admin / Zx9!qLm2#pW", {("SECRET", "Zx9!qLm2#pW")}),
        ("учётка: admin:Zx9!qLm2#pW", {("SECRET", "Zx9!qLm2#pW")}),
        ("креды ivanov/Qwerty123!", {("ACCOUNT", "ivanov"), ("SECRET", "Qwerty123!")}),
        ("доступ к srv-db01: svc_backup / Bk2024!x.", {("ACCOUNT", "svc_backup"), ("SECRET", "Bk2024!x")}),
        ("Учетку дали: i.petrova:Summer2024", {("ACCOUNT", "i.petrova"), ("SECRET", "Summer2024")}),
    ],
)
def test_login_and_password_pair_after_access_words_is_found(text, expected):
    assert found(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "Права доступа: read/write", "доступ 24/7", "доступ 09:00-18:00", "доступ к http://srv-app01:8080/app",
        "доступ host1:8080-8090", "доступ по ssh/rdp", "учётка ivanov", r"доступ к C:\Users\Public",
        "доступ api/v1/users2", "доступ admin/user", "креды в vault/prod",
        "Сервер доступен по адресу cdf:742b:2e85:cb21:7631:de9e:dde9:f863.",
    ],
)
def test_access_words_without_a_complex_password_are_left_alone(text):
    assert found(text) == set()
