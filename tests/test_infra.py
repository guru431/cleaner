import pytest

from cleaner.core.detect import infra
from cleaner.core.detect.base import DetectContext
from cleaner.core.entities import hostmap
from cleaner.core.types import DictEntry, Settings
from cleaner.core.types import EntityType as T

CTX = DetectContext(Settings())


def found(text: str, ctx: DetectContext = CTX) -> set[tuple[T, str]]:
    return {(span.type, text[span.start:span.end]) for span in infra.detect(text, ctx)}


def values(text: str, ctx: DetectContext = CTX) -> set[str]:
    return {value for _, value in found(text, ctx)}


def test_split_name():
    assert hostmap.split_name("srv-dc01.msk.corp.contoso.ru") == (["srv-dc01", "msk", "corp"], "contoso.ru")
    assert hostmap.split_name("SRV1.corp.local") == (["SRV1"], "corp.local")
    assert hostmap.split_name("contoso.ru") == ([], "contoso.ru")
    assert hostmap.split_name("setup.unknownext") == (["setup", "unknownext"], "")


def test_addresses():
    result = found("Узел 10.1.2.5, сеть 10.1.0.0/16, интерфейс 10.1.2.1/24, DNS 8.8.8.8, петля 127.0.0.1")
    assert (T.IP, "10.1.2.5") in result
    assert (T.IP, "10.1.0.0/16") in result
    assert (T.IP, "10.1.2.1") in result
    assert (T.IP, "8.8.8.8") in result
    assert "127.0.0.1" not in {value for _, value in result}


def test_version_numbers_and_masks_are_not_addresses():
    assert values("Версия 2.1.0.5 установлена, маска 255.255.255.0, build 1.2.3.4") == set()


def test_ipv6_and_mac():
    result = found(
        "Адрес 2a00:1450:4010::65, шлюз fe80::1, MAC 00:1A:2B:3C:4D:5E и 001a.2b3c.4d5e, время 12:30:45"
    )
    assert (T.IP, "2a00:1450:4010::65") in result
    assert (T.IP, "fe80::1") in result
    assert (T.MAC, "00:1A:2B:3C:4D:5E") in result
    assert (T.MAC, "001a.2b3c.4d5e") in result
    assert "12:30:45" not in {value for _, value in result}


def test_hosts_in_network_context():
    result = found(
        r"Откройте https://portal.contoso.ru:8443/app и \\FS01\Обмен, затем Invoke-Command -ComputerName WS-0142"
    )
    assert (T.HOST, "portal.contoso.ru") in result
    assert (T.HOST, "FS01") in result
    assert (T.HOST, "WS-0142") in result


def test_dotted_names_without_context():
    assert (T.HOST, "srv-dc01.corp.contoso.ru") in found("Не отвечает srv-dc01.corp.contoso.ru.")
    assert (T.DOMAIN, "contoso.ru") in found("Домен contoso.ru недоступен")
    assert (T.HOST, "SRV1.corp.local") in found("Узел SRV1.corp.local")


def test_code_and_file_names_are_not_hosts():
    text = "System.Net.Http и os.name, вызов re.search(x), файл README.md, setup.py, версия 1.2.3.dev, $obj.host"
    assert values(text) == set()


def test_well_known_and_never_listed_names_stay():
    ctx = DetectContext(Settings(never=frozenset({"partner.org"})))
    text = "Скачайте с download.microsoft.com, зеркало files.partner.org, наш сайт contoso.ru"
    assert values(text, ctx) == {"contoso.ru"}


def test_machine_account_and_share_names():
    result = found(r"Учётная запись SRV-APP01$ заблокирована, шара \\FS01\ADMIN$ и цена 100$")
    assert (T.HOST, "SRV-APP01") in result
    assert not {"ADMIN", "100"} & {value for _, value in result}


def test_accounts():
    result = found(
        r"Вход CONTOSO\ivanov, профиль C:\Users\ivanov\Desktop, служба NT AUTHORITY\SYSTEM, папка C:\Users\Public"
    )
    assert (T.DOMAIN, "CONTOSO") in result
    assert (T.ACCOUNT, "ivanov") in result
    assert not {"AUTHORITY", "SYSTEM", "Public"} & {value for _, value in result}


def test_lowercase_domain_prefix_must_be_known():
    assert T.ACCOUNT not in {type_ for type_, _ in found(r"папка reports\summary")}
    ctx = DetectContext(Settings(always=(DictEntry(T.DOMAIN, "contoso.ru", ("contoso",)),)))
    assert (T.ACCOUNT, "petrov") in found(r"вход contoso\petrov", ctx)


def accounts(text: str) -> set[str]:
    return {value for type_, value in found(text) if type_ is T.ACCOUNT}


def test_account_after_a_user_switch():
    """Обзор 1А, P1: двоеточие перед доменом — это ключ команды, а не диск."""
    for text in (r"net use \\FS01\share /user:CONTOSO\ivanov", r"runas /user:CONTOSO\ivanov cmd"):
        result = found(text)
        assert (T.DOMAIN, "CONTOSO") in result and (T.ACCOUNT, "ivanov") in result, text


def test_json_escaped_backslashes():
    """Обзор 1А, P1: в журналах JSON обратная косая удвоена."""
    text = r'{"user": "CONTOSO\\ivanov", "path": "C:\\Users\\ivanov\\Desktop", "share": "\\\\FS01\\share"}'
    result = found(text)
    assert (T.DOMAIN, "CONTOSO") in result
    assert accounts(text) == {"ivanov"}
    assert (T.HOST, "FS01") in result
    assert "Users" not in {value for _, value in result}


def test_ipv6_address_followed_by_a_colon():
    assert (T.IP, "2a00:1450:4010::65") in found("Адрес 2a00:1450:4010::65: не отвечает")


def test_profile_name_with_a_space_and_with_trailing_punctuation():
    """Обзор 1А, P1: имя с пробелом целиком, точка после имени — не часть имени."""
    assert accounts(r"Профиль C:\Users\Иван Петров\Desktop") == {"Иван Петров"}
    assert accounts(r"Профиль C:\Users\ivanov. Учётка CONTOSO\ivanov") == {"ivanov"}


def test_sid_and_dn():
    result = found(
        "SID S-1-5-21-1004336348-1177238915-682003330-1104, системный S-1-5-18, "
        "объект CN=Ivan Petrov,OU=IT,DC=contoso,DC=ru найден"
    )
    assert (T.SID, "S-1-5-21-1004336348-1177238915-682003330-1104") in result
    assert "S-1-5-18" not in {value for _, value in result}
    assert (T.DN, "CN=Ivan Petrov,OU=IT,DC=contoso,DC=ru") in result


@pytest.mark.parametrize(
    "text, name",
    [
        (r'cd "C:\Users\Иван Петров"', "Иван Петров"),
        (r"Профиль: C:\Users\Иван Петров.", "Иван Петров"),
        (r"Профиль C:\Users\Иван Петров, а учётка другая", "Иван Петров"),
        ("Профиль C:\\Users\\Иван Петров\nдальше", "Иван Петров"),
        ("'/home/ivan petrov'", "ivan petrov"),
    ],
)
def test_spaced_profile_name_before_a_quote_punctuation_or_line_end(text, name):
    """Обзор пакета исправлений 1А, P1: имя с пробелом берётся целиком не только перед «\»."""
    assert accounts(text) == {name}


def test_profile_name_followed_by_prose_is_one_word():
    assert accounts(r"профиль C:\Users\ivanov лежит на диске") == {"ivanov"}
    assert accounts(r'cd "C:\Users\ivanov" && dir') == {"ivanov"}


def test_host_after_a_url_login_is_found_before_punctuation():
    """FINDINGS P1 «Logins and hosts in URLs…»: хост после «user@» со знаком препинания за ним оставался открытым."""
    for text in (
        "Подключись: ssh://ivanov@srv-db01.corp.contoso.ru, пароль спроси",
        "(ssh://ivanov@srv-db01.corp.contoso.ru)",
        "ssh://ivanov@srv-db01.corp.contoso.ru; дальше",
    ):
        assert (T.HOST, "srv-db01.corp.contoso.ru") in found(text), text


def test_hyphenated_spaced_profile_name_is_taken_whole():
    assert accounts(r"C:\Users\Ivan Petrov-Vodkin\Documents") == {"Ivan Petrov-Vodkin"}
