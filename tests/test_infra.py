import pytest

from cleaner.core.detect import infra
from cleaner.core.detect.base import DetectContext
from cleaner.core.entities import hostmap
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import restore
from cleaner.core.types import ChatState, DictEntry, Settings
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


def test_a_whole_private_range_is_kept_and_a_network_inside_it_is_hidden():
    """Частный диапазон целиком («10.0.0.0/8») ничего не выдаёт, как и документационные: его подмена совпадала с ним
    самим, и он всегда становился меткой. Сеть внутри диапазона и адрес узла скрываются."""
    text = "Диапазоны 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 и 100.64.0.0/10; сеть 10.0.0.0/9, узел 192.168.0.0"
    assert found(text) == {(T.IP, "10.0.0.0/9"), (T.IP, "192.168.0.0")}
    state = ChatState(chat_id="ranges", net_key=bytes(32))
    sanitized = sanitize(state, "Разрешены 10.0.0.0/8 и 192.168.0.0/16", Settings()).sanitized
    assert sanitized == "Разрешены 10.0.0.0/8 и 192.168.0.0/16"


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


@pytest.mark.parametrize(
    "text",
    [
        "git config --global user.email", "const el = e.target;", "systemctl isolate multi-user.target",
        "настройки в application.properties и log4j.properties", "ключ ~/.ssh/id_rsa.pub", "import java.io.*;",
    ],
)
def test_code_names_ending_in_a_top_level_domain_are_not_domains(text):
    """FINDINGS P3 «Detection: false positives that damage the text, and smaller recall gaps»: домены из кода."""
    assert values(text) == set()


def test_real_names_with_the_same_endings_are_still_found():
    text = "Узлы srv01.corp.local, mail.contoso.ru, portal.fabrikam.org, api.contoso.io; домен contoso.io"
    assert values(text) == {"srv01.corp.local", "mail.contoso.ru", "portal.fabrikam.org", "api.contoso.io", "contoso.io"}
    assert values(r"https://portal.contoso.email/app, \\fs01.contoso.pub\share") == {
        "portal.contoso.email", "fs01.contoso.pub",
    }


@pytest.mark.parametrize("text", [r"dir /s C:\Temp", r"xcopy /S D:\src", "dir /s c:"])
def test_drive_letter_after_a_switch_is_not_a_host(text):
    assert values(text) == set()


def test_host_after_a_server_switch_is_still_found():
    assert values("schtasks /S srv01 /query, systeminfo /s SRV02") == {"srv01", "SRV02"}


@pytest.mark.parametrize(
    "text",
    [
        "dir /s logs", "xcopy /s src dst", "findstr /s error *.log", "del /S temp", "robocopy src dst /S logs",
        "attrib +r /s docs", "tasklist /v | findstr /s chrome", "schtasks /query\ndir /s logs",
    ],
)
def test_subdirectory_switch_takes_no_host(text):
    """Финальный обзор партии: «/S» у dir, xcopy, findstr — ключ подкаталогов, слово за ним — не узел."""
    assert values(text) == set()


@pytest.mark.parametrize(
    "text, host",
    [
        ("schtasks /query /fo list /s srv-app01", "srv-app01"),
        ('schtasks /create /tn "Backup job" /sc daily /S SRV01 /u admin', "SRV01"),
        ("tasklist /s srv01", "srv01"), ("taskkill /S srv01 /im app.exe", "srv01"), ("gpresult /s ws-0142 /r", "ws-0142"),
        ("getmac /s srv01", "srv01"), ("driverquery /s srv01", "srv01"), ("eventcreate /s srv01 /t error /id 100", "srv01"),
        ("openfiles /query /s srv01", "srv01"), ("waitfor /s srv01 /si done", "srv01"), ("setx /s srv01 X 1", "srv01"),
        ("takeown /s srv01 /f a.txt", "srv01"), (r"C:\Windows\System32\SYSTEMINFO.EXE /S srv01", "srv01"),
    ],
)
def test_server_switch_of_a_remote_command_names_a_host(text, host):
    assert (T.HOST, host) in found(text)


def test_zero_padded_address_is_found():
    result = found("узлы 010.001.002.005 и 192.168.001.010")
    assert {(T.IP, "010.001.002.005"), (T.IP, "192.168.001.010")} <= result
    assert values("петля 127.000.000.001, версия 001.002.003.004, номер 01.02.03.04") == set()


def test_zero_padded_address_is_masked_and_restored():
    """Запись с нулями впереди сводится к обычной: подмена — переставленный адрес, а не метка, и восстанавливается
    обычная запись адреса."""
    state = ChatState(chat_id="padded", net_key=bytes(32))
    result = sanitize(state, "узел 010.001.002.005", Settings())
    assert "010.001.002.005" not in result.sanitized and "<IP_" not in result.sanitized
    assert restore(state, result.sanitized, Settings()).text == "узел 10.1.2.5"


def test_zero_padded_and_plain_spellings_are_one_address():
    """FINDINGS «Small gaps left by the findings batch of 15.10»: «010.001.002.005» получал метку и был
    отдельной сущностью от 10.1.2.5."""
    state = ChatState(chat_id="padded", net_key=bytes(32))
    result = sanitize(state, "узлы 010.001.002.005 и 10.1.2.5", Settings())
    padded, plain = (span.surrogate for span in result.spans)
    assert padded == plain and padded.startswith("10.") and padded.endswith(".5") and padded != "10.1.2.5"
    assert len(state.entities) == 1


@pytest.mark.parametrize("text, expected", [
    (r"if ($remote_addr ~ ^10\.1\.2\.35$) { return 403; }", {(T.IP, r"10\.1\.2\.35")}),
    (r"grep -E '192\.168\.10\.5|8\.8\.4\.4' access.log", {(T.IP, r"192\.168\.10\.5"), (T.IP, r"8\.8\.4\.4")}),
    (r"Deny from 10\.1\.0\.0/16 и узел 010\.001\.002\.005", {(T.IP, r"10\.1\.0\.0/16"), (T.IP, r"010\.001\.002\.005")}),
], ids=["nginx", "grep", "network-and-padded"])
def test_ipv4_written_with_escaped_dots_is_found(text, expected):
    """Второе ревью, P2: адрес в регулярном выражении, правиле nginx, шаблоне grep пишут через «\\.», и слой 3 его не
    находил — адрес уходил в облако. Разделители — все три «\\.»; правила — те же, что у адреса через точку."""
    assert found(text) == expected


@pytest.mark.parametrize("text", [
    r"version 1\.2\.3\.4, build 10\.0\.190\.45",r"^\d+\.\d+\.\d+\.\d+$ и [0-9]{1,3}\.[0-9]{1,3}", r"^127\.0\.0\.1$",
    r"10\\\\.1\\\\.2\\\\.35 и 10\.1\.2\.35\.4", r"C:\Logs\10\.1\.2",
], ids=["versions", "patterns", "loopback", "escaped-backslash-and-longer", "short"])
def test_backslash_and_dot_elsewhere_make_no_address(text):
    """Та же находка с другой стороны: номера версий, шаблоны чисел, петля, «\\\\\\\\.» (в JSON — обратная косая и любой
    знак выражения), цепочка длиннее адреса и три числа остаются, как через точку."""
    assert values(text) == set()


def test_lowercase_domain_known_from_an_earlier_text():
    ctx = DetectContext(Settings(), known=(("CORP", T.DOMAIN),))
    assert (T.ACCOUNT, "petrov") in found(r"вход corp\petrov", ctx)


def test_cyrillic_login():
    assert accounts(r"вход CORP\иванов, профиль C:\Users\петров\Desktop") == {"иванов", "петров"}
    assert values(r"ERROR\nОшибка доступа, папка отчёты\иванов") == set()


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


def test_first_label_of_a_known_dns_domain_is_a_known_netbios_name():
    """Решение владельца 15.10: при известном «contoso.ru» строчное «contoso\\petrov» — учётная запись."""
    ctx = DetectContext(Settings(), known=(("contoso.ru", T.DOMAIN),))
    result = found(r"вход contoso\petrov", ctx)
    assert (T.DOMAIN, "contoso") in result and (T.ACCOUNT, "petrov") in result
    assert T.ACCOUNT not in {type_ for type_, _ in found(r"вход ru\petrov, папка reports\summary", ctx)}
    dictionary = DetectContext(Settings(always=(DictEntry(T.DOMAIN, "fabrikam.local"),)))
    assert (T.ACCOUNT, "petrov") in found(r"вход fabrikam\petrov", dictionary)


def test_netbios_name_of_a_domain_from_the_same_text():
    state = ChatState(chat_id="netbios", net_key=bytes(32))
    sanitized = sanitize(state, r"Сайт contoso.ru, вход contoso\petrov", Settings()).sanitized
    assert "petrov" not in sanitized and "contoso" not in sanitized


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


def test_domain_login_before_an_escaped_line_break_in_json():
    """Приёмка 5В: вывод команды внутри строки JSON (Codex в «code mode» отдаёт результат exec так) — перевод строки
    записан знаками «\\r\\n», обратная косая между доменом и входом удвоена. Экранирование после входа — не продолжение
    пути: учётная запись скрывается. «\\\\» после входа — по-прежнему путь."""
    text = r'{"output": "[database]\r\nhost = srv-db01\r\nuser = CONTOSO\\ivanov\r\n\r\n[report]\r\n"}'
    assert (T.DOMAIN, "CONTOSO") in found(text) and accounts(text) == {"ivanov"}
    assert accounts(r'"user": "CONTOSO\\ivanov\n"') == {"ivanov"}
    assert accounts(r'"path": "CONTOSO\\ivanov\\Desktop"') == set()


def test_ipv6_address_followed_by_a_colon():
    assert (T.IP, "2a00:1450:4010::65") in found("Адрес 2a00:1450:4010::65: не отвечает")


@pytest.mark.parametrize(
    "text, address",
    [
        ("Source:f54a:d0a2:e874:66d7:ad66:a1be:9367:6a02.", "f54a:d0a2:e874:66d7:ad66:a1be:9367:6a02"),
        ("IPv6:2a00:1450:4010::65", "2a00:1450:4010::65"),
        ("src:[2a00:1450:4010::65]:443", "2a00:1450:4010::65"),
        ("Адрес:2a00:1450:4010::65:", "2a00:1450:4010::65"),
    ],
)
def test_ipv6_right_after_a_label_and_a_colon(text, address):
    """FINDINGS P3 «Detection: valid numbers in spaced notations are missed on the open sets»: полный адрес IPv6
    сразу после «Source:» не находился — двоеточие перед адресом считалось частью другой записи."""
    assert found(text) == {(T.IP, address)}


def test_colon_chains_after_a_label_are_not_addresses():
    assert values("Время:12:30:45, MAC:00:1A:2B:3C:4D:5E, ключ:1:2:3:4:5:6:7:8:9, ab:cd:ef:1:2:3:4:5:6") == set()


def test_ipv6_after_a_label_is_masked_and_restored():
    state = ChatState(chat_id="ipv6", net_key=bytes(32))
    text = "Source:f54a:d0a2:e874:66d7:ad66:a1be:9367:6a02."
    result = sanitize(state, text, Settings())
    assert "f54a" not in result.sanitized
    assert restore(state, result.sanitized, Settings()).text == text


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


@pytest.mark.parametrize(
    "text, name",
    [
        (r"C:\Users\Dan O'Brien\Desktop", "Dan O'Brien"),
        (r"C:\Users\Il'ya Petrov\Desktop", "Il'ya Petrov"),
        ("C:\\Users\\Dan O\u2019Brien\\Desktop", "Dan O\u2019Brien"),
        (r"'C:\Users\Dan O'Brien'", "Dan O'Brien"),
        (r"C:\Users\o'brien\Desktop", "o'brien"),
        ("'/home/ivanov'", "ivanov"),
        ("\u2018/home/ivan petrov\u2019", "ivan petrov"),
    ],
)
def test_apostrophe_inside_a_profile_name_and_a_quote_after_it(text, name):
    """FINDINGS P3 «Profile names with apostrophes are split»: апостроф внутри слова — часть имени,
    кавычка после имени — нет."""
    assert accounts(text) == {name}


def test_profile_name_with_an_apostrophe_followed_by_prose_is_one_word():
    assert accounts(r"профиль C:\Users\Dan O'Brien лежит на диске") == {"Dan"}


@pytest.mark.parametrize("domain", ["SA", "APP", "USER", "GIT"])
def test_domain_login_is_found_whatever_the_domain_name(domain):
    r"""Обзор партии P1: общий список стандартных учётных записей прятал «SA\petrov»."""
    assert accounts(f"учётка {domain}\\petrov") == {"petrov"}


@pytest.mark.parametrize(
    "text", ['{"msg": "Backup DONE\\\\n"}', r"Backup DONE\n", r"ERROR\t", r"FAILED\\r", r'"ID\d+"', r"CONTOSO\i"],
)
def test_one_letter_after_a_backslash_is_not_a_login(text):
    """FINDINGS P2 «Detection: false SECRET, PHONE, CARD and login hits that damage code and lists»: «DONE\\n»
    становился учётной записью «n», и потом каждое «n» в тексте заменялось."""
    assert values(text) == set()
    ctx = DetectContext(Settings(), known=(("contoso", T.DOMAIN),))
    assert T.ACCOUNT not in {type_ for type_, _ in found(r"вход contoso\n", ctx)}


@pytest.mark.parametrize(
    "text",
    [
        r"reg query HKLM\Software /s", r"reg add HKCU\Environment /v X /d 1", r"reg query HKCR\Directory",
        r"reg load HKU\S-1-5-18 ntuser.dat", r"reg query HKCC\System", r"reg query hklm\software",
        r"reg query HKEY_LOCAL_MACHINE\SOFTWARE /s", r"Get-ItemProperty HKLM:\Software",
    ],
)
def test_registry_hive_is_not_a_domain(text):
    r"""FINDINGS «Small gaps left by the findings batch of 15.10»: «HKLM\Software» давал домен HKLM и вход Software."""
    assert values(text) == set()


def test_domain_login_next_to_a_registry_path_is_still_found():
    assert found(r"reg query HKLM\Software /s под CORP\ivanov") == {(T.DOMAIN, "CORP"), (T.ACCOUNT, "ivanov")}


def test_short_login_after_a_domain_is_still_found():
    assert accounts(r"вход CONTOSO\ab, CONTOSO\nikolaev, ERROR\tester") == {"ab", "nikolaev", "tester"}


@pytest.mark.parametrize("closer", ["»", "”", "**", "}", "…"])
def test_host_after_a_url_login_is_found_before_any_closer(closer):
    text = f"«ssh://ivanov@srv-db01.corp.contoso.ru{closer} дальше"
    assert (T.HOST, "srv-db01.corp.contoso.ru") in found(text), text


def test_name_under_an_issued_surrogate_domain_is_found():
    """FINDINGS P2 «Detection: a real host name under an issued surrogate domain is not found»."""
    ctx = DetectContext(Settings(), issued_domains=frozenset({"domain-1.example"}))
    for text in (
        "узел srv-db02.domain-1.example.", "https://SRV-DB02.DOMAIN-1.EXAMPLE/app", r"\\srv-db02.domain-1.example\c$",
    ):
        assert {type_ for type_, _ in found(text, ctx)} == {T.HOST}, text
    assert values("узел srv-db02.domain-1.example") == set()        # подмену не выдавали: имя IANA
    assert values("узел srv-db02.domain-2.example, домен domain-1.example", ctx) == set()


LABELLED = DetectContext(Settings(), issued_domains=frozenset({"domain-1.example", "<org_1>"}))


@pytest.mark.parametrize("text, names", [
    ("узел <TERM_1>.fabrikam.ru.", {"fabrikam.ru"}),
    ("узел [[TERM_1]].corp.fabrikam.ru", {"corp.fabrikam.ru"}),
    ("узел srv-db02.<TERM_1>.domain-1.example", {"srv-db02"}),
    ("узел <TERM_1>.corp.domain-1.example", {"corp.domain-1.example"}),
    ("узел www.<TERM_1>.domain-1.example", set()),
    ("узел srv-db02.<ORG_1>", {"srv-db02"}),
    ("узел srv-db02.host-1.<ORG_1>", {"srv-db02.host-1"}),
], ids=["domain-after", "square", "part-before", "part-between", "generic-before", "label-domain", "name-before"])
def test_name_next_to_a_label_part_is_found_around_it(text, names):
    """Обзор, Minor 8: часть имени бывает меткой (5.7, шаг 4). Рядом с ней находятся части между метками, сама метка
    во фрагмент не входит; выданную замену в них отрежет конвейер (5.10). <org_1> — метка, выданная домену в имени
    (host-1.<ORG_1>)."""
    assert found(text, LABELLED) == {(T.HOST, name) for name in names}


@pytest.mark.parametrize("text", [
    "файл <PERSON_1>.docx", "отчёт.<PERSON_1>.pdf", "сайт <ORG_1>.ru", "<TERM_1>.example.com", "звонил <PERSON_1>.Затем",
    "узел srv-db02.<TERM_1>.domain-2.example", "узел srv-db02.<ORG_2>", "x.<PERSON_1>.Net", "метка <TERM_1>",
], ids=["file", "file-parts", "bare-suffix", "well-known", "sentence", "not-issued", "other-label", "code", "bare"])
def test_label_with_a_dot_next_to_something_else_is_not_a_name(text):
    assert found(text, LABELLED) == set()


@pytest.mark.parametrize("text, expected", [
    (r"RewriteCond %{HTTP_HOST} ^www\.contoso\.ru$", {(T.HOST, r"www\.contoso\.ru")}),
    (r"server_name ~^srv01\.contoso\.ru$;", {(T.HOST, r"srv01\.contoso\.ru")}),
    (r"server_name ~^(.+)\.corp\.contoso\.local$;", {(T.HOST, r"corp\.contoso\.local")}),
    (r"grep -E '.*\.contoso\.ru' -", {(T.DOMAIN, r"contoso\.ru")}),
    (r"Select-String '\bportal\.contoso\.ru\b'", {(T.HOST, r"portal\.contoso\.ru")}),
    (r'if address :regex "from" "@contoso\.ru$"', {(T.DOMAIN, r"contoso\.ru")}),
    (r"^srv01\.contoso.ru$", {(T.HOST, r"srv01\.contoso.ru")}),
], ids=["rewrite", "nginx", "nginx-capture", "grep-any", "word-bounds", "sieve", "both-separators"])
def test_name_written_with_escaped_dots_is_found(text, expected):
    """Наблюдение раунда 3 имён узлов, P1: имя в регулярном выражении, шаблоне grep, настройке nginx пишут через «\\.», и
    слой 3 его не находил — настоящий домен уходил в облако. «\\.» — разделитель частей, как точка, с теми же правилами;
    цепочка начинается и после «\\.» за знаком выражения («.*\\.», «(.+)\\.»), и между «\\b» и «\\b»."""
    assert found(text) == expected


@pytest.mark.parametrize("text, expected", [
    (r"C:\Users\ivanov\.ssh\config", {"ivanov"}),
    (r"C:\Users\ivanov\.android\avd и C:\Users\bob\.local\bin", {"ivanov", "bob"}),
    (r'"C:\\Users\\ivanov\\.aws\\config"', {"ivanov"}),
    (r"\\fs01\share\.azure\x", {"fs01"}),
    (r"System\.Net\.Http, re\.search\(x\), README\.md, 1\.2\.3\.dev, $obj\.host\.ru", set()),
    (r"^www\.example\.com$ и ^login\.microsoftonline\.com$", set()),
], ids=["dot-folder", "folders-with-suffixes", "json-path", "share", "code", "well-known"])
def test_backslash_before_a_dot_elsewhere_is_not_a_name_separator(text, expected):
    """Та же находка с другой стороны: «\\» перед частью — разделитель пути Windows, и папка на точку в профиле
    («.android», «.local», «.aws» — суффиксы из списка) именем не становится; код, файлы, общеизвестные и
    зарезервированные имена через «\\.» остаются, как через точку."""
    assert values(text) == expected


@pytest.mark.parametrize("text, expected", [
    ("SSL: *.contoso.ru, *.corp.contoso.local", {(T.DOMAIN, "contoso.ru"), (T.HOST, "corp.contoso.local")}),
    ("Set-Cookie: sid=1; Domain=.contoso.ru; Path=/", {(T.DOMAIN, "contoso.ru")}),
    ("no_proxy=localhost,.contoso.ru,.corp.local", {(T.DOMAIN, "contoso.ru"), (T.DOMAIN, "corp.local")}),
    ('все адреса @contoso.ru и "@mail.contoso.ru"', {(T.DOMAIN, "contoso.ru"), (T.HOST, "mail.contoso.ru")}),
    ("[domain_realm]\n .contoso.local = CONTOSO.LOCAL", {(T.DOMAIN, "contoso.local"), (T.DOMAIN, "CONTOSO.LOCAL")}),
    ("url: https://${env}.contoso.ru/, ^(www|mail).contoso.ru$", {(T.DOMAIN, "contoso.ru")}),
    ("cookie .env.contoso.ru и *.env.contoso.ru", {(T.HOST, "env.contoso.ru")}),
], ids=["wildcard", "cookie", "no-proxy", "mail-routing", "kerberos", "template-and-regex", "env-host"])
def test_name_after_a_leading_dot_star_or_at_is_found(text, expected):
    """Второе ревью, P1: слой 3 не начинал имя после «.» и «@» — «*.contoso.ru» (сертификат, DNS), «domain=.contoso.ru»
    (cookie), «no_proxy=.contoso.ru,.corp.local», «@contoso.ru» (маршрутизация почты) уходили в облако. Имя начинается
    после точки за знаком, который не часть имени, и после «@» без имени входа; ведущие «.», «*.», «@» во фрагмент не
    входят. Правила — те же, что у любого имени с точкой."""
    assert found(text) == expected


@pytest.mark.parametrize("text", [
    ".gitignore, *.py, .NET, *.tar.gz, *.min.js, *.d.ts",
    "cp .env.example .env.local && cat .env.development.local .env.dev .env.ci",
    "файлы .zshrc.local, .gitconfig.local, .tmux.conf.local и ^\\.env\\.local$",
    "~/.contoso.ru, ./.env.local, C:\\proj\\.zshrc.local, /etc/.corp.local",
    "Ну...ru, ну и...Всё.ок",
    "@media screen and (max-width: 600px) {} @Override public void run() @app.get('/') user@ и @import url(a.css)",
    "obj?.data.id, foo().then.catch",
], ids=["files", "dotenv", "dotfiles", "paths", "ellipsis", "code-at", "code-chains"])
def test_leading_dot_or_at_before_a_file_or_code_is_not_a_name(text):
    """Та же находка с другой стороны: файл на точку («.env.local», «.zshrc.local» — первая часть — имя такого файла, за
    ней одна часть или «…local»), точка после разделителя пути, многоточие, «@» в CSS и Java, код остаются."""
    assert values(text) == set()


@pytest.mark.parametrize("text, expected", [
    (r'{"host_regex": "^www\\.contoso\\.ru$"}', {(T.HOST, r"www\\.contoso\\.ru")}),
    (r'Pattern.compile("\\bportal\\.contoso\\.ru\\b")', {(T.HOST, r"portal\\.contoso\\.ru")}),
    (r'{"pattern": ".*\\.corp\\.contoso\\.local", "label": "<TERM_1>\\.fabrikam\\.ru"}',
     {(T.HOST, r"corp\\.contoso\\.local"), (T.HOST, r"fabrikam\\.ru")}),
    (r'{"allow": "^10\\.1\\.2\\.35$"}', {(T.IP, r"10\\.1\\.2\\.35")}),
], ids=["json", "java-word-bounds", "after-expression-and-label", "address"])
def test_name_and_address_in_a_regex_inside_a_string_literal_are_found(text, expected):
    """Второе ревью, P3: регулярное выражение внутри строки JSON, Java, C#, Python пишут через «\\\\.» — после раскрытия
    строки это «\\.». Такое имя и адрес уходили в облако, известные — тоже. «\\\\.» — разделитель, как «\\.», с теми же
    правилами; цепочка не начинается после «\\», поэтому путь Windows в JSON остаётся путём."""
    ctx = DetectContext(Settings(), issued_domains=frozenset({"<term_1>"}))
    assert found(text, ctx) == expected


@pytest.mark.parametrize("text, expected", [
    (r'{"path": "C:\\Users\\ivanov\\.android\\avd", "share": "\\\\fs01\\data\\.azure"}', {"ivanov", "fs01"}),
    (r'{"cfg": "C:\\Users\\Public\\.aws\\credentials", "bin": "node_modules\\.bin", "dir": "C:\\host\\.local"}', set()),
    (r'"contoso\\\\.ru", "10\\\\.1\\\\.2\\\\.35", "System\\.Net\\.Http"', set()),
], ids=["windows-paths", "dot-folders", "escaped-backslashes-and-code"])
def test_backslashes_in_json_paths_are_not_name_separators(text, expected):
    """Та же находка с другой стороны: путь Windows в JSON («C:\\\\Users\\\\ivanov\\\\.android») — путь, папки на точку —
    не имена; «\\\\\\\\.» (в выражении — обратная косая и любой знак) — не разделитель; код остаётся кодом."""
    assert values(text) == expected


def test_name_with_escaped_dots_under_an_issued_domain_or_next_to_a_label_is_found():
    ctx = DetectContext(Settings(), issued_domains=frozenset({"domain-1.example"}))
    assert found(r"^srv-db02\.domain-1\.example$", ctx) == {(T.HOST, r"srv-db02\.domain-1\.example")}
    assert values(r"^srv-db02\.<TERM_1>\.domain-1\.example$", LABELLED) == {"srv-db02"}
    assert values(r"^<TERM_1>\.fabrikam\.ru$", LABELLED) == {r"fabrikam\.ru"}
    assert values(r"<PERSON_1>\.docx и ^www\.<TERM_1>\.domain-1\.example$", LABELLED) == set()


def test_mixed_case_name_with_an_issued_replacement_inside_is_a_name():
    """Наблюдение раунда 3 имён узлов, P3: в «Petrov.host-1.fabrikam.ru» смешанный регистр («Petrov») делал имя похожим
    на код (System.Net), и fabrikam.ru оставался открытым. Цепочка с выданной заменой внутри — имя, признаки кода к ней не
    применяются; суффикс из списка нужен по-прежнему. Без выданной замены — как прежде."""
    ctx = DetectContext(Settings(), issued_domains=frozenset({"domain-1.example"}), issued_names=frozenset({"host-1"}))
    assert values("узел Petrov.host-1.fabrikam.ru", ctx) == {"Petrov.host-1.fabrikam.ru"}
    assert values(r"^Petrov\.HOST-1\.Fabrikam\.ru$", ctx) == {r"Petrov\.HOST-1\.Fabrikam\.ru"}
    assert values("узел Ivanov.domain-1.example.Fabrikam.ru", ctx) == {"Ivanov.domain-1.example.Fabrikam.ru"}
    assert values("System.Net.Http, re.search(x), Petrov.host-2.fabrikam.ru, Petrov.host-1.Затем", ctx) == set()
    assert values("узел <ORG_1>.Fabrikam.ru", LABELLED) == {"Fabrikam.ru"}       # после метки доменного имени
    assert values("x.<PERSON_1>.System.Net", LABELLED) == set()


def test_real_host_typed_under_an_issued_domain_is_masked_and_restored():
    state = ChatState(chat_id="issued", net_key=bytes(32))
    assert sanitize(state, "Домен contoso.ru", Settings()).sanitized == "Домен domain-1.example"
    result = sanitize(state, "Узел srv-db02.domain-1.example, почта mail.domain-1.example", Settings())
    assert result.sanitized == "Узел host-1.domain-1.example, почта mail.domain-1.example"
    assert restore(state, result.sanitized, Settings()).text == "Узел srv-db02.contoso.ru, почта mail.contoso.ru"
    again = "Узел host-1.domain-1.example"          # выданная часть перед подменой — та же подмена
    assert sanitize(state, again, Settings()).sanitized == again
    assert len(state.entities) == 2
