import json
from pathlib import Path

import pytest

from cleaner.core.detect import infra
from cleaner.core.detect.base import DetectContext
from cleaner.core.entities import hostmap
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import restore
from cleaner.core.types import ChatRule, ChatState, DictEntry, Policy, Settings, default_policies
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


@pytest.mark.parametrize(
    "text, hosts",
    [
        ('Invoke-Command -ComputerName "SRV-APP01" -ScriptBlock { hostname }', {"SRV-APP01"}),
        ("Get-Service -ComputerName:BUH-PC07", {"BUH-PC07"}),
        ('Get-ADUser -Server "DC01" -Identity x', {"DC01"}),
        ('schtasks /query /S "BUH-PC07"', {"BUH-PC07"}),
        ("Restart-Computer -ComputerName SRV-APP01,SRV-APP02,BUH-PC07 -Force", {"SRV-APP01", "SRV-APP02", "BUH-PC07"}),
        ("Restart-Computer -ComputerName 'SRV-APP01', \"BUH-PC07\" -Force", {"SRV-APP01", "BUH-PC07"}),
        ("Invoke-Command -ComputerName WS-0142, затем перезапустите", {"WS-0142"}),
        (r'Get-ChildItem -Server "C:\Temp"', set()),
    ],
)
def test_quoted_colon_and_listed_computer_names(text, hosts):
    """FINDINGS P2 «значения -ComputerName, -Server, /S в кавычках, через двоеточие и списком»: каждый узел — фрагмент.
    Слово через запятую с пробелом без кавычек — продолжение текста, а не узел списка."""
    assert {value for type_, value in found(text) if type_ is T.HOST} == hosts


@pytest.mark.parametrize(
    "text, hosts",
    [
        (r"psexec -accepteula \\srv01 cmd /c ipconfig", {"srv01"}), (r"psexec \\buh-pc07,buh-pc08 -s cmd", {"buh-pc07", "buh-pc08"}),
        (r"net view \\FS01", {"FS01"}), (r"sc.exe \\srv-app01 query Spooler", {"srv-app01"}),
        (r"shutdown /r /m \\ws-0142 /t 0", {"ws-0142"}), ("mstsc /v:srv-term01:3389", {"srv-term01"}),
        ("Nov  9 10:01:02 srv01 sshd[812]: Accepted publickey", {"srv01"}),
        ("2026-11-09T10:01:02.123+03:00 gw-msk kernel: eth0 up", {"gw-msk"}),
        ("Nov 9 10:01:02 localhost CRON[44]: session opened", set()),
    ],
)
def test_dotless_host_in_a_command_or_syslog_field(text, hosts):
    """IDEAS P3 «узлы без точек по структуре»: команда или поле требуют узел, и слово без точек — имя узла."""
    assert {value for type_, value in found(text) if type_ is T.HOST} == hosts


@pytest.mark.parametrize(
    "text",
    [r'"(\\w+) (\\d+)"', r"a \\ b \\hline", r"\\srv01 недоступен", "Встреча Nov 9 10:01 у Иванова", r"see \\srv01 now"],
)
def test_dotless_name_outside_those_commands_is_not_a_host(text):
    assert {value for type_, value in found(text) if type_ is T.HOST} == set()


@pytest.mark.parametrize(
    "text",
    [
        "2026-11-09T10:01:02Z INFO main.py: started", "2026-11-09T10:01:02.123+03:00 ERROR app.service: failed",
        "2026-11-09T10:01:02Z warning kernel: low memory", "Nov  9 10:01:02 Debug app[7]: x",
        "2026-11-09T10:01:02Z CRIT sshd[1]: y", "2026-11-09T10:01:02Z Fatal worker: z",
    ],
)
def test_log_level_after_a_timestamp_is_not_a_host(text):
    """Ревью: в строке журнала с меткой времени ISO уровень («INFO», «ERROR») занимал место поля узла и становился
    DOMAIN/HOST во всём чате."""
    assert found(text) == set()


def test_loc_is_an_internal_suffix_but_a_pandas_indexer_is_code():
    """IDEAS P3 «суффикс loc»: «.loc» — частый суффикс доменов AD; «df.loc[…]» — индексатор pandas (2287 строк из 2461 с
    «.loc» в выборке кода site-packages)."""
    assert found("контроллер dc01.romashka.loc, домен romashka.loc") == {
        (T.HOST, "dc01.romashka.loc"), (T.DOMAIN, "romashka.loc"),
    }
    assert found('df.loc[mask, "total"] = 0') == set()
    assert (T.HOST, "mail.romashka.loc") in found("connect from mail.romashka.loc[10.1.2.3]")


def test_added_internal_suffix_marks_a_name():
    assert values("узел srv01.romashka.lcl") == set()
    try:
        hostmap.set_extra_suffixes(("lcl",))
        assert found("узел srv01.romashka.lcl") == {(T.HOST, "srv01.romashka.lcl")}
    finally:
        hostmap.set_extra_suffixes(())
    assert values("узел srv01.romashka.lcl") == set()


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


TENANT_NAMES = (
    "romashka-backup.blob.core.windows.net",
    "romashka-sql.database.windows.net",
    "romashka-kv.vault.azure.net",
    "romashka-bucket.s3.amazonaws.com",
    "romashka.visualstudio.com",
    "123456789012.dkr.ecr.eu-west-1.amazonaws.com",
    "romashka.storage.googleapis.com",
    "romashka.github.io",
    "romashka.gitlab.io",
    "romashka.sharepoint.com",
    "romashka-my.sharepoint.com",
    "romashka.atlassian.net",
    "romashka.slack.com",
    "romashka.okta.com",
    "ec2-203-0-113-10.compute-1.amazonaws.com",
    "ec2-198-51-100-7.eu-west-1.compute.amazonaws.com",
    "123456789012.signin.aws.amazon.com",
    "my-nlb-0123456789abcdef.elb.eu-west-1.amazonaws.com",
    "romashka-redis.abc123.0001.euw1.cache.amazonaws.com",
    "romashka-dwh.abc123.eu-west-1.redshift.amazonaws.com",
    "romashka-docdb.cluster-abc123.eu-west-1.docdb.amazonaws.com",
    "b-1.romashka-kafka.abc123.c2.kafka.eu-west-1.amazonaws.com",
    "fs-0123abcd.efs.eu-west-1.amazonaws.com",
    "clustercfg.romashka.abc123.memorydb.eu-west-1.amazonaws.com",
    "vpce-0123abcd-ef01.vpce-svc-0123.eu-west-1.vpce.amazonaws.com",
    "romashka.westeurope.kusto.windows.net",
    "romashka.mongo.cosmos.azure.com",
    "romashka.table.cosmos.azure.com",
    "romashka.mariadb.database.azure.com",
    "romashka.managedhsm.azure.net",
    "romashka-topic.westeurope-1.eventgrid.azure.net",
    "romashka.westeurope.batch.azure.com",
    "romashka.services.ai.azure.com",
    # Имя ресурса вида «xx-слово-1» — не регион AWS (регрессия 7f7b57c: такие имена уходили открытыми).
    "my-bucket-1.s3.amazonaws.com",
    "hr-files-2.s3.eu-west-1.amazonaws.com",
    "kv-romashka-1.vault.azure.net",
    "db-crm-1.database.windows.net",
    "my-team-1.atlassian.net",
    "hr-portal-2.sharepoint.com",
    # Служебное слово вендора между учётной записью и суффиксом — часть суффикса, а не метка арендатора.
    "romashkasql.privatelink.database.windows.net",
    "romashkabackup.privatelink.blob.core.windows.net",
    "romashka-redis-abc123.serverless.euw1.cache.amazonaws.com",
    "romashka.abc123.clustercfg.euw1.cache.amazonaws.com",
    "romashka.enterprise.slack.com",
    # Key Vault в CNAME и nslookup, Purview, Data Factory, Neptune, Amazon MQ.
    "romashka-kv.privatelink.vaultcore.azure.net",
    "romashka.purview.azure.com",
    "romashka.westeurope.datafactory.azure.net",
    "x.cluster-abc123.eu-west-1.neptune.amazonaws.com",
    "b-1234abcd.mq.eu-west-1.amazonaws.com",
)
SERVICE_NAMES = (
    "admin.atlassian.com", "id.atlassian.com", "login.microsoftonline.com", "update.microsoft.com", "management.azure.com", "s3.amazonaws.com",
    "storage.googleapis.com", "dev.azure.com", "www.googleapis.com", "fonts.googleapis.com",
    "raw.githubusercontent.com", "login.live.com", "graph.microsoft.com", "api.github.com", "pypi.org", "docker.io",
    "registry-1.docker.io", "lambda.us-east-1.amazonaws.com", "s3.eu-west-1.amazonaws.com",
    "dkr.ecr.eu-west-1.amazonaws.com", "code.visualstudio.com", "app.vssps.visualstudio.com", "login.windows.net",
    "blob.core.windows.net", "database.windows.net", "vault.azure.net",
    # Регион AWS и служебная часть перед суффиксом арендатора — не арендатор.
    "docs.aws.amazon.com", "console.aws.amazon.com", "eu-west-1.signin.aws.amazon.com",
    "api.openai.azure.com", "help.kusto.windows.net",
    # Публичные реестры пакетов и CDN — того же рода, что pypi.org и docker.io; в частном разделе их доменов нет.
    "files.pythonhosted.org", "registry.npmjs.org", "ghcr.io", "aka.ms", "cdn.jsdelivr.net",
    # Многоарендные SaaS: сам домен вендора, служебная часть перед ним и служба из «!имя» встроенного списка.
    "github.io", "www.github.io", "sharepoint.com", "www.sharepoint.com", "atlassian.net", "api.slack.com",
    "app.slack.com", "hooks.slack.com", "login.okta.com",
    # Голые зоны Private Link и служебные суффиксы без метки арендатора.
    "privatelink.blob.core.windows.net", "privatelink.database.windows.net", "privatelink.openai.azure.com",
    "serverless.euw1.cache.amazonaws.com", "clustercfg.euw1.cache.amazonaws.com", "enterprise.slack.com",
    "privatelink.vaultcore.azure.net", "purview.azure.com", "mq.eu-west-1.amazonaws.com",
    # Служебные узлы Slack (API и веб-сокеты клиента).
    "edgeapi.slack.com", "wss-primary.slack.com", "wss-backup.slack.com", "wss-mobile.slack.com",
)


@pytest.mark.parametrize("value", TENANT_NAMES)
def test_tenant_resource_under_a_well_known_domain_is_hidden(value):
    """Находка 12.11: левую часть имени под многоарендным облачным доменом выбирает организация — учётная запись
    хранилища, сервер Azure SQL, бакет, номер учётной записи AWS. Суффикс арендатора — из частного раздела списка
    публичных суффиксов или встроенного списка (data/tenant_suffixes.txt). Публичное имя EC2 содержит адрес сервера:
    «ec2-…compute-1.amazonaws.com» в частном разделе целиком суффикс, поэтому «compute-1.amazonaws.com» — во встроенном."""
    assert not infra.well_known(value, CTX)
    assert values(f"Ресурс {value} недоступен") == {value}


@pytest.mark.parametrize("value", SERVICE_NAMES)
def test_vendor_service_names_stay(value):
    """Служебные имена вендора без метки арендатора общеизвестны: «googleapis.com» и «githubusercontent.com» сами стоят в
    частном разделе списка, но «www» и «raw» перед ними — не арендаторы."""
    assert infra.well_known(value, CTX)
    assert values(f"Ресурс {value} недоступен") == set()


def test_slack_service_node_is_not_searched():
    """«edgeapi» в «edgeapi.slack.com» был меткой арендатора и становился искомым: слово скрывалось во всём чате."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    text = "Клиент ходит на edgeapi.slack.com и wss-primary.slack.com; edgeapi отвечает 429"
    assert sanitize(state, text, Settings()).sanitized == text


@pytest.mark.parametrize("text, login", [
    (
        "Файл https://romashka-my.sharepoint.com/personal/ivanov_romashka_onmicrosoft_com/Documents/x.docx недоступен",
        "ivanov_romashka_onmicrosoft_com",
    ),
    ("Get-PnPFolder -Url /personal/i_petrov_romashka_ru/Documents", "i_petrov_romashka_ru"),
])
def test_onedrive_personal_site_segment_is_an_account(text, login):
    """Находка 12.11: сегмент личного сайта OneDrive — учётная запись ivanov@romashka.onmicrosoft.com, в которой «@» и «.»
    заменены на «_», — уходил открытым. Теперь он — учётная запись и восстанавливается как написан."""
    assert (T.ACCOUNT, login) in found(text)
    state = ChatState(chat_id="onedrive", net_key=bytes(32))
    sanitized = sanitize(state, text, Settings()).sanitized
    assert login not in sanitized and "romashka" not in sanitized
    assert restore(state, sanitized, Settings()).text == text


def test_personal_folder_is_not_an_account():
    assert values("Папки personal/notes, /data/personal/my_notes и personal/2026_q3_plan") == set()


def test_never_listed_tenant_resource_stays():
    ctx = DetectContext(Settings(never=frozenset({"romashka-sql.database.windows.net"})))
    assert values("Сервер romashka-sql.database.windows.net и romashka-kv.vault.azure.net", ctx) == {
        "romashka-kv.vault.azure.net"
    }


def test_azure_sql_connection_string_hides_the_server_and_restores():
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    text = (
        "Server=tcp:romashka-sql.database.windows.net,1433;Initial Catalog=crm;Encrypt=True;"
        "Connection Timeout=30; вход через login.microsoftonline.com"
    )
    sanitized = sanitize(state, text, Settings()).sanitized
    assert "romashka" not in sanitized and "login.microsoftonline.com" in sanitized
    assert restore(state, sanitized, Settings()).text == text


@pytest.mark.parametrize("tenant, services", [
    (
        "Бакет romashka-bucket.s3.amazonaws.com",
        "Токен из https://sts.amazonaws.com, роли iam.amazonaws.com, узлы ec2.eu-west-1.amazonaws.com",
    ),
    (
        "Модель romashka-oai.openai.azure.com, вход login.windows.net, EndpointSuffix=core.windows.net",
        "Откройте portal.azure.com, management.azure.com и dev.azure.com/org; вход login.windows.net",
    ),
    (
        "Портал romashka.sharepoint.com, сайт romashka.github.io, задачи romashka.atlassian.net",
        "Вход через login.okta.com, вебхук hooks.slack.com, сайт sharepoint.com",
    ),
])
def test_vendor_service_names_stay_after_a_tenant_name(tenant, services):
    """Находка 12.11: подмена имени арендатора делала облачный домен вендора («amazonaws.com», «windows.net») сущностью
    DOMAIN, и его служебные имена скрывались во всём чате, а при DOMAIN «блокировать» блокировали выдачу. Теперь у имени
    арендатора подменяются только его части, облачный суффикс остаётся как есть и сущностью не становится."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    settings = Settings(policies=default_policies() | {T.DOMAIN: Policy.BLOCK})
    first = sanitize(state, tenant, settings)
    assert "romashka" not in first.sanitized and first.deliverable
    assert "login.windows.net" not in tenant or "login.windows.net" in first.sanitized
    assert "core.windows.net" not in tenant or "EndpointSuffix=core.windows.net" in first.sanitized
    assert not [entity for entity in state.entities.values() if entity.type is T.DOMAIN]
    second = sanitize(state, services, settings)
    assert second.sanitized == services and second.deliverable


@pytest.mark.parametrize("value, fake", [
    ("romashka-sql.database.windows.net", "host-1.database.windows.net"),
    ("romashka-backup.blob.core.windows.net", "host-1.blob.core.windows.net"),
    ("romashka-kv.vault.azure.net", "host-1.vault.azure.net"),
    ("romashka-bucket.s3.amazonaws.com", "host-1.s3.amazonaws.com"),
    ("123456789012.dkr.ecr.eu-west-1.amazonaws.com", "host-1.dkr.ecr.eu-west-1.amazonaws.com"),
    ("app.romashka.visualstudio.com", "host-1.sub-2.visualstudio.com"),
    ("www.romashka.visualstudio.com", "www.host-1.visualstudio.com"),
    ("romashka.github.io", "host-1.github.io"),
    ("romashka-my.sharepoint.com", "host-1.sharepoint.com"),
    ("romashka.slack.com", "host-1.slack.com"),
    ("romashkasql.privatelink.database.windows.net", "host-1.privatelink.database.windows.net"),
    ("romashka.abc123.clustercfg.euw1.cache.amazonaws.com", "host-1.sub-2.clustercfg.euw1.cache.amazonaws.com"),
    ("romashka.enterprise.slack.com", "host-1.enterprise.slack.com"),
])
def test_tenant_name_keeps_the_cloud_suffix(value, fake):
    """У имени арендатора подменяются метки арендатора и части слева от неё, суффикс арендатора остаётся: модель видит,
    что это Azure SQL, хранилище, Key Vault или бакет."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    assert sanitize(state, f"Ресурс {value} недоступен", Settings()).sanitized == f"Ресурс {fake} недоступен"


def test_saas_tenants_get_own_labels_under_the_open_vendor_domain():
    """Находка 12.11: домены SaaS вне списка общеизвестных скрывались целиком — «romashka.sharepoint.com» делал
    «sharepoint.com» сущностью DOMAIN, и любое имя под ним получало ту же фиктивную доменную часть: модель не видела, что
    это SharePoint. Теперь у каждого арендатора своя подмена метки, домен вендора открыт."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    text = "Портал romashka.sharepoint.com, личный romashka-my.sharepoint.com, партнёр contoso.sharepoint.com"
    sanitized = sanitize(state, text, Settings()).sanitized
    assert sanitized == "Портал host-1.sharepoint.com, личный host-2.sharepoint.com, партнёр host-3.sharepoint.com"
    assert not [entity for entity in state.entities.values() if entity.type is T.DOMAIN]
    assert restore(state, sanitized, Settings()).text == text


@pytest.mark.parametrize("rule, expected", [
    ("romashka-sql", "Сервер <TERM_1>.database.windows.net"),
    ("database", "Сервер <TERM_1>"),
    ("windows.net", "Сервер <TERM_1>"),
    ("database.windows.net", "Сервер <TERM_1>"),
])
def test_user_rule_on_a_tenant_name_part(rule, expected):
    """Правило на метке арендатора — правило на целой части имени (5.7, шаг 4): часть получает его метку. Суффикс
    арендатора подмены не получает, и правило на нём или его части имя поглощает, как правило не на целой части обычного
    имени. Раньше части сверялись с разбиением без арендатора: «database» и «windows.net» считались целыми частями, имя не
    поглощалось, а подмена оставляла суффикс как есть — значение правила уходило открытым."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    state.rules.append(ChatRule("mask", rule, T.TERM))
    text = "Сервер romashka-sql.database.windows.net"
    sanitized = sanitize(state, text, Settings()).sanitized
    assert sanitized == expected
    assert restore(state, sanitized, Settings()).text == text


@pytest.mark.parametrize("rule", ["windows.net", "database.windows.net"])
@pytest.mark.parametrize("type_", [T.DOMAIN, T.HOST])
def test_host_or_domain_rule_on_a_tenant_suffix_hides_the_suffix(rule, type_):
    """Правило «скрыть» типа HOST или DOMAIN на суффиксе арендатора или его части: раньше имя арендатора оставляло
    суффикс открытым («host-1.database.windows.net»), и значение правила в одном месте скрывалось, а в другом уходило.
    Теперь такое имя делится как обычное, и суффикс подменяется."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    state.rules.append(ChatRule("mask", rule, type_))
    text = "Вход login.windows.net и сервер romashka-sql.database.windows.net"
    sanitized = sanitize(state, text, Settings()).sanitized
    assert "windows.net" not in sanitized and "romashka" not in sanitized
    assert sanitized.endswith("сервер host-1.sub-2.domain-1.example")
    assert restore(state, sanitized, Settings()).text == text


def test_tenant_names_round_trip_in_any_writing():
    """Восстановление подмены имени арендатора — по выданной строке, как у прочих имён: заглавными, с точкой в конце, в
    адресе ссылки."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    text = (
        "Server=tcp:romashka-sql.database.windows.net,1433;Initial Catalog=crm;\n"
        "Файл https://romashka-backup.blob.core.windows.net/backups/db.bak"
    )
    sanitized = sanitize(state, text, Settings()).sanitized
    assert sanitized == (
        "Server=tcp:host-1.database.windows.net,1433;Initial Catalog=crm;\n"
        "Файл https://host-2.blob.core.windows.net/backups/db.bak"
    )
    assert restore(state, sanitized, Settings()).text == text
    answer = (
        "Проверьте HOST-1.DATABASE.WINDOWS.NET и host-1.database.windows.net. "
        "Скачайте [копию](https://host-2.blob.core.windows.net/backups/db.bak), сервер host-1."
    )
    assert restore(state, answer, Settings()).text == (
        "Проверьте ROMASHKA-SQL.DATABASE.WINDOWS.NET и romashka-sql.database.windows.net. "
        "Скачайте [копию](https://romashka-backup.blob.core.windows.net/backups/db.bak), сервер romashka-sql."
    )


@pytest.mark.parametrize("text", [
    "Копия https://romashkabackup.blob.core.windows.net/x, az storage blob list --account-name romashkabackup",
    "AccountName=romashkabackup;AccountKey=<SECRET>;EndpointSuffix=core.windows.net; хост romashkabackup.blob.core.windows.net",
    "Сервер romashkasql.database.windows.net; sqlcmd -S romashkasql",
])
def test_tenant_label_without_digits_is_searched(text):
    """Находка 12.11: часть имени становилась искомой, только если в ней цифра или дефис, а имена учётных записей хранилищ
    Azure и серверов SQL обычно строчные буквы — и уходили открытыми рядом с именем, даже в той же строке. Метка
    арендатора искома и без них."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    sanitized = sanitize(state, text, Settings()).sanitized
    assert "romashka" not in sanitized
    assert "EndpointSuffix=core.windows.net" in sanitized or "EndpointSuffix" not in text
    assert restore(state, sanitized, Settings()).text == text


@pytest.mark.parametrize("name, fake", [
    ("romashkasql.privatelink.database.windows.net", "host-1.privatelink.database.windows.net"),
    ("romashka-redis.serverless.euw1.cache.amazonaws.com", "host-1.serverless.euw1.cache.amazonaws.com"),
])
def test_vendor_word_before_the_suffix_is_not_the_tenant(name, fake):
    """Регрессия f899ed3: «privatelink» и «serverless» между учётной записью и суффиксом становились меткой арендатора —
    искомой, — а имя сервера оставалось открытым рядом («sqlcmd -S romashkasql»), и обычное слово «privatelink» в
    следующем тексте чата скрывалось. Теперь они — часть суффикса из встроенного списка."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    account = name.split(".")[0]
    text = f"Сервер {name}; sqlcmd -S {account}"
    sanitized = sanitize(state, text, Settings()).sanitized
    assert sanitized == f"Сервер {fake}; sqlcmd -S host-1"
    assert restore(state, sanitized, Settings()).text == text
    words = "Создайте privatelink для SQL и serverless-кэш"
    assert sanitize(state, words, Settings()).sanitized == words


def test_short_tenant_label_is_not_searched():
    """Короткая метка арендатора («test», «prod», «demo») — обычно слово: искомой она не становится, иначе после
    «test.blob.core.windows.net» скрывалось бы каждое «test» чата. Имя целиком скрывается."""
    state = ChatState(chat_id="tenant", net_key=bytes(32))
    assert sanitize(state, "Хранилище test.blob.core.windows.net", Settings()).sanitized == (
        "Хранилище host-1.blob.core.windows.net"
    )
    assert sanitize(state, "Запустите test и prod", Settings()).sanitized == "Запустите test и prod"


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


def test_domain_login_in_url_encoding():
    """FINDINGS P2 «DOMAIN\\login в URL-кодировке»: «%5C» — обратная косая в журнале веб-сервера и адресе возврата."""
    for text in ("GET /login?user=CONTOSO%5Civanov&next=/", "user=CONTOSO%5civanov"):
        result = found(text)
        assert (T.DOMAIN, "CONTOSO") in result and accounts(text) == {"ivanov"}, text
    assert accounts("path=CONTOSO%5Cshare%5Creport") == set()


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


def test_ipv6_with_an_embedded_ipv4_is_one_address():
    """FINDINGS P3 «IPv6 со встроенным IPv4»: «::ffff:127» становился адресом IPv6, а «.0.0.1» оставался рядом. Адрес IPv4
    в записи «::ffff:…» — тот же адрес: его сущность и подмена — как у адреса IPv4, петля остаётся открытой."""
    assert found("from ::ffff:127.0.0.1") == set()
    state = ChatState(chat_id="mapped", net_key=bytes(32))
    sanitized = sanitize(state, "from ::ffff:10.20.30.40, затем 10.20.30.40", Settings()).sanitized
    assert "10.20.30.40" not in sanitized
    mapped, _, plain = sanitized.removeprefix("from ::ffff:").partition(", затем ")
    assert mapped == plain
    sanitized = sanitize(state, "NAT64 64:ff9b::10.1.2.3 отвечает", Settings()).sanitized
    assert "ff9b" not in sanitized and "10.1.2.3" not in sanitized


def test_ipv4_mapped_ipv6_in_hex_is_an_address():
    """Ревью: пропуск «::ffff:» ради точечной записи пропускал и шестнадцатеричную «::ffff:a14:1e28» (10.20.30.40), которую
    правило IPv4 не находит, — адрес уходил открытым. Петля и документационные адреса в такой записи открыты, как у IPv4."""
    assert found("connect from ::ffff:a14:1e28 port 22") == {(T.IP, "::ffff:a14:1e28")}
    assert found("client [::ffff:0a14:1e28]:5432 refused") == {(T.IP, "::ffff:0a14:1e28")}
    assert found("from ::ffff:7f00:1 and ::ffff:c000:201") == set()
    state = ChatState(chat_id="mapped-hex", net_key=bytes(32))
    text = "connect from ::ffff:a14:1e28 port 22"
    result = sanitize(state, text, Settings())
    assert "a14:1e28" not in result.sanitized
    assert restore(state, result.sanitized, Settings()).text == text


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
    "dn",
    [r"CN=Ivanov\, Ivan,OU=Accounting,DC=contoso,DC=ru", r"CN=Ivanov\\, Ivan,OU=Accounting,DC=contoso,DC=ru"],
    ids=["rfc4514", "json"],
)
def test_dn_with_an_escaped_comma_is_one_fragment(dn):
    """FINDINGS P1 «LDAP-имя с экранированной запятой»: «CN=Фамилия\\, Имя» обычен в AD, и фамилия оставалась открытой."""
    assert found(f'объект "{dn}" найден') == {(T.DN, dn)}
    assert found("CN=a\\," * 5000) == set()     # без DC — не имя; откат линейный (сторож скорости — test_long_input)


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


def test_agent_service_domains_stay_open():
    """FINDINGS P3 28.10: адреса агентов в их системной части и описаниях инструментов общеизвестны."""
    for text in ("https://claude.ai/code", "https://docs.claude.com/en/docs/claude-code", "https://chatgpt.com/codex",
                 "https://opencode.ai/docs"):
        state = ChatState(chat_id="agents", net_key=bytes(32))
        assert sanitize(state, text, Settings()).sanitized == text


def test_placeholder_login_in_a_profile_path_is_not_an_account():
    """FINDINGS P3 29.10: логин-заглушка в примере пути (описание bash у OpenCode) — не учётная запись."""
    for text in ('mkdir "/Users/name/My Documents"', "/home/user/app", r"C:\Users\username\Desktop"):
        assert accounts(text) == set(), text
    assert accounts("/home/ivanov/app") == {"ivanov"}


@pytest.mark.parametrize(
    "text, login",
    [
        ("/c/Users/ivanov/AppData/Local/Temp", "ivanov"), ("cd /mnt/c/Users/ivanov", "ivanov"),
        ("ls /c/Users/i.petrov/Documents", "i.petrov"), ("/cygdrive/d/Users/ivanov/x", "ivanov"),
    ],
)
def test_profile_path_of_git_bash_msys_wsl_and_cygwin(text, login):
    """FINDINGS P2 «путь профиля в записи Git Bash, MSYS, WSL и Cygwin»: Git Bash — оболочка Claude Code на Windows."""
    assert accounts(text) == {login}
    assert accounts("https://contoso.example/a/users/ivanov") == set()


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    items = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    return [text for item in items for text in _strings(item)]


def test_claude_code_system_part_keeps_service_strings():
    """Запись настоящего хода Claude Code в режиме написаний: счётчик токенов не секрет, ссылки на claude.* открыты."""
    body = json.loads((Path(__file__).parent / "fixtures" / "agents" / "claude_code" / "turn2.json").read_text("utf-8"))
    state = ChatState(chat_id="claude-code", net_key=bytes(32))
    state.written = True
    sanitized = []
    for text in _strings([body["system"], body["messages"], body["tools"]]):
        result = sanitize(state, text, Settings())
        sanitized.append(result.sanitized)
        for span in result.spans:
            if state.entities[span.entity_id].type is T.SECRET:
                assert "tokens left" not in text[span.start:span.end], text[span.start:span.end]
    joined = "\n".join(sanitized)
    assert "<total_tokens>15000000 tokens left</total_tokens>" in joined
    for link in ("https://claude.com/claude-code", "claude.ai/code", "claude.ai/design", "claude.ai login"):
        assert link in joined, link
