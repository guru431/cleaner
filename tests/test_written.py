"""Режим написаний (спецификация 2026-10-28, раздел 11): в чате шлюза каждое написание — своя замена, и точное
восстановление возвращает строку посимвольно, как она была в тексте агента."""
import random

import pytest

from cleaner.core.pipeline import sanitize
from cleaner.core.restore import originals
from cleaner.core.types import ChatState, DictEntry, Policy, Settings, default_policies
from cleaner.core.types import EntityType as T

MASKED = default_policies() | {T.SECRET: Policy.MASK}
DICTIONARY = (DictEntry(T.TERM, "Заря-Восток", ("Zarya-Vostok",)),)

# Тексты проверки 28.10.2026: на нынешнем ядре разные написания восстанавливались первым встреченным.
SPELLINGS = {
    "email": "a ivan.petrov@contoso.ru b Ivan.Petrov@Contoso.RU",
    "email_encoded": "a ivan.petrov@contoso.ru b GET /?to=ivan.petrov%40contoso.ru c ivan.petrov%40Contoso.ru",
    "phone": "a +7 916 123-45-67 b 89161234567 c +7(916)1234567",
    "ipv4": "a 10.1.2.5 b 010.001.002.005",
    "ipv6": "a 2a00:1450:4010::65 b 2A00:1450:4010:0:0:0:0:65",
    "host": "ping SRV-DC01.corp.contoso.ru; ping srv-dc01; ping Srv-Dc01; ssh srv-dc01.CORP.contoso.ru",
    "realm": "realm CORP.CONTOSO.RU and corp.contoso.ru",
    "account": r"CONTOSO\ivanov_ii and contoso\Ivanov_II and C:\Users\ivanov_ii\x",
    "inn": "ИНН 7707083893 и ИНН 7707 083 893",
    "dictionary": "Проект Заря-Восток, он же Zarya-Vostok и ЗАРЯ-ВОСТОК",
}
# Уже точные и до режима написаний.
EXACT = {
    "secret": "password=Hunter2Hunter2",
    "sid": "SID S-1-5-21-1004336348-1177238915-682003330-1001",
    "dn": "CN=Ivanov,OU=Users,DC=corp,DC=contoso,DC=ru",
    "regex": r"^10\.1\.2\.5$",
    "mac": "00:1A:2B:3C:4D:5E и 00-1a-2b-3c-4d-5e",
    "url": "https://admin:S3cretPass@srv-web01.corp.contoso.ru/",
    "json": '{"user": "CONTOSO\\\\ivanov", "mail": "ivan.petrov@contoso.ru"}',
}


def written_state() -> ChatState:
    state = ChatState(chat_id="agent", net_key=bytes(range(32)))
    state.written = True
    return state


def masked(always: tuple[DictEntry, ...] = DICTIONARY) -> Settings:
    return Settings(always=always, policies=MASKED)


@pytest.mark.parametrize("text", [*SPELLINGS.values(), *EXACT.values()], ids=[*SPELLINGS, *EXACT])
def test_every_spelling_restores_exactly(text):
    settings = masked()
    state = written_state()
    sanitized = sanitize(state, text, settings).sanitized
    assert originals(state, settings, exact=True)(sanitized) == text
    plain = ChatState(chat_id="plain", net_key=bytes(range(32)))
    hidden = {text[span.start:span.end].lower() for span in sanitize(plain, text, settings).spans}
    assert hidden and not [value for value in hidden if value in sanitized.lower()]


def _cased(rnd: random.Random, value: str) -> str:
    return rnd.choice((value, value.lower(), value.upper(), value.title()))


def _piece(rnd: random.Random) -> str:
    """Кусок порождённого текста: значение какого-нибудь типа в своей записи или обычные слова, код, путь."""
    kind = rnd.randrange(16)
    if kind == 0:
        return _cased(rnd, rnd.choice(("ivan.petrov@contoso.ru", "a.sidorova@fabrikam.com")))
    if kind == 1:
        return rnd.choice(("+7 916 123-45-67", "89161234567", "+7(916)1234567", "8 (495) 777-12-34"))
    if kind == 2:
        return rnd.choice(("10.1.2.5", "010.001.002.005", "10.1.2.05", "192.168.10.20", r"10\.1\.2\.5"))
    if kind == 3:
        return rnd.choice(("2a00:1450:4010::65", "2A00:1450:4010:0:0:0:0:65", "2a00:1450:4010:0000::0065"))
    if kind == 4:
        return rnd.choice(("00:1A:2B:3C:4D:5E", "00-1a-2b-3c-4d-5e", "001a.2b3c.4d5e"))
    if kind == 5:
        return _cased(rnd, rnd.choice(("srv-dc01.corp.contoso.ru", "srv-web02.corp.contoso.ru", "SRV-DC01")))
    if kind == 6:
        return _cased(rnd, "corp.contoso.ru")
    if kind == 7:
        return rnd.choice((r"CONTOSO\ivanov_ii", r"contoso\Ivanov_II", r"C:\Users\ivanov_ii\Documents"))
    if kind == 8:
        return rnd.choice(("ИНН 7707083893", "ИНН 7707 083 893"))
    if kind == 9:
        return rnd.choice(("password=Hunter2Hunter2", 'token: ghp_' 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5'))  # secret-scan:allow -- synthetic test fixture
    if kind == 10:
        return rnd.choice(("S-1-5-21-1004336348-1177238915-682003330-1001", "CN=Ivanov,OU=Users,DC=corp,DC=contoso,DC=ru"))
    if kind == 11:
        return "https://admin:S3cretPass@srv-web01.corp.contoso.ru/"
    if kind == 12:
        return rnd.choice(("Заря-Восток", "Zarya-Vostok", "ЗАРЯ-ВОСТОК"))
    if kind == 13:
        return rnd.choice(("def handler(request):\n    return render(request, 'index.html')", "if (a < b) { x = 1; }"))
    if kind == 14:
        return rnd.choice(("/var/log/syslog", "C:\\Program Files\\App\\app.exe", "./scripts/run.sh"))
    return rnd.choice(("Проверь узел", "и ещё раз", "after the restart", "see the log", "файл notes.txt"))


def test_written_round_trip_on_generated_texts():
    rnd = random.Random(5)
    settings = masked()
    state = written_state()
    for _ in range(200):
        text = rnd.choice((" ", "\n", ", ", "; ")).join(_piece(rnd) for _ in range(rnd.randint(3, 8)))
        sanitized = sanitize(state, text, settings).sanitized
        assert originals(state, settings, exact=True)(sanitized) == text


def test_same_spelling_gets_the_same_replacement():
    settings = masked()
    state = written_state()
    text = "узел SRV-DC01, почта Ivan.Petrov@Contoso.RU"
    first = sanitize(state, text, settings).sanitized
    other = sanitize(state, "узел srv-dc01, почта ivan.petrov@contoso.ru", settings).sanitized
    assert sanitize(state, text, settings).sanitized == first
    assert first.lower() != other.lower()       # регистр подмены имени узла повторяет оригинал и в обычном чате


def test_exact_restore_ignores_mangled_labels_and_restores_secrets():
    settings = Settings(always=(DictEntry(T.PERSON, "Иван Петров"),))      # SECRET — «скрывать без восстановления»
    state = written_state()
    sanitized = sanitize(state, "Иван Петров, пароль: Qwerty123!, узел 10.1.2.5", settings).sanitized
    assert sanitized.startswith("<PERSON_1>, пароль: <SECRET_1>, узел ")
    fake = sanitized.rsplit(" ", 1)[1]
    derived = fake.rsplit(".", 1)[0] + ".77"         # новый узел в условной подсети (FR-7.6)
    exact = originals(state, settings, exact=True)
    assert exact("<PERSON_1> <SECRET_1>") == "Иван Петров Qwerty123!"
    assert exact(f"PERSON_1 &lt;PERSON_1&gt; SECRET_1 {derived}") == "PERSON_1 &lt;PERSON_1&gt; SECRET_1 10.1.2.77"
    tolerant = originals(state, settings)
    assert tolerant("<SECRET_1> PERSON_1") == "<SECRET_1> Иван Петров"


ORDINARY = {
    "email": "a <EMAIL_1> b <EMAIL_1>",
    "phone": "a <PHONE_1> b <PHONE_1> c <PHONE_1>",
    "ipv4": "a 10.90.233.5 b 10.90.233.5",
    "ipv6": "a 2001:db8:1::1 b 2001:db8:1::1",
    "host": "ping HOST-1.sub-2.domain-1.example; ping host-1; ping host-1; ssh host-1.SUB-2.domain-1.example",
    "realm": "realm HOST-1.domain-1.example and host-1.domain-1.example",
    "account": r"DOMAIN-1\<ACCOUNT_1> and domain-1\<ACCOUNT_1> and C:\Users\<ACCOUNT_1>\x",
    "inn": "ИНН <INN_1> и ИНН <INN_1>",
    "dictionary": "Проект <TERM_1>, он же <TERM_1> и <TERM_1>",
}


@pytest.mark.parametrize("name", ORDINARY)
def test_ordinary_chats_are_unchanged(name):
    """Без режима написаний — прежний очищенный текст (записан до правки ядра)."""
    state = ChatState(chat_id="w", net_key=bytes(range(32)))
    assert sanitize(state, SPELLINGS[name], masked()).sanitized == ORDINARY[name]
