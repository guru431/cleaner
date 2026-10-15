"""Проверка утечек (раздел 8): адрес IP находится по адресу, а не только по записям, которые чат уже видел."""
import pytest

from cleaner.core import leakcheck
from cleaner.core.entities import ops
from cleaner.core.pipeline import sanitize
from cleaner.core.types import DictEntry, Entity, Policy, Settings, default_policies
from cleaner.core.types import EntityType as T


def leaked(text, state, settings) -> list[tuple[str, str | None]]:
    return [(text[leak.start:leak.end], leak.entity_id) for leak in leakcheck.check(text, state, settings)]


@pytest.mark.parametrize(
    "written, other, found",
    [
        ("2A00:1450:4010:0::0065", "x 2a00:1450:4010:0:0:0:0:65 y", "2a00:1450:4010:0:0:0:0:65"),
        ("2a00:1450:4010::65", "x 2a00:1450:4010:0000::0065, y", "2a00:1450:4010:0000::0065"),
        ("2a00:1450:4010::65", "Source:2A00:1450:4010:0::65: занят", "2A00:1450:4010:0::65"),
        ("10.1.2.5", "x 010.001.002.005 y", "010.001.002.005"),
        ("10.1.2.5", "маршрут 010.001.002.005/24", "010.001.002.005/24"),
    ],
    ids=["full", "padded", "after_label", "ipv4_zeros", "ipv4_with_prefix"],
)
def test_ip_address_is_found_in_a_notation_the_chat_has_not_seen(state, settings, written, other, found):
    """FINDINGS «Restore round of 15.10», (1): написания сущности — только записи, которые чат видел, а адрес бывает
    записан и иначе. Слой 3 разбирает любую запись, поэтому слабее была только вторая линия защиты."""
    sanitize(state, f"узел {written}", settings)
    [entity] = state.entities.values()
    assert leaked(other, state, settings) == [(found, entity.id)]


def test_network_and_dictionary_address_are_found_in_another_notation(state, settings):
    ops.mask(state, "2a00:1450:4010::/64", T.IP)
    sanitize(state, "сеть 2a00:1450:4010::/64", settings)
    [entity] = state.entities.values()
    assert leaked("сеть 2A00:1450:4010:0::/64", state, settings) == [("2A00:1450:4010:0::/64", entity.id)]
    always = Settings(always=(DictEntry(T.IP, "192.168.10.7"),))
    assert leaked("узел 192.168.010.007", state, always) == [("192.168.010.007", None)]


def test_written_notation_is_reported_once(state, settings):
    """Запись, которую нашло написание сущности, второй находкой по адресу не становится."""
    sanitize(state, "узел 2A00:1450:4010:0::0065 и 10.1.2.5", settings)
    text = "x 2A00:1450:4010:0::0065 и 2a00:1450:4010::65 и 10.1.2.5/24"
    assert [found for found, _ in leaked(text, state, settings)] == ["2A00:1450:4010:0::0065", "2a00:1450:4010::65", "10.1.2.5"]


@pytest.mark.parametrize(
    "change",
    [
        lambda state, settings: (ops.unmask(state, "10.1.2.5"), settings)[1],
        lambda state, settings: Settings(never=frozenset({"010.001.002.005"})),
        lambda state, settings: Settings(policies=default_policies() | {T.IP: Policy.OFF}),
    ],
    ids=["unmasked", "never_list", "policy_off"],
)
def test_open_address_in_another_notation_is_not_a_leak(state, settings, change):
    """С другой стороны: адрес, с которого сняли замену, из списка «никогда не скрывать» и тип с выключенной
    политикой — не утечка ни в какой записи, как и в написаниях (шаг 1)."""
    sanitize(state, "узел 10.1.2.5", settings)
    assert leaked("x 010.001.002.005 y", state, change(state, settings)) == []


@pytest.mark.parametrize("text, found", [
    (r'my $to = "ivanov\@contoso.ru";', r"ivanov\@contoso.ru"),
    (r"/^ivanov\@contoso\.ru$/", r"ivanov\@contoso\.ru"),
    (r'"ivanov\\@contoso.ru"', None),
], ids=["perl", "regex", "escaped-backslash"])
def test_known_email_written_with_an_escaped_at_is_a_leak(state, settings, text, found):
    """Ревью раунда 5, P3: адрес в строке Perl и PHP пишут через «\\@» — это тот же адрес, и проверка утечек находит
    известный. «\\\\@» — обратная косая и массив Perl, не «@»: такой записи адреса нет."""
    sanitize(state, "почта ivanov@contoso.ru", settings)
    [email] = state.entities.values()
    assert leaked(text, state, settings) == ([(found, email.id)] if found else [])


def test_replacement_and_other_addresses_are_not_leaks(state, settings):
    """Подмена в другой записи — подмена, как на шаге 1, даже если совпала с настоящим адресом другой сущности
    (позже в чате появился адрес, равный выданной подмене); адрес не из чата, адрес внутри цепочки через двоеточие
    и число, похожее на адрес, — не утечки."""
    sanitize(state, "узел 2a00:1450:4010::65 и 10.1.2.5", settings)
    fake = next(text for text, surrogate in state.surrogates.items() if surrogate.kind == "ip")
    state.entities["twin"] = Entity("twin", T.IP, 9, fake, fake, "detector", [fake])
    padded = ".".join(octet.zfill(3) for octet in fake.split("."))
    text = f"{padded}, 2001:0db8:0001::0001, 010.001.002.006, ab:cd:2a00:1450:4010:0:0:0:0:65, 1.2.3.4.5"
    assert leaked(text, state, settings) == []
