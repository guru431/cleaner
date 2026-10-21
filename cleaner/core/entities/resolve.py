"""Сопоставление фрагментов с сущностями чата и выдача замен."""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from uuid import uuid4

from cleaner.core.detect.merge import NAME_WORDS, MergedSpan
from cleaner.core.entities import hostmap, labels, macsid, names, netmap
from cleaner.core.match import has_invisible, normalize
from cleaner.core.types import STRICTNESS, ChatState, Entity, EntityType, Settings, Surrogate

T = EntityType
_DIGIT_TYPES = frozenset({T.INN, T.SNILS, T.OGRN, T.KPP, T.OMS, T.CARD, T.PASSPORT})
# Записи адресов в тексте: IPv4 с длиной префикса и без (и через «\.»), IPv6. Как в слое 3 и при восстановлении, адрес
# может стоять сразу за подписью («Source:2001:db8:1::1», «Source:203.0.113.1»); подпись в запись не входит.
_ADDRESS_TOKEN = re.compile(
    r"(?<![\w.])\d{1,3}(\\{0,2}\.)\d{1,3}\1\d{1,3}\1\d{1,3}(?:/\d{1,2})?(?!\w|\\{0,2}\.\d)"
    r"|(?<![\w:.])(?:(?=\w*[^\W\dA-Fa-f])\w+:|\w{5,}:)?"
    r"(?P<v6>(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w:])"
)
_LEGAL_FORMS = frozenset(
    {"ооо", "зао", "оао", "пао", "ао", "ип", "нко", "гуп", "муп", "фгуп", "llc", "inc", "ltd", "gmbh", "corp", "co"}
)
_NAME = re.compile(r"[\w-]+(?:\.[\w-]+)*")
# Подмена имени в тексте. Номера длиннее двадцати цифр счётчик не выдаст, и дальше цепочка цифр не берётся: все её
# начала собирались бы квадратичное время.
_ISSUED_NAME = re.compile(r"(host|sub|domain)-([0-9]{1,20})")


@dataclass(frozen=True)
class ResolvedSpan:
    start: int
    end: int
    entity_id: str
    surrogate: str
    sources: tuple[str, ...]
    validated: bool = False             # MergedSpan.validated


def canonical_key(type_: EntityType, value: str) -> str:
    """Ключ, по которому разные написания одного значения сводятся к одной сущности."""
    if type_ is T.EMAIL:
        return value.lower()
    if type_ is T.PHONE:
        digits = re.sub(r"\D", "", value)
        return "7" + digits[1:] if len(digits) == 11 and digits[0] == "8" else digits
    if type_ in _DIGIT_TYPES:
        return re.sub(r"\D", "", value)
    if type_ is T.BANK_ACCOUNT:
        return re.sub(r"[^0-9A-Za-z]", "", value).upper()
    if type_ is T.ACCOUNT:
        return value.rsplit("\\", 1)[-1].lower()
    if type_ in (T.SECRET, T.DN):
        return value
    if type_ is T.MAC:
        return macsid.mac_key(value)
    if type_ is T.ORG:
        words = re.sub(r"[\"'«»“”„.]", " ", normalize(value)).split()
        return " ".join(w for w in words if w not in _LEGAL_FORMS) or " ".join(words)
    if type_ is T.ADDRESS:
        return " ".join(re.sub(r"[^\w\s]", " ", normalize(value)).split())
    return normalize(value)


def _ip_text(value: str) -> str:
    ip, prefix = netmap.parse(value)
    if prefix is None:
        return str(ip)
    if not 0 <= prefix <= ip.max_prefixlen:
        raise ValueError(value)         # «10.0.0.0/40» — не сеть: перестановка споткнулась бы о длину
    return f"{ip}/{prefix}"


def name_parts(value: str, precedes: bool) -> tuple[list[str], str]:
    """Части имени через точку слева от домена и домен (5.10): в части имени перед заменой и в части без точки домена нет.
    По ним выдаёт подмены _name, и по ним же конвейер судит о типах частей адреса (pipeline._types)."""
    return (value.split("."), "") if precedes or "." not in value else hostmap.parts(value)


def _fake_forms(fake: str) -> set[str]:
    """Записи подмены адреса, которые найдёт восстановление: она сама и у сети — её адрес без длины префикса (_ip)."""
    return {fake, fake.split("/")[0]}


class Resolver:
    """Один проход по тексту: находит или создаёт сущности и выдаёт им замены."""

    def __init__(self, state: ChatState, settings: Settings, text: str, generic_labels: frozenset[str]):
        self.state = state
        self.settings = settings
        self.text = text
        self.text_lower = text.lower()
        self.generic = generic_labels
        self.index = {(e.type, e.key): e for e in state.entities.values()}
        # До 15.10.2026 нормализация оставляла невидимые знаки (мягкий перенос, пробел нулевой ширины, ударение), и
        # ключ сущности из такого значения хранится с ними, а у адреса — с пробелом на их месте. Сегодняшний ключ того
        # же значения другой, и сущность получила бы новую метку. Поэтому её написание с невидимыми знаками ведёт к
        # ней и по сегодняшнему ключу: так находится и сущность, в которую значение влито объединением, — написания
        # влитой переходят к ней. Ключ, уже занятый другой сущностью, остаётся за той.
        for entity in state.entities.values():
            for form in entity.forms:
                if has_invisible(form):
                    self.index.setdefault((entity.type, canonical_key(entity.type, form)), entity)
        self.alias: dict[tuple[EntityType, str], str] = {}
        for entry in settings.always:
            key = self._dictionary_key(entry.type, entry.value)
            for form in (entry.value, *entry.aliases):
                self.alias[(entry.type, normalize(form))] = key
            lead = self._lead(entry.type, entry.value) if entry.aliases and entry.type in (T.HOST, T.DOMAIN) else None
            for form in entry.aliases if lead else ():
                # Варианты одной записи — одна замена (5.4): у имени с точками её задаёт первая часть,
                # поэтому первая часть каждого варианта ведёт к ключу первой части значения. Домен
                # варианта остаётся своим: «dc01.contoso.local» не делает contoso.local тем же, что contoso.ru.
                other = self._lead(entry.type, form)
                if other and other[0] is lead[0]:
                    self.alias[(other[0], normalize(other[1]))] = lead[1].lower()
        self.open_values = settings.never | {r.value.lower() for r in state.rules if r.action == "unmask"}
        # Правила, которые дают части имени узла свой тип. Правило HOST или DOMAIN часть подменяет как обычно.
        self.manual = {
            normalize(r.value): r.type for r in state.rules
            if r.action == "mask" and r.type is not None and r.type not in (T.HOST, T.DOMAIN)
        }
        self.real_ips: set[str] = set()
        self._text_addresses: set[str] | None = None
        self._open_addresses: set[str] | None = None
        self._text_names: set[str] | None = None
        self._text_labels: set[str] | None = None
        self._searched: set[str] | None = None      # написания сущностей чата — при первом слиянии находок (_remember)
        self._runs: dict[str, bool] = {}            # сущности людей: слияние ли это находок длиннее имени (_run)

    @staticmethod
    def _dictionary_key(type_: EntityType, value: str) -> str:
        if type_ in (T.HOST, T.DOMAIN):
            return value.lower()
        if type_ is T.IP:
            try:
                return _ip_text(value)
            except ValueError:
                return value.lower()
        return canonical_key(type_, value)

    def run(self, text: str, spans: list[MergedSpan]) -> list[ResolvedSpan]:
        for span in spans:
            if span.type is T.IP:
                try:
                    self.real_ips.add(_ip_text(text[span.start:span.end]))
                except ValueError:
                    pass
        return [
            self._resolve(span, text[span.start:span.end] if span.value is None else span.value) for span in spans
        ]

    def _resolve(self, span: MergedSpan, value: str) -> ResolvedSpan:
        origin = "manual" if "manual" in span.sources else "dictionary" if "dict" in span.sources else "detector"
        name = partial(self._name, follows=span.follows, precedes=span.precedes)
        special = {T.IP: self._ip, T.MAC: self._mac, T.SID: self._sid, T.HOST: name, T.DOMAIN: name}.get(span.type)
        # None — значение не того вида (например, ручное правило): обычная метка. Вид проверяется до
        # первой записи в состояние: исключение посреди подмены оставило бы сущность без замены и номер.
        resolved = special(value, span.type, origin) if special else None
        entity, surrogate = resolved or self._labelled(span.type, value, origin, span.searchable, span.forms)
        return ResolvedSpan(span.start, span.end, entity.id, surrogate, span.sources, span.validated)

    # --- сущности ---------------------------------------------------------

    def _next(self, type_: EntityType) -> int:
        number = self.state.counters.get(type_.value, 0) + 1
        self.state.counters[type_.value] = number
        return number

    def _entity(
        self, type_: EntityType, key: str, value: str, origin: str, searchable: bool = True, forms: tuple[str, ...] = (),
    ) -> Entity:
        merged_into = self.state.key_alias.get(f"{type_.value}:{key}")
        entity = self.state.entities.get(merged_into) if merged_into else self.index.get((type_, key))
        if entity is None:
            entity = Entity(uuid4().hex, type_, self._next(type_), key, value, origin)
            self.state.entities[entity.id] = entity
            self.index[(type_, key)] = entity
        self._remember(entity, value, searchable, forms)
        return entity

    def _remember(self, entity: Entity, value: str, searchable: bool, forms: tuple[str, ...]) -> None:
        """Искомые написания: значение — или написания находок, слитых в него (MergedSpan.forms). Написание находки, уже
        искомое в чате (известное значение другой сущности), не повторяется: оно и так найдётся."""
        if searchable and value not in entity.forms:
            entity.forms.append(value)
        if not forms:
            return
        if self._searched is None:
            self._searched = {form for e in self.state.entities.values() for form in e.forms}
        for form in forms:
            if form not in self._searched:
                self._searched.add(form)
                entity.forms.append(form)

    def _issue(self, entity: Entity, slot: str, make: Callable[[], str]) -> str:
        """Замена сущности для данного вида записи: выдаётся один раз и запоминается."""
        key = f"{entity.id}|{slot}"
        if key not in self.state.issued:
            self.state.issued[key] = make()
        return self.state.issued[key]

    def _taken(self, candidate: str) -> bool:
        if self._text_names is None:
            # Подмены «host-N», «sub-N», «domain-N», которые стоят в тексте, и внутри слова тоже: «host-12» — это и
            # «host-1». Собираются один раз на текст: искать каждую новую по всему тексту было бы квадратично.
            self._text_names = {
                f"{m.group(1)}-{m.group(2)[:length]}"
                for m in _ISSUED_NAME.finditer(self.text_lower) for length in range(1, len(m.group(2)) + 1)
            }
        return (
            candidate in self._text_names
            or (T.HOST, candidate) in self.index
            or (T.DOMAIN, candidate) in self.index
        )

    def _free_number(self, entity: Entity, template: str) -> None:
        while self._taken(template.format(entity.number)):
            entity.number = self._next(entity.type)

    # --- метки ------------------------------------------------------------

    def _label_taken(self, type_: EntityType, number: int) -> bool:
        """Метка с этим номером уже встречалась как посторонняя или стоит в тексте (в любом виде)."""
        if self._text_labels is None:      # один раз на текст, как и подмены имён (_taken)
            self._text_labels = {m.group() for m in labels.SHAPE.finditer(self.text)}
        for style in ("angle", "square"):
            label = labels.format_label(style, type_, number)
            if label in self.state.foreign_labels or label in self._text_labels:
                return True
        return False

    def _label(self, entity: Entity) -> str:
        def make() -> str:
            while self._label_taken(entity.type, entity.number):
                entity.number = self._next(entity.type)
            label = labels.format_label(self.state.label_style, entity.type, entity.number)
            self.state.surrogates[label] = Surrogate(entity.id)
            return label

        return self._issue(entity, "label", make)

    def _labelled(
        self, type_: EntityType, value: str, origin: str, searchable: bool = True, forms: tuple[str, ...] = (),
    ) -> tuple[Entity, str]:
        key = self.alias.get((type_, normalize(value))) or canonical_key(type_, value)
        if type_ is T.PERSON:
            entity = self._person(key, value, origin, searchable, forms)
        else:
            entity = self._entity(type_, key, value, origin, searchable, forms)
        return entity, self._label(entity)

    def _person(self, key: str, value: str, origin: str, searchable: bool = True, forms: tuple[str, ...] = ()) -> Entity:
        """Человек: тот же ключ (словарь, объединение, прежнее написание) или единственная совместимая сущность (5.9).
        Слияние находок длиннее имени (forms, 5.7, шаги 2 и 3) — не упоминание: к человеку оно не присоединяется и
        значения для восстановления не задаёт, а упоминания не присоединяются к нему (_run). Иначе позже найденное
        «Иван Иван» восстанавливалось слиянием «Иван Иван Иван Иван Иван», а слияние подменяло значение человека."""
        run = bool(forms) and len(value.split()) > NAME_WORDS
        mention = () if run else names.parse(value)
        merged_into = self.state.key_alias.get(f"{T.PERSON.value}:{key}")
        entity = self.state.entities.get(merged_into) if merged_into else self.index.get((T.PERSON, key))
        if entity is None:
            # Написание, уже отнесённое к сущности, за ней и остаётся: иначе на следующем проходе (5.10) или в
            # следующем тексте появившийся тёзка сделал бы его неоднозначным и выдал новую метку.
            folded = normalize(value)
            entity = next((
                e for e in self.state.entities.values()
                if e.type is T.PERSON and not self._run(e) and any(normalize(form) == folded for form in e.forms)
            ), None)
        if entity is None and mention:
            fitting = [
                e for e in self.state.entities.values()
                if e.type is T.PERSON and e.forms and not self._run(e) and names.compatible(mention, e)
            ]
            if len(fitting) == 1:
                entity = fitting[0]
                self.index[(T.PERSON, key)] = entity
        if entity is None:
            entity = self._entity(T.PERSON, key, value, origin, searchable, forms)
        else:
            self._remember(entity, value, searchable, forms)
        if not run:
            names.absorb(entity, mention, value)
        return entity

    def _run(self, entity: Entity) -> bool:
        """Сущность слияния находок длиннее имени (_person): ключ длиннее четырёх слов, а целиком значение не искомо —
        ни одно написание не совпадает с ключом. Так узнаются и слияния, записанные чатами до 15.10.2026. Ответ
        запоминается на проход: ключ слияния бывает длиной в текст."""
        if entity.id not in self._runs:
            self._runs[entity.id] = len(entity.key.split()) > NAME_WORDS and all(
                normalize(form) != entity.key for form in entity.forms
            )
        return self._runs[entity.id]

    # --- подмены ----------------------------------------------------------

    def _ip(self, value: str, type_: EntityType, origin: str) -> tuple[Entity, str] | None:
        try:
            canonical = _ip_text(value)
        except ValueError:
            return None
        ip = netmap.parse(canonical)[0]
        # IPv6 восстанавливается в записи из текста, где адрес встретился впервые, как и остальные сущности;
        # IPv4 — в простой записи (5.4). Ключ — канонический: одна сущность на адрес в любой записи. Каноническая
        # запись остаётся и среди искомых: по ней известные значения и проверка утечек находили адрес и раньше.
        # Адрес через «\.» («\\.») получает ту же подмену через тот же разделитель, и восстановление пишет оригинал так же
        # (раздел 7, шаг 2).
        written = value if ip.version == 6 else canonical
        entity = self._entity(T.IP, canonical, written, origin)
        if canonical not in entity.forms:
            entity.forms.append(canonical)

        def make() -> str:
            fake = netmap.fake_ip(canonical, self.state)
            # Публичным адресам и IPv6 подмены выдаются по порядку: занятую текстом можно пропустить.
            # Частный адрес переставляется однозначно — при совпадении остаётся только метка.
            while fake is not None and self._address_in_text(fake) and netmap.private_bits(ip) is None:
                fake = netmap.fake_ip(canonical, self.state)
            collides = fake is not None and (
                fake in self.real_ips or (T.IP, fake) in self.index or self._address_open(fake)
                or self._address_in_text(fake) or self._claimed(fake, ip)
            )
            if fake is None or collides:
                return self._label(entity)
            kind = "ip6" if ":" in fake else "ip"
            self.state.surrogates[fake] = Surrogate(entity.id, written, kind)
            if "/" in fake:
                # Модель может написать адрес сети без длины префикса.
                bare = Surrogate(entity.id, written.split("/")[0], kind)
                self.state.surrogates.setdefault(fake.split("/")[0], bare)
            return fake

        return entity, self._issue(entity, "ip", make).replace(".", hostmap.separator(value))

    def _address_in_text(self, address: str) -> bool:
        """Стоит ли подмена в тексте как адрес, в любой записи: «2001:0db8:0001::0001» — это 2001:db8:1::1,
        «203.000.113.001» — 203.0.113.1, «203.0.113.1/24» — и сеть, и сам адрес. Ответ таких записей не различит.
        Подмена сети — ещё и своим адресом (_fake_forms). Подмены netmap выдаёт в каноническом виде."""
        if self._text_addresses is None:      # собирается один раз на текст: проверок — тысячи
            self._text_addresses = set()
            for m in _ADDRESS_TOKEN.finditer(self.text):
                token = m.group("v6") or m.group()
                if token.endswith(":") and not token.endswith("::"):
                    token = token[:-1]          # двоеточие после адреса IPv6 — знак препинания («2001:db8:1::1: занят»)
                self._text_addresses |= netmap.canonical_forms(token)    # не адрес — с подменой не совпадёт
        return not self._text_addresses.isdisjoint(_fake_forms(address))

    def _address_open(self, address: str) -> bool:
        """Совпадает ли подмена с открытым адресом (список «никогда не скрывать», правило «открыть») в любой его записи:
        «2001:0db8:0001::0001» в списке — это подмена 2001:db8:1::1, открытый 10.90.0.0 — подмена сети 10.90.0.0/16
        (_fake_forms). Открытый адрес показывается в текстах чата как есть, и восстановление превратило бы его в оригинал
        другой сущности. Список разбирается при первой подмене адреса."""
        if self._open_addresses is None:
            self._open_addresses = netmap.addresses(self.open_values)
        return not self._open_addresses.isdisjoint(_fake_forms(address))

    def _claimed(self, fake: str, ip: netmap.Address) -> bool:
        """Восстанавливается ли подмена уже в другой адрес (6.2). Узел «.0» и сеть с обнулёнными битами узла переставляются
        в одну подмену: 192.168.1.0 (верхняя половина /23) — в 192.168.94.0, как и сеть 192.168.0.0/23 без длины префикса,
        и «192.168.1.0/23» из текста (длину префикса узла слой 3 во фрагмент не берёт) восстанавливалось бы сетью. Подмена
        сети сверяется и своим адресом, если его выдали подменой адреса; адрес сети, записанный только для восстановления
        (_ip), подмене другой сети не мешает: 10.90.0.0/16 и 10.90.0.0/17 — разные записи. Тот же адрес в другой записи
        (сеть 10.1.2.0/24 и шлюз 10.1.2.0) — не помеха."""
        for key in dict.fromkeys((fake, fake.split("/")[0])):
            taken = self.state.surrogates.get(key)
            if taken is None or (key != fake and self.state.issued.get(f"{taken.entity_id}|ip") != key):
                continue
            try:
                if netmap.parse(taken.original or "")[0] != ip:
                    return True
            except ValueError:
                return True         # метка или имя узла
        return False

    def _mac(self, value: str, type_: EntityType, origin: str) -> tuple[Entity, str] | None:
        key = macsid.mac_key(value)
        if len(key) != 12:
            return None
        entity = self._entity(T.MAC, key, value, origin)
        style = macsid.style_of(value)

        def make() -> str:
            fake = macsid.fake_mac(entity.number, style)
            self.state.surrogates[fake] = Surrogate(entity.id, value, "mac")
            return fake

        return entity, self._issue(entity, f"mac{style}", make)

    def _sid(self, value: str, type_: EntityType, origin: str) -> tuple[Entity, str] | None:
        m = macsid.SID.fullmatch(value)
        if not m:
            return None
        domain_id, rid = m.group(1), m.group(2)
        original = f"S-1-5-21-{domain_id}"
        entity = self._entity(T.SID, domain_id, original, origin)

        def make() -> str:
            fake = macsid.fake_sid_prefix(entity.number)
            self.state.surrogates[fake] = Surrogate(entity.id, original, "sid")
            return fake

        prefix = self._issue(entity, "sid", make)
        return entity, prefix + (f"-{rid}" if rid else "")

    def _part(self, label: str, origin: str, leading: bool, standalone: bool = False) -> tuple[Entity, str]:
        """Одна часть имени узла. Искомой становится только отдельная или «похожая на имя узла» часть."""
        searchable = standalone or (leading and re.search(r"[\d-]", label) is not None)
        key = self.alias.get((T.HOST, normalize(label))) or label.lower()
        entity = self._entity(T.HOST, key, label, origin, searchable)

        def make() -> str:
            prefix = "host" if leading else "sub"
            self._free_number(entity, prefix + "-{}")
            fake = f"{prefix}-{entity.number}"
            self.state.surrogates[fake] = Surrogate(entity.id, label, "host")
            return fake

        return entity, hostmap.mirror_case(label, self._issue(entity, "name", make))

    def _netbios(self, value: str, origin: str) -> tuple[Entity, str]:
        key = self.alias.get((T.DOMAIN, normalize(value))) or value.lower()
        entity = self._entity(T.DOMAIN, key, value, origin)

        def make() -> str:
            self._free_number(entity, "domain-{}")
            fake = f"DOMAIN-{entity.number}"
            self.state.surrogates[fake] = Surrogate(entity.id, value, "host")
            return fake

        fake = self._issue(entity, "netbios", make)
        return entity, fake if value.isupper() else fake.lower()

    def _lead(self, type_: EntityType, value: str) -> tuple[EntityType, str] | None:
        """Чья замена стоит в подмене имени первой: тип сущности и часть, по которой _name ищет её ключ."""
        if not _NAME.fullmatch(value):
            return None
        if "." not in value:
            return type_, value
        left, registrable = hostmap.parts(value)
        first = next((label for label in left if label.lower() not in self.generic), None)
        return (T.HOST, first) if first else (T.DOMAIN, registrable)

    def _dns(self, registrable: str, origin: str) -> tuple[Entity, str]:
        key = self.alias.get((T.DOMAIN, normalize(registrable))) or registrable.lower()
        domain = self._entity(T.DOMAIN, key, registrable, origin)

        def make() -> str:
            self._free_number(domain, "domain-{}")
            fake = f"domain-{domain.number}.example"
            self.state.surrogates[fake] = Surrogate(domain.id, registrable, "host")
            return fake

        return domain, self._issue(domain, "dns", make)

    def _manual(self, part: str) -> tuple[Entity, str] | None:
        """Часть имени, которой пользователь дал другой тип (смена типа, правило): метка этого типа вместо
        подмены части, остальные части подменяются как обычно (5.7, шаг 4)."""
        type_ = self.manual.get(normalize(part))
        return self._labelled(type_, part, "manual") if type_ else None

    def _name(
        self, value: str, type_: EntityType, origin: str, follows: bool = False, precedes: bool = False,
    ) -> tuple[Entity, str] | None:
        """follows, precedes — фрагмент стоит в имени после выданной замены или метки и перед ней (pipeline._placed).
        Имя через «\\.» или «\\\\.» (регулярное выражение, в том числе в строке JSON) разбирается как через точку, а подмена
        пишется тем же разделителем — так её найдёт и восстановит раздел 7 (шаг 2); в таблицу замен оба записываются
        через точку."""
        separator = hostmap.separator(value)
        value = hostmap.dotted(value)
        if not _NAME.fullmatch(value):
            return None
        whole = not (follows or precedes)
        if "." not in value and whole:
            if type_ is T.DOMAIN:
                return self._netbios(value, origin)
            # Имя узла, которое правило поглотило бы, остаётся HOST, если у HOST политика строже (merge, 5.7): метка
            # правила вернула бы мягкую политику.
            retyped = self.manual.get(normalize(value))
            policies = self.settings.policies
            if retyped and STRICTNESS.get(policies.get(retyped), 0) >= STRICTNESS.get(policies.get(type_), 0):
                return self._manual(value)
            return self._part(value, origin, leading=True, standalone=True)
        # Часть имени рядом с заменой — не имя целиком (5.10): в частях перед заменой домена нет, одиночная часть после
        # неё — тоже часть. Первой часть после замены не бывает, и отдельным написанием никакая из них не становится.
        left, registrable = name_parts(value, precedes)
        retyped = self._manual(registrable) if registrable else None
        domain = retyped or (self._dns(registrable, origin) if registrable else None)
        fakes, owners, leading = [], [], not follows
        for label in left:
            manual = self._manual(label)
            if manual is None and label.lower() in self.generic:
                fakes.append(label)
                continue
            entity, fake = manual or self._part(label, origin, leading=leading)
            leading = False         # первая — первая не служебная часть: у www.srv02.corp.contoso.ru это srv02
            owners.append((entity, manual is not None))
            fakes.append(fake)
        if domain:
            owners.append((domain[0], retyped is not None))
            fakes.append(domain[1])
        # Сущность имени целиком — часть с самой строгой политикой: по ней «блокировать» проверяют очистка и экран
        # чата (FR-4.2). При равных — часть, которой пользователь дал другой тип: блокировка её типа, заданная позже,
        # тоже видна на экране; затем — первая слева, как прежде. Восстановление проверяет политики всех частей.
        policies = self.settings.policies
        primary = max(owners, key=lambda owner: (STRICTNESS.get(policies.get(owner[0].type), 0), owner[1]))[0]
        surrogate = ".".join(fakes)
        # Имя длиннее имени DNS (253 знака) — цепочка вроде «a.a.a….ru» — целиком не записывается: поиск замен и
        # проверка ссылок перебирают цепочки частей до длины самой длинной записанной, и имя из тысяч частей делало бы
        # их кубическими. Его части выданы, и восстанавливается оно по частям. Часть имени рядом с заменой — не имя
        # из запроса и тоже не записывается.
        if left and whole and len(value) <= hostmap.MAX_NAME:
            self.state.surrogates.setdefault(surrogate, Surrogate(primary.id, value, "host"))
        return primary, surrogate.replace(".", separator)
