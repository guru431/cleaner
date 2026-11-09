"""Поиск известных написаний в тексте."""
from __future__ import annotations

import bisect
import re
import unicodedata
from collections.abc import Callable, Iterable
from typing import Any, Generic, TypeVar

import regex

from cleaner.core.types import EntityType

T = TypeVar("T")
_TOKEN = re.compile(r"[^\W\d_]+|\d+")
_PREFIX = 64        # написание длиннее ищется по кускам такой длины (find_forms)
# Узел дерева длинных написаний — их начало длиной в несколько кусков: следующие куски и хвосты (последний кусок, 1–64
# знака) по длине, хвост -> ((режим, нагрузка), …). С вхождения сверяется срез на кусок и на каждую длину хвоста — не
# больше 64 в узле, сколько бы написаний ни делили начало.
_Node = tuple[dict[str, "_Node[T]"], dict[int, dict[str, tuple[tuple[str, T], ...]]]]
_SPACE_RUN = re.compile(r"\s+")
# Невидимые знаки: форматирующие (мягкий перенос, пробел нулевой ширины, метки направления) и знак
# ударения. Ударение выпадает, только если не вошло в букву при сборке NFC: у русских гласных букв
# с ударением нет, а «é» — одна буква и остаётся собой.
_STRESS = "\N{COMBINING ACUTE ACCENT}"
_FORMAT = regex.compile(r"\p{Cf}+")
_FORMAT_OR_STRESS = regex.compile(r"[\p{Cf}" + _STRESS + "]+")
# «\.» — точка: имя в регулярном выражении, шаблоне grep, настройке nginx («^srv01\.contoso\.ru$») — то же имя, и «\\.» —
# то же выражение внутри строки JSON, Java, C# (hostmap.dotted). Три обратные косые и больше точку не экранируют. «\@» —
# «@» адреса в строке Perl и PHP и в выражении Perl («ivanov\@contoso.ru», слой 1); «\\@» — обратная косая и массив Perl.
_ESCAPED = re.compile(r"(?<!\\)(?:\\{1,2}(?=\.)|\\(?=@))")


def _lower(text: str) -> str:
    """Нижний регистр без изменения длины строки."""
    lowered = text.lower()
    if len(lowered) == len(text):
        return lowered
    return "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in text)


def _fold(char: str) -> str:
    low = char.lower()
    low = low if len(low) == 1 else char
    return "е" if low == "ё" else low


def _normalize_decomposed(text: str) -> tuple[str, list[int], list[int]]:
    """Медленный путь для текста не в NFC: буква с комбинирующими знаками собирается в одну.

    Ударение, которое в букву не вошло, выпадает, а буква накрывает его в исходном тексте.
    """
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            j = i + 1
            while j < n and text[j].isspace():
                j += 1
            chars.append(" ")
            starts.append(i)
            ends.append(j)
            i = j
            continue
        j = i + 1
        while j < n and unicodedata.combining(text[j]):
            j += 1
        for char in unicodedata.normalize("NFC", text[i:j]):
            if char != _STRESS:
                chars.append(_fold(char))
                starts.append(i)
                ends.append(j)
        i = j
    return "".join(chars), starts, ends


def _without(text: str, invisible: regex.Pattern[str]) -> tuple[str, list[int], list[int]]:
    """Нормализация текста без невидимых знаков; позиции — в исходном тексте.

    Знаки вырезаются одним проходом выражения, остальное идёт обычным путём. Знак накрывает и
    невидимые знаки за ним: ударение на последней букве уходит под замену вместе с ней.
    """
    pieces: list[str] = []
    origin: list[int] = []          # позиция каждого оставшегося знака в исходном тексте и конец текста
    position = 0
    for m in invisible.finditer(text):
        pieces.append(text[position:m.start()])
        origin.extend(range(position, m.start()))
        position = m.end()
    pieces.append(text[position:])
    origin.extend(range(position, len(text) + 1))
    lowered, starts, ends = _normalize("".join(pieces))
    return lowered, [origin[s] for s in starts], [origin[e] for e in ends]


def _normalize(text: str) -> tuple[str, list[int], list[int]]:
    """Текст для сравнения и границы каждого его знака в исходном тексте.

    Нижний регистр, «ё» как «е», буквы в NFC, любая цепочка пробельных знаков (в том числе
    неразрывный пробел и перевод строки) — один пробел, невидимых знаков и отдельного ударения нет.
    """
    nfc = unicodedata.is_normalized("NFC", text)
    # В тексте NFC отдельное ударение в букву уже не вошло; в остальном оно выпадает после сборки
    # букв медленным путём — иначе «e» с ударением перестала бы быть «é».
    invisible = _FORMAT_OR_STRESS if nfc else _FORMAT
    if invisible.search(text):
        return _without(text, invisible)
    if not nfc:
        return _normalize_decomposed(text)
    lowered = _lower(text).replace("ё", "е")
    pieces: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    position = 0
    for m in _SPACE_RUN.finditer(lowered):
        start, end = m.span()
        if start > position:
            pieces.append(lowered[position:start])
            starts.extend(range(position, start))
            ends.extend(range(position + 1, start + 1))
        pieces.append(" ")
        starts.append(start)
        ends.append(end)
        position = end
    if position < len(lowered):
        pieces.append(lowered[position:])
        starts.extend(range(position, len(lowered)))
        ends.extend(range(position + 1, len(lowered) + 1))
    return "".join(pieces), starts, ends


def normalize(text: str) -> str:
    """Та же нормализация, что при поиске, — для ключей сопоставления написаний."""
    return _normalize(text)[0].strip()


def has_invisible(text: str) -> bool:
    """Есть ли в тексте невидимые знаки или ударение, которые нормализация выбрасывает (с 15.10.2026)."""
    return _FORMAT_OR_STRESS.search(text) is not None


def _unescaped(lowered: str, starts: list[int], ends: list[int]) -> tuple[str, list[int], list[int]]:
    """Нормализованный текст, в котором «\\.» и «\\\\.» — точка, а «\\@» — «@» (_ESCAPED): обратные косые выпадают, знак
    накрывает и их."""
    pieces: list[str] = []
    kept_starts: list[int] = []
    kept_ends: list[int] = []
    position = 0
    for m in _ESCAPED.finditer(lowered):
        slash, sign = m.start(), m.end()
        pieces += [lowered[position:slash], lowered[sign]]
        kept_starts += [*starts[position:slash], starts[slash]]
        kept_ends += [*ends[position:slash], ends[sign]]
        position = sign + 1
    pieces.append(lowered[position:])
    return "".join(pieces), kept_starts + starts[position:], kept_ends + ends[position:]


def _bounded(text: str, start: int, end: int, mode: str) -> bool:
    if mode == "none":
        return True
    before = text[start - 1] if start else ""
    after = text[end] if end < len(text) else ""
    first, last = text[start], text[end - 1]
    if (before.isdigit() and first.isdigit()) or (after.isdigit() and last.isdigit()):
        return False        # число не вырезается из более длинного числа
    if mode == "letters":
        return not (before.isalpha() or after.isalpha())
    if before.isalnum() or before in ("_", "-") or after.isalnum() or after in ("_", "-"):
        return False
    if last.isdigit() and after == "." and text[end + 1:end + 2].isdigit():
        return False        # 10.1.2.3 внутри 10.1.2.3.4
    if first.isdigit() and before == "." and text[start - 2:start - 1].isdigit():
        return False
    return True


_NEEDLES: dict[str, str] = {}
_NEEDLES_MAX = 1 << 17


def _needle(form: str) -> str:
    """Написание в виде для сравнения. Чистая функция строки: ответы запоминаются (не больше _NEEDLES_MAX, затем память
    очищается), и сборка таблицы на тысячах сущностей чата не нормализует их написания заново. Словарь строк сборщик
    мусора не обходит."""
    try:
        return _NEEDLES[form]
    except KeyError:
        pass
    needle = _ESCAPED.sub("", _normalize(form)[0])
    if len(_NEEDLES) >= _NEEDLES_MAX:
        _NEEDLES.clear()
    _NEEDLES[form] = needle
    return needle


def _put(table: dict[str, tuple[tuple[str, T], ...]], needle: str, entry: tuple[str, T]) -> None:
    """Ещё одно написание needle. Кортеж, а не список: таблица из строк, чисел и кортежей не меняется после сборки, и
    сборщик мусора её не обходит."""
    table[needle] = (*table.get(needle, ()), entry)


class Forms(Generic[T]):
    """Таблица написаний для find_forms, собранная один раз: её можно искать во многих текстах. После сборки не
    меняется — общая для потоков."""

    __slots__ = ("index", "long", "loose")

    def __init__(self, forms: Iterable[tuple[str, str, T]]):
        # первое слово написания -> длина написания -> написание -> ((режим, нагрузка), …).
        # Группировка по длине нужна, чтобы тысячи логинов с общим началом («user00001», «i.ivanov»)
        # проверялись одним обращением к словарю, а не перебором. Написание длиннее _PREFIX — деревом кусков по _PREFIX
        # знаков (_Node): срез длиной в написание с каждого вхождения первого слова был бы квадратичным («a@bbb…b.ru» и
        # тысячи «a» в тексте), а сверка с каждым написанием общего начала — тоже (тысячи токенов JWT одного издателя).
        index: dict[str, dict[int, dict[str, tuple[tuple[str, T], ...]]]] = {}
        long: dict[str, dict[str, _Node[T]]] = {}
        loose: list[tuple[str, str, T]] = []
        for form, mode, payload in forms:
            needle = _needle(form)
            if not needle.strip():
                continue
            head = _TOKEN.match(needle)
            if head and mode != "none" and len(needle) > _PREFIX:
                node = long.setdefault(head.group(), {}).setdefault(needle[:_PREFIX], ({}, {}))
                position = _PREFIX
                while len(needle) - position > _PREFIX:
                    node = node[0].setdefault(needle[position:position + _PREFIX], ({}, {}))
                    position += _PREFIX
                _put(node[1].setdefault(len(needle) - position, {}), needle[position:], (mode, payload))
            elif head and mode != "none":
                _put(index.setdefault(head.group(), {}).setdefault(len(needle), {}), needle, (mode, payload))
            else:
                loose.append((needle, mode, payload))
        self.index, self.long, self.loose = index, long, loose

    def extended(self, forms: Iterable[tuple[str, str, T]]) -> Forms[T]:
        """Таблица этих написаний и forms после них — та же, что Forms(прежние + forms), без разбора прежних заново. Эта
        таблица не меняется: узлы, в которые добавляется написание, копируются (другие потоки ищут по ней)."""
        out: Forms[T] = Forms(())
        out.index, out.long, out.loose = dict(self.index), dict(self.long), list(self.loose)
        owned: set[int] = set()

        def own(parent: dict, key: object, make: Callable[[], Any]) -> Any:
            """Узел parent[key] этой таблицы: новый, уже скопированный или копия прежнего."""
            child = parent.get(key)
            if child is not None and id(child) in owned:
                return child
            if child is None:
                child = make()
            elif isinstance(child, tuple):
                child = (dict(child[0]), dict(child[1]))
            else:
                child = child.copy()
            parent[key] = child
            owned.add(id(child))
            return child

        def node() -> _Node[T]:
            return {}, {}

        for form, mode, payload in forms:
            needle = _needle(form)
            if not needle.strip():
                continue
            head = _TOKEN.match(needle)
            if head and mode != "none" and len(needle) > _PREFIX:
                at = own(own(out.long, head.group(), dict), needle[:_PREFIX], node)
                position = _PREFIX
                while len(needle) - position > _PREFIX:
                    at = own(at[0], needle[position:position + _PREFIX], node)
                    position += _PREFIX
                _put(own(at[1], len(needle) - position, dict), needle[position:], (mode, payload))
            elif head and mode != "none":
                _put(own(own(out.index, head.group(), dict), len(needle), dict), needle, (mode, payload))
            else:
                out.loose.append((needle, mode, payload))
        return out

    def find(self, text: str) -> list[tuple[int, int, T]]:
        """То же, что find_forms(text, forms)."""
        return _find(text, self.index, self.long, self.loose)


# Цифровые значения в другой записи (FR-3.4, FR-5.3): «+7 (903) 111-22-33» — это и «9031112233», и «903 111-22-33»;
# «4508 123456» — и «4508123456». Ключ значения — его цифры (resolve.canonical_key), у телефона — и последние десять:
# код страны и «8» вместо «+7» пишут по-разному. Значения короче _DIGITS_MIN цифр по цифрам не ищутся: даты, суммы и
# номера строк складывались бы в них из соседних чисел.
_DIGIT_KEY_TYPES = frozenset({
    EntityType.INN, EntityType.SNILS, EntityType.OGRN, EntityType.KPP, EntityType.OMS, EntityType.CARD,
    EntityType.PASSPORT, EntityType.BANK_ACCOUNT,
})
DIGIT_TYPES = _DIGIT_KEY_TYPES | {EntityType.PHONE}     # типы, у которых бывают ключи digit_keys
_DIGITS_MIN = 9             # КПП — девять цифр, короче цифровых значений нет
_PHONE_TAIL = 10            # номер без кода страны
_HEAD = 3                   # начало ключа, по которому отбрасываются чужие числа (Digits.find)
_NOT_DIGIT = re.compile(r"[^0-9]")
# Цепочка чисел с разделителями записи номера — пробелы, тире, точки, скобки, не больше трёх знаков между числами — и не
# меньше _DIGITS_MIN цифр: каждый повтор берёт одну цифру, и короткие числа (их в журналах большинство) отсеивает
# выражение, а не цикл. Перевод строки цепочку рвёт: числа соседних строк — разные значения.
_DIGIT_SEPARATORS = r"[ \t\u00a0\u2009\u202f.()\-\u2010-\u2015]"
_DIGIT_CHAIN = re.compile(rf"(?<![0-9])[0-9](?:{_DIGIT_SEPARATORS}{{0,3}}[0-9]){{{_DIGITS_MIN - 1},}}")
_DIGIT_RUN = re.compile(r"[0-9]+")
_LATIN = re.compile(r"[A-Za-z]")


def digit_keys(type_: EntityType, form: str) -> tuple[str, ...]:
    """Цифры, по которым написание form значения типа type_ ищется в любой записи (Digits); () — не ищется по цифрам."""
    if type_ is EntityType.PHONE:
        digits = _NOT_DIGIT.sub("", form)
        if len(digits) < _PHONE_TAIL:
            return ()
        tail = digits[-_PHONE_TAIL:]
        keys = {digits, tail}
        if len(digits) == _PHONE_TAIL + 1 and digits[0] in "78":
            keys |= {"7" + tail, "8" + tail}        # «+7 903…» и «8 903…» — один номер
        return tuple(sorted(keys))
    if type_ not in _DIGIT_KEY_TYPES or (type_ is EntityType.BANK_ACCOUNT and _LATIN.search(form)):
        return ()           # IBAN с буквами ищется по написанию
    digits = _NOT_DIGIT.sub("", form)
    return (digits,) if len(digits) >= _DIGITS_MIN else ()


class Digits(Generic[T]):
    """Ключи цифровых значений (digit_keys) -> нагрузка; ищет их в цепочках чисел с разделителями. После сборки не
    меняется — общая для потоков."""

    __slots__ = ("keys", "heads", "longest")

    def __init__(self, keys: dict[str, T]):
        self.keys = keys
        self.heads = frozenset(key[:_HEAD] for key in keys)
        self.longest = max(map(len, keys), default=0)

    def extended(self, keys: dict[str, T]) -> Digits[T]:
        """Таблица с ключами keys поверх этих: нагрузка ключа из keys заменяет прежнюю."""
        if not keys:
            return self
        out: Digits[T] = Digits({})
        out.keys = self.keys | keys
        out.heads = self.heads | {key[:_HEAD] for key in keys}
        out.longest = max(self.longest, max(map(len, keys), default=0))
        return out

    def find(self, text: str, found: Iterable[tuple[int, int]] = ()) -> list[tuple[int, int, T]]:
        """Вхождения ключей: несколько соседних чисел цепочки, цифры которых — ключ, самые длинные слева направо.
        Найденное раньше (found — написания) второй раз не находится. Рядом с вхождением нет букв: «id9031112233» —
        не номер. «+» перед номером и скобка вокруг кода входят во вхождение."""
        if not self.keys:
            return []
        keys, heads, longest = self.keys, self.heads, self.longest
        hits: list[tuple[int, int, T]] = []
        for chain in _DIGIT_CHAIN.finditer(text):
            base, written = chain.start(), chain.group()
            groups = [m.span() for m in _DIGIT_RUN.finditer(written)]
            digits = "".join(written[a:b] for a, b in groups)
            offsets = [0]                   # начало цифр каждого числа цепочки в digits и их конец
            for a, b in groups:
                offsets.append(offsets[-1] + b - a)
            i = 0
            while i < len(groups):
                first, best = offsets[i], -1
                if digits[first:first + _HEAD] in heads:
                    for j in range(i, len(groups)):
                        if offsets[j + 1] - first > longest:
                            break
                        if digits[first:offsets[j + 1]] in keys:
                            best = j
                if best < 0:
                    i += 1
                    continue
                payload = keys[digits[first:offsets[best + 1]]]
                start, end = base + groups[i][0], base + groups[best][1]
                if start and text[start - 1] == "(" and text.count(")", start, end) > text.count("(", start, end):
                    start -= 1
                if start and text[start - 1] == "+":
                    start -= 1
                before = text[start - 1] if start else ""
                after = text[end] if end < len(text) else ""
                if not (before.isalpha() or before == "_" or after.isalpha() or after == "_"):
                    hits.append((start, end, payload))
                i = best + 1
        if not hits:
            return hits
        spans = sorted(found)
        starts = [start for start, _ in spans]
        reach: list[int] = []               # самый дальний конец найденного, начатого не позже каждого
        for _, end in spans:
            reach.append(max(end, reach[-1]) if reach else end)
        outside = []
        for start, end, payload in hits:
            k = bisect.bisect_left(starts, end) - 1
            if k < 0 or reach[k] <= start:
                outside.append((start, end, payload))
        return outside


def find_forms(text: str, forms: Iterable[tuple[str, str, T]]) -> list[tuple[int, int, T]]:
    """Все вхождения написаний без учёта регистра, «ё/е», вида пробелов и формы записи букв; «\\.» и «\\\\.» — точка,
    «\\@» — «@».

    forms — тройки (написание, режим границ, полезная нагрузка). Режимы:
    strict — рядом нет букв, цифр, «_» и «-»; letters — рядом нет букв; none — где угодно.
    Позиции возвращаются в исходном тексте.
    """
    return Forms(forms).find(text)


def _find(
    text: str, index: dict[str, dict[int, dict[str, tuple[tuple[str, T], ...]]]], long: dict[str, dict[str, _Node[T]]],
    loose: list[tuple[str, str, T]],
) -> list[tuple[int, int, T]]:
    if not (index or long or loose):
        return []
    lowered, starts, ends = _normalize(text)
    if "\\." in lowered or "\\@" in lowered:
        lowered, starts, ends = _unescaped(lowered, starts, ends)
    hits: list[tuple[int, int, T]] = []
    for token in _TOKEN.finditer(lowered):
        start = token.start()
        for length, table in index.get(token.group(), {}).items():
            for mode, payload in table.get(lowered[start:start + length], ()):
                if _bounded(lowered, start, start + length, mode):
                    hits.append((starts[start], ends[start + length - 1], payload))
        roots = long.get(token.group())
        node = roots.get(lowered[start:start + _PREFIX]) if roots else None
        position = start + _PREFIX
        while node is not None:
            children, tails = node
            for length, table in tails.items():
                end = position + length
                for mode, payload in table.get(lowered[position:end], ()):
                    if _bounded(lowered, start, end, mode):
                        hits.append((starts[start], ends[end - 1], payload))
            node = children.get(lowered[position:position + _PREFIX]) if children else None
            position += _PREFIX
    for needle, mode, payload in loose:
        position = lowered.find(needle)
        while position != -1:
            end = position + len(needle)
            if _bounded(lowered, position, end, mode):
                hits.append((starts[position], ends[end - 1], payload))
            position = lowered.find(needle, position + 1)
    return hits
