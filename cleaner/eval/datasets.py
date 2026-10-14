"""Открытые русские наборы для сравнения (QA-4) в формат eval: {"text", "spans": [{start, end, type, entity}]}."""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence

from cleaner.core.detect.ner import ADDRESS_GAP

# Метка набора -> тип ТЗ или часть: person — часть имени, street — улица, дом или весь адрес, place — город, регион, страна.
LABELS = {
    "FIRST_NAME": "person", "LAST_NAME": "person", "MIDDLE_NAME": "person", "PERSON": "person", "PER": "person", "NAME": "person",
    "ORG": "ORG", "ORGANIZATION": "ORG",
    "ADDRESS": "street", "STREET_ADDRESS": "street", "STREET": "street", "HOUSE": "street",
    "CITY": "place", "COUNTRY": "place", "REGION": "place", "DISTRICT": "place", "GPE": "place", "LOC": "place",
    "LOCATION": "place",
    "EMAIL": "EMAIL", "PHONE": "PHONE", "PHONE_NUMBER": "PHONE", "INN": "INN", "SNILS": "SNILS", "OMS": "OMS",
    "PASSPORT": "PASSPORT", "DRIVER_LICENSE": "PASSPORT", "MILITARY_ID": "PASSPORT", "BIRTH_CERTIFICATE": "PASSPORT",
    "CREDIT_CARD": "CARD", "CARD": "CARD", "IP_ADDRESS": "IP", "IP": "IP",
}
_NAME_GAP = re.compile(r"[ \t]+|\.[ \t]*")


def bio_to_spans(
    tokens: Sequence[str], tags: Sequence[str], text: str | None = None,
) -> tuple[str, list[tuple[int, int, str]]] | None:
    """Токены с метками BIO -> (текст, [(начало, конец, метка)]). Без текста он собирается через пробел."""
    offsets: list[tuple[int, int]] = []
    if text is None:
        position = 0
        for token in tokens:
            offsets.append((position, position + len(token)))
            position += len(token) + 1
        text = " ".join(tokens)
    else:
        lowered, position = text.lower(), 0
        for token in tokens:
            found = lowered.find(token.lower(), position)
            if found < 0:
                return None
            offsets.append((found, found + len(token)))
            position = found + len(token)
    spans: list[list] = []
    for (start, end), tag in zip(offsets, tags):
        if tag == "O" or "-" not in tag:
            continue
        prefix, label = tag.split("-", 1)
        if prefix == "I" and spans and spans[-1][2] == label and spans[-1][1] <= start:
            spans[-1][1] = end
        else:
            spans.append([start, end, label])
    return text, [(start, end, label) for start, end, label in spans]


def convert(text: str, spans: Sequence[tuple[int, int, str]], unmapped: Counter) -> dict:
    """Части имени рядом — одна сущность PERSON; части адреса — один ADDRESS, если есть улица или дом (как слой 4)."""
    unmapped.update(label for _, _, label in spans if label not in LABELS)
    items = sorted((start, end, LABELS[label]) for start, end, label in spans if label in LABELS)
    groups: list[list] = []                          # [начало, конец, вид, есть ли улица или дом]
    for start, end, kind in items:
        last = groups[-1] if groups else None
        gap = text[last[1]:start] if last else ""
        joinable = last is not None and (
            (kind == "person" == last[2] and (not gap or _NAME_GAP.fullmatch(gap)))
            or (kind in ("street", "place") and last[2] in ("street", "place") and len(gap) <= 40 and ADDRESS_GAP.fullmatch(gap))
        )
        if joinable:
            last[1] = max(last[1], end)
            last[3] = last[3] or kind == "street"
        else:
            groups.append([start, end, kind, kind == "street"])
    out = []
    for start, end, kind, has_street in groups:
        if kind in ("street", "place") and not has_street:
            continue                                  # город или страна сами по себе адресом не считаются
        type_ = "PERSON" if kind == "person" else "ADDRESS" if kind in ("street", "place") else kind
        out.append({"start": start, "end": end, "type": type_, "entity": len(out)})
    return {"text": text, "spans": out}
