"""Открытые русские наборы для сравнения (QA-4) в формат eval: {"text", "spans": [{start, end, type, entity}]}.

Снимок набора — файл JSONL и манифест рядом (<имя>.manifest.json): источник, ревизия, sha256 файла, версия
конвертера, число примеров. Повторная загрузка не подменяет принятый снимок незаметно: прежний сохраняется рядом
под именем с началом своего sha256 (write_snapshot)."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from cleaner.core.detect.merge import NAME_WORDS, adjacent_name_parts
from cleaner.core.detect.ner import ADDRESS_GAP, ADDRESS_GAP_MAX

# Версия преобразования разметки: другой номер — другие сущности, и замер с прежним несопоставим.
# 1 — каждое упоминание отдельной сущностью; 2 — одинаковое значение одного типа в примере — одна сущность (QA-2).
# Правила 25.10.2026 (I-метка после O начинает новый фрагмент, части имени через точку сводятся только после инициала)
# номер не меняют: снимки всех трёх наборов с ними совпали байт в байт. 3 — ряд частей имени длиннее NAME_WORDS слов —
# список людей, как в слое 4 (ревью 26.10.2026): в pii_benchmark так разошёлся один пример из 2139, hivetrace и jayguard
# совпали байт в байт.
CONVERTER = 3

# Метка набора -> тип ТЗ или часть: person — часть имени, street — улица, дом или весь адрес, place — город, регион, страна.
LABELS = {
    "FIRST_NAME": "person", "LAST_NAME": "person", "MIDDLE_NAME": "person", "PERSON": "person", "PER": "person", "NAME": "person",
    "ORG": "ORG", "ORGANIZATION": "ORG",
    "ADDRESS": "street", "STREET_ADDRESS": "street", "STREET": "street", "HOUSE": "street",
    "CITY": "place", "COUNTRY": "place", "REGION": "place", "DISTRICT": "place", "GPE": "place", "LOC": "place",
    "LOCATION": "place",
    "EMAIL": "EMAIL", "PHONE": "PHONE", "PHONE_NUMBER": "PHONE", "INN": "INN", "SNILS": "SNILS", "OMS": "OMS",
    "PASSPORT": "PASSPORT", "DRIVER_LICENSE": "PASSPORT", "MILITARY_ID": "PASSPORT", "BIRTH_CERTIFICATE": "PASSPORT",
    "PASSPORT_NUMBER": "PASSPORT", "KPP": "KPP", "OGRN": "OGRN", "OGRNIP": "OGRN",
    "CREDIT_CARD": "CARD", "CARD": "CARD", "BANK_CARD_NUMBER": "CARD", "IP_ADDRESS": "IP", "IP": "IP",
    # Токен — секрет по FR-4.1. Адрес целиком и CVC типа в ТЗ не имеют и не измеряются.
    "TOKEN": "SECRET",
}


def bio_to_spans(
    tokens: Sequence[str], tags: Sequence[str], text: str | None = None,
) -> tuple[str, list[tuple[int, int, str]]] | None:
    """Токены с метками BIO -> (текст, [(начало, конец, метка)]). Без текста он собирается через пробел. I-метка
    продолжает только фрагмент предыдущего токена; после O или другой метки она начинает новый, как в conlleval: иначе
    «Иванов/I-PER и/O Петров/I-PER» было бы одним человеком вместе с «и» (ревью 24.10.2026)."""
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
    inside = None                   # метка фрагмента, которым кончился предыдущий токен
    for (start, end), tag in zip(offsets, tags):
        if tag == "O" or "-" not in tag:
            inside = None
            continue
        prefix, label = tag.split("-", 1)
        if prefix == "I" and inside == label:
            spans[-1][1] = end
        else:
            spans.append([start, end, label])
        inside = label
    return text, [(start, end, label) for start, end, label in spans]


def convert(text: str, spans: Sequence[tuple[int, int, str]], unmapped: Counter) -> dict:
    """Части имени рядом — один фрагмент PERSON; части адреса — один ADDRESS, если есть улица или дом (как слой 4).
    Имя, как в слое 4 (merge._join_names), — не длиннее NAME_WORDS слов: ряд длиннее — список людей, части врозь.

    Упоминания одного значения одного типа в разных местах примера — одна сущность: по QA-2 она защищена, только
    если скрыты все. Значение сравнивается без учёта регистра и пробелов; разные формы имени («Иванов», «Иванову»)
    остаются разными сущностями — у открытых наборов нет разметки, что это один человек."""
    unmapped.update(label for _, _, label in spans if label not in LABELS)
    items = sorted((start, end, LABELS[label]) for start, end, label in spans if label in LABELS)
    groups: list[list] = []                          # [начало, конец, вид, есть ли улица или дом]
    run: list[tuple[int, int]] = []                  # части ряда имени, которым кончается groups
    words, listed = 0, False                         # слов в ряду; ряд длиннее имени — его части в groups по отдельности
    for start, end, kind in items:
        last = groups[-1] if groups else None
        gap = text[last[1]:start] if last else ""
        count = max(1, len(text[start:end].split()))
        if (
            kind == "person" and last is not None and last[2] == "person"
            and adjacent_name_parts(text, last[0], last[1], start)
        ):
            run.append((start, end))
            words += count
            if listed:
                groups.append([start, end, kind, False])
            elif words <= NAME_WORDS:
                last[1] = max(last[1], end)
            else:
                listed = True
                groups[-1:] = [[s, e, kind, False] for s, e in run]
            continue
        if kind == "person":
            run, words, listed = [(start, end)], count, False
        joinable = (
            last is not None and kind in ("street", "place") and last[2] in ("street", "place")
            and len(gap) <= ADDRESS_GAP_MAX and ADDRESS_GAP.fullmatch(gap)
        )
        if joinable:
            last[1] = max(last[1], end)
            last[3] = last[3] or kind == "street"
        else:
            groups.append([start, end, kind, kind == "street"])
    out: list[dict] = []
    entities: dict[tuple[str, str], int] = {}
    for start, end, kind, has_street in groups:
        if kind in ("street", "place") and not has_street:
            continue                                  # город или страна сами по себе адресом не считаются
        type_ = "PERSON" if kind == "person" else "ADDRESS" if kind in ("street", "place") else kind
        entity = entities.setdefault((type_, " ".join(text[start:end].split()).casefold()), len(entities))
        out.append({"start": start, "end": end, "type": type_, "entity": entity})
    return {"text": text, "spans": out}


def manifest_path(path: Path) -> Path:
    return path.with_name(path.stem + ".manifest.json")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_snapshot(out: Path, name: str, records: Sequence[dict], source: str, revision: str, pinned: bool) -> Path:
    """Примеры с разметкой — в <имя>.jsonl с манифестом. Если там уже другой снимок, он переносится рядом
    (<имя>-<начало его sha256>.jsonl, с манифестом, если он был): основное имя — у нового снимка, иначе снимок до
    манифестов или прежнего конвертера оставался по пути, который документирован, и проверка отправляла скачивать
    заново по кругу. Базовый замер привязан к отпечатку набора: сравнение с новым снимком скажет, что набор другой."""
    kept = [record for record in records if record["spans"]]
    data = "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in kept).encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    path = out / f"{name}.jsonl"
    if path.exists() and (previous := file_sha256(path)) != digest:
        moved = out / f"{name}-{previous[:12]}.jsonl"
        path.replace(moved)
        if manifest_path(path).exists():
            manifest_path(path).replace(manifest_path(moved))
    path.write_bytes(data)
    manifest = {
        "name": name, "source": source, "revision": revision, "pinned": pinned, "sha256": digest,
        "converter": CONVERTER, "examples": len(kept),
    }
    manifest_path(path).write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def check_snapshot(path: Path, *, sha256: str | None = None) -> tuple[str, dict | None, list[str]]:
    """Имя набора (для базового замера и паспорта), манифест и расхождения снимка с ним."""
    try:
        manifest = json.loads(manifest_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = None
    if not isinstance(manifest, dict):
        return path.stem, None, ["нет манифеста: источник, ревизия и версия конвертера неизвестны"]
    problems = []
    if manifest.get("sha256") != (file_sha256(path) if sha256 is None else sha256):
        problems.append("файл не совпадает с манифестом (sha256): снимок изменён после загрузки")
    if manifest.get("converter") != CONVERTER:
        problems.append(
            f"снимок собран конвертером версии {manifest.get('converter')}, нынешняя — {CONVERTER}: "
            "скачайте наборы заново (scripts/fetch_open_sets.py)"
        )
    return str(manifest.get("name") or path.stem), manifest, problems


def read_snapshot(path: Path) -> tuple[str, bytes, dict]:
    """Контрольная сумма и разметка получаются из одних прочитанных байтов."""
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    name, manifest, problems = check_snapshot(path, sha256=digest)
    if manifest is None:
        status = "missing"
    elif manifest.get("sha256") != digest:
        status = "mismatch"
    else:
        status = "match"
    source = (manifest or {}) | {"sha256": digest, "manifest_status": status, "warnings": problems}
    return name, data, source
