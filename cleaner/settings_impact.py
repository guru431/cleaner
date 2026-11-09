"""Read-only aggregate previews and version-bound application of shared settings."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from contextlib import contextmanager
from dataclasses import asdict, replace

from cleaner.core.pipeline import sanitize
from cleaner.core.detect import dictionary
from cleaner.core.types import EntityType, Policy
from cleaner.eval import runner
from cleaner.service import _cached_layers
from cleaner.storage import crypto, db
from cleaner.storage.db import transaction
from cleaner.storage.repo import Repository

_AAD = "settings-impact"
_UNDO = "settings.impact.undo"
# Счётчики по чужим чатам показываются, только если затронуты чаты не меньше чем трёх других владельцев. Иначе
# оценка одной записи словаря отвечала бы, есть ли строка в текстах конкретного человека (раздел 4 ТЗ): при одном
# или двух владельцах администратор, знающий круг подозреваемых, узнаёт чей текст. Ноль тоже скрыт — иначе
# «скрыто» само означало бы «встречается».
MIN_OWNERS = 3


def snapshot(repo):
    return {"policies": {t.value: p.value for t, p in repo.policies().items()},
            "dictionary": [asdict(row) for row in repo.dictionary()]}


def settings_for(repo, config):
    rows = config["dictionary"]
    return replace(repo.settings(), policies={EntityType(t): Policy(p) for t, p in config["policies"].items()},
                   always=tuple(dictionary.entry(EntityType(r["type"]), r["value"], tuple(r["aliases"]), r.get("inflect", False))
                                for r in rows if r["list"] == "always"),
                   never=frozenset(v.strip().lower() for r in rows if r["list"] == "never" for v in (r["value"], *r["aliases"]) if v.strip()))


def _binding(repo):
    """Подтверждение связано с настройками и эталоном, но не с версиями чатов: каждый ход агента и каждый новый
    текст поднимают версию, и пока кто-то работает, применить было бы нельзя. Тексты, изменённые после оценки,
    в её числах не учтены и очищаются уже по новым настройкам при обычных действиях Cleaner."""
    raw = [snapshot(repo), runner.settings_fingerprint(repo.settings(), repo.global_key),
           runner.fingerprint(runner.gold_examples(repo), repo.global_key), repo.setting("settings.impact.version")]
    return hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()


@contextmanager
def _reading(repo):
    """Согласованный снимок базы отдельным соединением (BEGIN DEFERRED, журнал WAL): пересчёт идёт без общего замка
    и без транзакции записи — сессии, шлюз агентов и задания его не ждут. У базы в памяти второго соединения нет:
    тогда, как прежде, под замком."""
    path = repo._one("PRAGMA database_list")["file"]
    if not path:
        with repo.lock, transaction(repo.conn):
            yield repo
        return
    conn = db.connect(path)
    try:
        conn.execute("BEGIN DEFERRED")
        conn.execute("SELECT COUNT(*) FROM settings").fetchone()       # снимок фиксируется первым чтением
        yield Repository(conn, repo.master, repo.clock)
    finally:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        conn.close()


def changed(repo, operation):
    config = copy.deepcopy(snapshot(repo))
    if operation["kind"] == "policies":
        config["policies"].update(operation["policies"])
    elif operation["kind"] == "add":
        config["dictionary"].extend(operation["rows"])
    elif operation["kind"] == "delete":
        config["dictionary"] = [r for r in config["dictionary"] if r["id"] != operation["id"]]
    elif operation["kind"] == "undo":
        raw = repo.setting(_UNDO)
        if not raw:
            raise ValueError("Предыдущей конфигурации нет")
        config = json.loads(crypto.unseal(repo.global_key, base64.b64decode(raw), _UNDO))
    else:
        raise ValueError("Неизвестная правка настроек")
    return config


def _changes(before, config):
    """События журнала по каждому изменению — с теми же полями, что пишут прямые правки (FR-11.1), без значений.
    Одна добавленная запись — как добавление, несколько — как импорт; несколько удалённых (возврат после импорта) —
    одним событием с числом."""
    events = [("policy_changed", {"type": type_, "policy": policy}) for type_, policy in sorted(config["policies"].items())
              if before["policies"].get(type_) != policy]
    kept, known = {r["id"] for r in config["dictionary"]}, {r["id"] for r in before["dictionary"]}
    for list_ in ("always", "never"):
        removed = sum(1 for r in before["dictionary"] if r["list"] == list_ and r["id"] not in kept)
        added = sum(1 for r in config["dictionary"] if r["list"] == list_ and r["id"] not in known)
        if removed:
            events.append(("dictionary_changed", {"action": "delete", "list": list_} | ({"count": removed} if removed > 1 else {})))
        if added == 1:
            events.append(("dictionary_changed", {"action": "add", "list": list_}))
        elif added:
            events.append(("dictionary_import", {"list": list_, "count": added}))
    return events


def preview(repo, user_id, operation):
    with _reading(repo) as snap:
        before_config = snapshot(snap)
        config = changed(snap, operation)
        before, after = snap.settings(), settings_for(snap, config)
        mine, others = (dict(chats=0, items=0, blocked=0, replacements=0) for _ in range(2))
        owners, pending, frozen = set(), 0, 0
        own = []
        for user in snap.users():
            counts = mine if user.id == user_id else others
            for chat in snap.chats(user.id):
                if chat.kind == "agent":
                    frozen += 1
                    continue
                old, _ = snap.load_state(chat.id)
                new = copy.deepcopy(old)
                touched = False
                on = snap.layer_defaults() | snap.chat_layers(chat.id)
                for item in snap.items(chat.id):
                    if item.kind != "input":
                        continue
                    if item.status != "done":
                        pending += 1
                        continue
                    layers, _ = _cached_layers(item, on)
                    a, b = sanitize(old, item.original, before, layers), sanitize(new, item.original, after, layers)
                    if (a.sanitized, bool(a.blocked), bool(a.blocked_surrogates)) != (b.sanitized, bool(b.blocked), bool(b.blocked_surrogates)):
                        touched = True
                        counts["items"] += 1
                        counts["blocked"] += bool(b.blocked or b.blocked_surrogates) and not bool(a.blocked or a.blocked_surrogates)
                        counts["replacements"] += len(b.spans) - len(a.spans)
                        if user.id == user_id and len(own) < 10:
                            own.append({"before": a.sanitized, "after": b.sanitized})
                counts["chats"] += touched
                if touched and user.id != user_id:
                    owners.add(user.id)
        examples = runner.gold_examples(snap)
        old = runner.run(examples, before, ["1-3"], None)["1-3"]
        new = runner.run(examples, after, ["1-3"], None)["1-3"]
        quality = [{"title": title, "before": runner.share(*old.classes.get(title, (0, 0))),
                    "after": runner.share(*new.classes.get(title, (0, 0)))} for title in set(old.classes) | set(new.classes)]
        binding = _binding(snap)
    # Оценка — в журнал (раздел 4 ТЗ, FR-11.2): вид правки и числа, без значений словаря.
    was, will = {r["id"] for r in before_config["dictionary"]}, {r["id"] for r in config["dictionary"]}
    repo.audit("settings_previewed", user_id, kind=operation["kind"],
               policies=sum(event == "policy_changed" for event, _ in _changes(before_config, config)),
               added=sum(1 for r in config["dictionary"] if r["id"] not in was),
               removed=sum(1 for r in before_config["dictionary"] if r["id"] not in will))
    payload = {"user": user_id, "expires": repo.clock.now().timestamp() + 600, "binding": binding, "config": config}
    receipt = base64.urlsafe_b64encode(crypto.seal(repo.global_key, json.dumps(payload).encode(), _AAD)).decode()
    shown = len(owners) >= MIN_OWNERS
    return {"mine": mine, "others": others if shown else None, "owners": len(owners) if shown else None,
            "min_owners": MIN_OWNERS, "pending": pending, "frozen": frozen, "own": own, "quality": quality,
            "receipt": receipt}


def apply(repo, user_id, receipt):
    try:
        payload = json.loads(crypto.unseal(repo.global_key, base64.b64decode(receipt, altchars=b"-_", validate=True), _AAD))
    except (ValueError, crypto.CryptoError):
        raise ValueError("Предпросмотр недействителен") from None
    with repo.lock, transaction(repo.conn):
        if payload["user"] != user_id or payload["expires"] <= repo.clock.now().timestamp() or payload["binding"] != _binding(repo):
            raise ValueError("Настройки изменились: оцените влияние ещё раз")
        current = snapshot(repo)
        previous = base64.b64encode(crypto.seal(repo.global_key, json.dumps(current).encode(), _UNDO)).decode()
        repo.set_setting(_UNDO, previous)
        repo.set_setting("settings.impact.version", str(int(repo.setting("settings.impact.version") or "0") + 1))
        repo.conn.execute("DELETE FROM policies")
        for type_, policy in payload["config"]["policies"].items():
            repo.set_policy(EntityType(type_), Policy(policy))
        current_ids = {row.id for row in repo.dictionary()}
        wanted_rows = payload["config"]["dictionary"]
        wanted_ids = {row["id"] for row in wanted_rows}
        for entry_id in current_ids - wanted_ids:
            repo.delete_dictionary(entry_id)
        for row in wanted_rows:
            if row["id"] in current_ids:
                continue
            repo._insert_dictionary(row["list"], row["value"], EntityType(row["type"]) if row["type"] else None,
                                    tuple(row["aliases"]), row["comment"], row.get("inflect", False))
        for event, details in _changes(current, payload["config"]):
            repo.audit(event, user_id, **details)
        repo.audit("settings_changed", user_id, section="shared", action="preview_applied")
