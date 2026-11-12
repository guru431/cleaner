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
    """Политики и словарь в виде JSON: типы — строками, варианты — списками, как после квитанции."""
    return json.loads(json.dumps({"policies": {t.value: p.value for t, p in repo.policies().items()},
                                  "dictionary": [asdict(row) for row in repo.dictionary()]}))


def _fields(row):
    """Изменяемые поля записи словаря — то, что меняет правка записи."""
    return list(row["aliases"]), row["comment"], bool(row.get("inflect", False))


def listed(before, config):
    """Изменения конфигурации по спискам: удаляемые и добавляемые записи, изменяемые записи (было, станет) и
    изменяемые политики (тип, было, станет). Значения словаря — для страницы оценки администратора, не для журнала."""
    was = {r["id"]: r for r in before["dictionary"]}
    will = {r["id"] for r in config["dictionary"]}
    return {"removed": [r for r in before["dictionary"] if r["id"] not in will],
            "added": [r for r in config["dictionary"] if r["id"] not in was],
            "edited": [(was[r["id"]], r) for r in config["dictionary"]
                       if r["id"] in was and _fields(r) != _fields(was[r["id"]])],
            "policies": [(t, before["policies"].get(t), p) for t, p in sorted(config["policies"].items())
                         if before["policies"].get(t) != p]}


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
    тогда, как прежде, под замком. Пока снимок открыт, удаление чата не ждёт его, а усечение журнала WAL выполняется
    при его закрытии (Repository.reading)."""
    path = repo._one("PRAGMA database_list")["file"]
    if not path:
        with repo.lock, transaction(repo.conn):
            yield repo
        return
    with repo.reading():
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
    elif operation["kind"] == "edit":
        row = operation["row"]
        if not any(r["id"] == row["id"] for r in config["dictionary"]):
            raise ValueError("Запись не найдена")
        config["dictionary"] = [row if r["id"] == row["id"] else r for r in config["dictionary"]]
    elif operation["kind"] == "undo":
        raw = repo.setting(_UNDO)
        if not raw:
            raise ValueError("Предыдущей конфигурации нет")
        undo = json.loads(crypto.unseal(repo.global_key, base64.b64decode(raw), _UNDO))
        if "dictionary" in undo:            # снимок прежнего вида (до 12.11.2026) — конфигурация целиком
            return undo
        # Обратная правка последнего применения: записи, добавленные потом мимо оценки (экран проверки, ручное
        # добавление, импорт), и политики, изменённые потом, остаются. Возвращённая запись, значение которой уже снова
        # есть в том же списке, не дублируется.
        added = set(undo["added"])
        config["dictionary"] = [r for r in config["dictionary"] if r["id"] not in added]
        present = {(r["list"], r["value"].lower()) for r in config["dictionary"]}
        config["dictionary"].extend(r for r in undo["removed"] if (r["list"], r["value"].lower()) not in present)
        former = {r["id"]: r for r in undo.get("edited", ())}
        config["dictionary"] = [former.get(r["id"], r) for r in config["dictionary"]]
        for type_, (was, applied) in undo["policies"].items():
            if config["policies"].get(type_) == applied:
                config["policies"][type_] = was
    else:
        raise ValueError("Неизвестная правка настроек")
    return config


def _changes(before, config, imported=False):
    """События журнала по каждому изменению — с теми же полями, что пишут прямые правки (FR-11.1), без значений.
    imported — правка из импорта CSV (признак import операции): добавленные — как импорт, при любом их числе;
    иначе — как добавление. Несколько добавленных, удалённых или изменённых (возврат) — одним событием с числом."""
    events = [("policy_changed", {"type": type_, "policy": policy}) for type_, policy in sorted(config["policies"].items())
              if before["policies"].get(type_) != policy]
    kept, known = {r["id"] for r in config["dictionary"]}, {r["id"] for r in before["dictionary"]}
    changed_rows = listed(before, config)["edited"]
    for list_ in ("always", "never"):
        removed = sum(1 for r in before["dictionary"] if r["list"] == list_ and r["id"] not in kept)
        added = sum(1 for r in config["dictionary"] if r["list"] == list_ and r["id"] not in known)
        edited = sum(1 for was, _ in changed_rows if was["list"] == list_)
        if edited:
            events.append(("dictionary_changed", {"action": "edit", "list": list_} | ({"count": edited} if edited > 1 else {})))
        if removed:
            events.append(("dictionary_changed", {"action": "delete", "list": list_} | ({"count": removed} if removed > 1 else {})))
        if added and imported:
            events.append(("dictionary_import", {"list": list_, "count": added}))
        elif added:
            events.append(("dictionary_changed", {"action": "add", "list": list_} | ({"count": added} if added > 1 else {})))
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
    repo.audit("settings_previewed", user_id, kind="import" if operation.get("import") else operation["kind"],
               policies=sum(event == "policy_changed" for event, _ in _changes(before_config, config)),
               added=sum(1 for r in config["dictionary"] if r["id"] not in was),
               removed=sum(1 for r in before_config["dictionary"] if r["id"] not in will),
               edited=len(listed(before_config, config)["edited"]))
    payload = {"user": user_id, "expires": repo.clock.now().timestamp() + 600, "binding": binding, "config": config,
               "import": bool(operation.get("import"))}
    receipt = base64.urlsafe_b64encode(crypto.seal(repo.global_key, json.dumps(payload).encode(), _AAD)).decode()
    shown = len(owners) >= MIN_OWNERS
    return {"mine": mine, "others": others if shown else None, "owners": len(owners) if shown else None,
            "min_owners": MIN_OWNERS, "pending": pending, "frozen": frozen, "own": own, "quality": quality,
            "receipt": receipt, "kind": operation["kind"], "changes": listed(before_config, config)}


def apply(repo, user_id, receipt):
    try:
        payload = json.loads(crypto.unseal(repo.global_key, base64.b64decode(receipt, altchars=b"-_", validate=True), _AAD))
    except (ValueError, crypto.CryptoError):
        raise ValueError("Предпросмотр недействителен") from None
    with repo.lock, transaction(repo.conn):
        if payload["user"] != user_id or payload["expires"] <= repo.clock.now().timestamp() or payload["binding"] != _binding(repo):
            raise ValueError("Настройки изменились: оцените влияние ещё раз")
        current = snapshot(repo)
        changes = listed(current, payload["config"])
        repo.set_setting("settings.impact.version", str(int(repo.setting("settings.impact.version") or "0") + 1))
        repo.conn.execute("DELETE FROM policies")
        for type_, policy in payload["config"]["policies"].items():
            repo.set_policy(EntityType(type_), Policy(policy))
        for row in changes["removed"]:
            repo.delete_dictionary(row["id"])
        added = [repo._insert_dictionary(row["list"], row["value"], EntityType(row["type"]) if row["type"] else None,
                                         tuple(row["aliases"]), row["comment"], row.get("inflect", False))
                 for row in changes["added"]]
        for _, row in changes["edited"]:
            repo.update_dictionary(row["id"], tuple(row["aliases"]), row["comment"], row.get("inflect", False))
        # Для возврата хранится обратная правка этого применения, а не прежняя конфигурация целиком: иначе возврат
        # молча удалял бы записи, добавленные после применения мимо оценки.
        undo = {"added": added, "removed": changes["removed"], "edited": [was for was, _ in changes["edited"]],
                "policies": {type_: [was, policy] for type_, was, policy in changes["policies"]}}
        repo.set_setting(_UNDO, base64.b64encode(crypto.seal(repo.global_key, json.dumps(undo).encode(), _UNDO)).decode())
        for event, details in _changes(current, payload["config"], payload.get("import", False)):
            repo.audit(event, user_id, **details)
        repo.audit("settings_changed", user_id, section="shared", action="preview_applied")
