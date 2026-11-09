"""Read-only aggregate previews and version-bound application of shared settings."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import asdict, replace

from cleaner.core.pipeline import sanitize
from cleaner.core.detect import dictionary
from cleaner.core.types import EntityType, Policy
from cleaner.eval import runner
from cleaner.service import _cached_layers
from cleaner.storage import crypto
from cleaner.storage.db import transaction

_AAD = "settings-impact"
_UNDO = "settings.impact.undo"


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
    chats = [tuple(row) for row in repo._all("SELECT id, version FROM chats ORDER BY id")]
    raw = [snapshot(repo), chats, runner.settings_fingerprint(repo.settings(), repo.global_key),
           runner.fingerprint(runner.gold_examples(repo), repo.global_key), repo.setting("settings.impact.version")]
    return hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()


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


def preview(repo, user_id, operation):
    with repo.lock, transaction(repo.conn):
        config = changed(repo, operation)
        before, after = repo.settings(), settings_for(repo, config)
        counts = dict(chats=0, items=0, blocked=0, replacements=0, pending=0, frozen=0)
        own = []
        for user in repo.users():
            for chat in repo.chats(user.id):
                if chat.kind == "agent":
                    counts["frozen"] += 1
                    continue
                old, _ = repo.load_state(chat.id)
                new = copy.deepcopy(old)
                touched = False
                on = repo.layer_defaults() | repo.chat_layers(chat.id)
                for item in repo.items(chat.id):
                    if item.kind != "input":
                        continue
                    if item.status != "done":
                        counts["pending"] += 1
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
        examples = runner.gold_examples(repo)
        old = runner.run(examples, before, ["1-3"], None)["1-3"]
        new = runner.run(examples, after, ["1-3"], None)["1-3"]
        quality = [{"title": title, "before": runner.share(*old.classes.get(title, (0, 0))),
                    "after": runner.share(*new.classes.get(title, (0, 0)))} for title in set(old.classes) | set(new.classes)]
        payload = {"user": user_id, "expires": repo.clock.now().timestamp() + 600, "binding": _binding(repo), "config": config}
        receipt = base64.urlsafe_b64encode(crypto.seal(repo.global_key, json.dumps(payload).encode(), _AAD)).decode()
        return {"counts": counts, "own": own, "quality": quality, "receipt": receipt}


def apply(repo, user_id, receipt):
    try:
        payload = json.loads(crypto.unseal(repo.global_key, base64.b64decode(receipt, altchars=b"-_", validate=True), _AAD))
    except (ValueError, crypto.CryptoError):
        raise ValueError("Предпросмотр недействителен") from None
    with repo.lock, transaction(repo.conn):
        if payload["user"] != user_id or payload["expires"] <= repo.clock.now().timestamp() or payload["binding"] != _binding(repo):
            raise ValueError("Настройки или чаты изменились: оцените влияние ещё раз")
        previous = base64.b64encode(crypto.seal(repo.global_key, json.dumps(snapshot(repo)).encode(), _UNDO)).decode()
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
        repo.audit("settings_changed", user_id, section="shared", action="preview_applied")
