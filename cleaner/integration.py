"""Text requests from applications: explicit preview, single-use receipt and browser-safe answers.

The client owns its history. Cleaner keeps the context's encrypted replacement table; the preview
receipt carries the history encrypted with that context's key and expires after ten minutes.
Sending uses the ordinary pipeline and egress, never the agent gateway's terminal restoration.
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from collections import Counter
from dataclasses import asdict

from cleaner.core.pipeline import Layers, Turn, build_outgoing, sanitize
from cleaner.core.entities import ops
from cleaner.core.types import EntityType, Span
from cleaner.service import ChatService, SendRefused, _stricter, admitted, link
from cleaner.storage import crypto
from cleaner.storage.repo import Item

RECEIPT_SECONDS = 600


def provider_for(repo, key, model: str | None = None):
    access = key.upstream or ""
    provider = repo.provider(access.removeprefix("provider:")) if access.startswith("provider:") else None
    if provider is None or not provider.enabled:
        raise SendRefused("Для подключения Studio нужен ключ Cleaner с доступом к облачному подключению")
    models = tuple(m for m in provider.models if not key.models or m in key.models)
    if model is not None and model not in models:
        raise SendRefused("Модель недоступна этому ключу Cleaner")
    return provider, models


def _binding(provider) -> str:
    # A provider edit, including credential rotation, invalidates an already shown preview.
    return hashlib.sha256(json.dumps(asdict(provider), sort_keys=True, default=str).encode()).hexdigest()


class IntegrationService(ChatService):
    """Shares ChatService's repository, engines, admission and send pool (created with from_service)."""

    @classmethod
    def from_service(cls, service: ChatService):
        result = object.__new__(cls)
        result.__dict__ = service.__dict__
        return result

    def _build_request(self, state, settings, messages, provider, model, layers, cached=None):
        turns, models, replacements = [], [], []
        blocked = 0
        for number, message in enumerate(messages):
            found = None if cached is None else tuple(
                Span(**(span | {"type": EntityType(span["type"])})) for span in cached[number]
            )
            result = sanitize(state, message["content"], settings, layers if found is None else Layers(cached=found))
            models.append([asdict(span) for span in result.model_spans])
            blocked += len(result.blocked) + len(result.blocked_surrogates)
            replacements.extend({
                "message": number, "start": span.start, "end": span.end,
                "type": state.entities[span.entity_id].type.value, "replacement": span.surrogate,
            } for span in result.spans)
            turns.append(Turn(message["role"],
                              result.sanitized if message["role"] == "assistant" else message["content"],
                              tuple(result.model_spans)))
        outgoing = build_outgoing(state, turns, settings, provider.id, model)
        outgoing.blocked = max(outgoing.blocked, blocked)
        return outgoing, models, replacements

    @admitted("text")
    def prepare_request(self, chat_id: str, user_id: str, key, model: str, messages: list[dict], rules=()):
        self._check_length("".join(message["content"] for message in messages))
        provider, _ = provider_for(self.repo, key, model)
        layers, ran = self._live_layers(chat_id)
        prepared = {}

        def work(state, items, settings):
            cache = None
            if rules:
                # Discover strict policies before accepting a manual enclosing replacement.
                _, cache, _ = self._build_request(state, settings, messages, provider, model, layers)
            for rule in rules:
                if not any(rule["value"] in message["content"] for message in messages):
                    raise SendRefused("Фрагмента для правки нет в текущем запросе")
                if rule["action"] == "mask":
                    wanted = EntityType(rule["type"] or "TERM")
                    if any(_stricter(settings, entity.type, wanted) and any(
                        form.lower() in rule["value"].lower() or rule["value"].lower() in form.lower()
                        for form in entity.forms
                    ) for entity in state.entities.values()):
                        raise SendRefused("Правка ослабляет политику найденного типа: выберите более строгий тип")
                    ops.mask(state, rule["value"], wanted)
                else:
                    ops.unmask(state, rule["value"])
            outgoing, cached, replacements = self._build_request(state, settings, messages, provider, model, layers, cache)
            prepared.update(outgoing=outgoing, cached=cached, replacements=replacements)
            return [], []

        version = []
        self._apply(chat_id, work, after=version.append)
        outgoing = prepared["outgoing"]
        payload = {
            "key": key.id, "version": version[0], "expires": self.repo.clock.now().timestamp() + RECEIPT_SECONDS,
            "provider": _binding(provider), "model": model, "messages": messages,
            "cached": prepared["cached"], "digest": outgoing.context.digest(), "layers": self.layers(chat_id),
        }
        receipt = base64.urlsafe_b64encode(crypto.seal(
            self.repo.chat_secret(chat_id), json.dumps(payload, ensure_ascii=False).encode(), f"request:{chat_id}",
        )).decode()
        self.repo.audit("request_prepared", user_id, chat_id, messages=len(messages), layers=ran)
        return {
            "receipt": receipt, "deliverable": outgoing.sendable, "digest": outgoing.context.digest(),
            "messages": ([{"role": "system", "content": outgoing.context.system}] + [
                {"role": message.role, "content": message.text} for message in outgoing.context.messages
            ]) if outgoing.sendable else [],
            "replacements": prepared["replacements"],
            "counts": dict(Counter(row["type"] for row in prepared["replacements"])),
            "leaks": len(outgoing.leaks), "blocked": outgoing.blocked,
        }

    @admitted("send")
    def send_request(self, chat_id: str, user_id: str, key, receipt: str):
        try:
            payload = json.loads(crypto.unseal(
                self.repo.chat_secret(chat_id), base64.b64decode(receipt, altchars=b"-_", validate=True),
                f"request:{chat_id}",
            ))
        except (ValueError, crypto.CryptoError):
            raise SendRefused("Предпросмотр недействителен: проверьте запрос ещё раз") from None
        if payload["key"] != key.id or payload["expires"] <= self.repo.clock.now().timestamp():
            raise SendRefused("Предпросмотр истёк: проверьте запрос ещё раз")
        provider, _ = provider_for(self.repo, key, payload["model"])
        if payload["provider"] != _binding(provider) or payload["layers"] != self.layers(chat_id):
            raise SendRefused("Подключение или слои изменились: проверьте запрос ещё раз")
        built = {}

        def work(state, items, settings):
            if any(item.kind == "answer" and item.status in ("running", "queued") for item in items):
                raise SendRefused("Предыдущий ответ ещё идёт")
            outgoing, _, replacements = self._build_request(
                state, settings, payload["messages"], provider, payload["model"], Layers(), payload["cached"],
            )
            if outgoing.context.digest() != payload["digest"] or not outgoing.sendable:
                raise SendRefused("Запрос изменился или заблокирован: проверьте его ещё раз")
            built.update(context=outgoing.context, count=len(replacements))
            return [Item(uuid.uuid4().hex, 0, "answer", "", None, source="api", status="running",
                         meta={"provider": provider.name, "model": payload["model"], "in_request": len(replacements)})], []

        [item] = self._apply(chat_id, work, expected=payload["version"])
        self.live.start(item.id)
        self._submit(self.send_submit, self.run_send, chat_id, item.id, user_id,
                     built["context"], link(provider), built["count"])
        self.repo.audit("cloud_send", user_id, chat_id, provider=provider.id, model=payload["model"],
                        messages=len(built["context"].messages))
        return item
