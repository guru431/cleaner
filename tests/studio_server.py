"""Loopback-only Cleaner for Studio's cross-repository contract test; all data is synthetic."""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn
import httpx

from cleaner.clock import SystemClock
from cleaner.storage import crypto, db
from cleaner.storage.repo import Provider, Repository
from cleaner.web import auth
from cleaner.web.app import create_app
from cleaner.engines import Engines, GATEWAY_KEY_ENV

KEY = "ck_" + "A" * 43
CANARY = "ivan@contoso.ru"


def main():
    root, port = Path(sys.argv[1]), int(sys.argv[2])
    connection = db.connect(root / "cleaner.db")
    db.migrate(connection)
    clock = SystemClock()
    repo = Repository(connection, crypto.new_key(), clock)
    user = repo.create_user("fixture", "unused-synthetic-hash", "user")
    provider = repo.add_provider(Provider("", "Fixture", "openai", "https://provider.invalid/v1", "bearer",
                                         "synthetic-provider-key", ("protected-model",)))
    repo.add_api_key(user, "Studio fixture", auth.token_hash(KEY), KEY[-4:], upstream=f"provider:{provider}")
    repo.set_layer_defaults({"ner": False, "llm": False})

    def cloud(context, *args, **kwargs):
        assert CANARY not in "\n".join(context.texts()), "uncleaned request reached the provider boundary"
        yield "Ответ <EMAIL_1>. "
        yield "[Внешняя ссылка](https://external.example/?v=<EMAIL_1>)"

    def local(request):
        assert request.url.host == "127.0.0.1"
        assert CANARY in request.content.decode()
        event = {"choices": [{"delta": {"content": f"Локально: {CANARY}"}}]}
        return httpx.Response(200, text="data: " + json.dumps(event) + "\n\ndata: [DONE]\n\n")

    engines = Engines(repo, root / "models", environ={GATEWAY_KEY_ENV: "synthetic-local-key"}, transport=httpx.MockTransport(local))
    app = create_app(repo, clock, secure_cookies=False, cloud_send=cloud, engines=engines)
    tls = {"ssl_certfile": sys.argv[3], "ssl_keyfile": sys.argv[4]} if len(sys.argv) == 5 else {}
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error", access_log=False, **tls)


if __name__ == "__main__":
    main()
