# Заголовки запросов по подписке

Заголовки запросов Claude Code и Codex с входом владельца (подписки Claude и ChatGPT), направленных на заглушку
`scripts/agent_capture.py --headers-only` (план 5В, задача 1, шаг 4). Тела не записывались: в них личные инструкции
профиля. Файлы входа агентов (`~/.claude/.credentials.json`, `~/.codex/auth.json`) не копировались и не читались.

- Claude Code 2.1.270, настоящий профиль, вымышленный репозиторий с `.claude/settings.local.json`:
  `ANTHROPIC_BASE_URL=http://127.0.0.1:38917`, `ANTHROPIC_CUSTOM_HEADERS=X-Cleaner-Key: capture`, без
  `ANTHROPIC_AUTH_TOKEN` и `ANTHROPIC_API_KEY`; `claude -p --strict-mcp-config --settings '{"disableAllHooks": true}' "Скажи «да»"`.
- Codex 0.163.0, настоящий `~/.codex`: `codex exec -c model_provider=capture-sub -c
  'model_providers.capture-sub={name="capture-sub", base_url="http://127.0.0.1:38917/v1", wire_api="responses",
  requires_openai_auth=true, env_http_headers={"X-Cleaner-Key"="CAPTURE_KEY"}}' "Скажи «да»"`.

`headers.json`: `claude_code_title` и `claude_code_turn` — запрос названия сессии и ход; `codex_models_1/2` —
`GET /v1/models?client_version=…` (Codex с входом ChatGPT спрашивает список моделей у своего провайдера; ответ 404
работе не мешает); `codex_memory` — фоновая консолидация памяти Codex (`request_kind: memory`, тело 1,7 МБ); `codex_turn` —
ход.

Замены: у `authorization` — только схема и длина значения (так пишет заглушка); идентификаторы (сессия, окно, запрос,
`chatgpt-account-id`) — вымышленные `00000000-0000-4000-8000-…` с сохранением совпадений; `x-codex-turn-metadata` —
только `request_kind`, `thread_source`, `turn_trigger` (в нём идентификатор установки и рабочие каталоги профиля).
