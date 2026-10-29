# Записи запросов OpenCode

Настоящие тела запросов OpenCode к провайдеру по протоколу OpenAI Chat Completions, записанные заглушкой
`scripts/agent_capture.py` (спецификация 2026-10-28, раздел 18, проверки 1–2; план 5В, задача 1). Основа тестов
протокола Chat Completions в шлюзе.

- OpenCode 1.14.39 (`opencode/1.14.39 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13`), Windows, 29.10.2026;
  `opencode run "Прочитай notes.txt и отметь строку учётной записи"`.
- Свежие каталоги настроек и данных (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, `XDG_STATE_HOME`),
  `OPENCODE_CONFIG` — файл с одним провайдером, `OPENCODE_DISABLE_CLAUDE_CODE=1` (иначе OpenCode берёт
  `~/.claude/CLAUDE.md` и навыки Claude Code владельца): провайдер `capture` с `npm: "@ai-sdk/openai-compatible"`,
  `options.baseURL = "http://127.0.0.1:38917/v1"`, `options.apiKey`, `options.headers = {"X-Cleaner-Key": "capture"}`.
  Личных настроек в теле нет (проверено поиском имени пользователя и путей профиля).
- Вымышленный репозиторий — тот же, что у Codex (`../codex/README.md`).
- Сценарий заглушки — `script.json`: ход 1 — `reasoning_content`, текст и вызов `read` (аргументы одной частью
  `tool_calls`); ход 2 — вызов `edit` со строкой учётной записи из результата чтения
  (`{{re:Учётная запись: \S+}}`); ход 3 — текст «Готово…». Правка легла в файл.

| Файл | Что |
|---|---|
| `title.json` | служебный запрос названия сессии (без `tools`) |
| `turn1.json` | тело первого хода (`POST /v1/chat/completions`) |
| `turn2.json` | второй ход: ответ модели (`reasoning_content`, текст, `tool_calls`) и сообщение `tool` с содержимым `notes.txt` |
| `turn3.json` | третий ход: вызов `edit` и его результат |
| `headers.json` | метод, путь и заголовки этих запросов (без `authorization`, `host`, `content-length`) |
| `script.json` | сценарий заглушки (части `chat.completion.chunk`) |

Замены в записях (кроме этого — ничего не менялось): временный каталог профиля в описании инструмента `bash` —
`C:\Users\dev\AppData\Local\Temp\opencode`.
