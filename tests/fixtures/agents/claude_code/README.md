# Записи запросов Claude Code

Настоящие тела запросов Claude Code к провайдеру Anthropic, записанные заглушкой `scripts/agent_capture.py`
(спецификация 2026-10-28, раздел 18, проверки 1–2). Основа тестов шлюза (план 5Б).

- Claude Code 2.1.270 (`claude-cli/2.1.270 (external, sdk-cli)`), Windows, 28.10.2026.
- Запуск: `claude -p "Прочитай notes.txt"`, затем `claude -p --resume <сессия> "Ещё раз"`; `ANTHROPIC_BASE_URL` —
  заглушка, `ANTHROPIC_AUTH_TOKEN=capture`, `ANTHROPIC_MODEL=capture-model`, чистый профиль (`CLAUDE_CONFIG_DIR` —
  пустой каталог: без памяти, хуков и серверов MCP), `CLAUDE_CODE_ATTRIBUTION_HEADER` не задан.
- Вымышленный репозиторий `C:\cleaner-capture\contoso-repo` с `notes.txt`: почта в двух регистрах
  (`ivan.petrov@contoso.ru`, `Ivan.Petrov@Contoso.RU`), `srv-dc01.corp.contoso.ru`, `10.1.2.5`, `CONTOSO\ivanov`,
  `password=Hunter2Hunter2`.
- Сценарий заглушки: ход 1 — рассуждение (`thinking` с подписью), текст «Читаю файл.» и `tool_use` `Read` файла
  `notes.txt` (`input` одной дельтой `input_json_delta`); ход 2 — текст «Готово», `end_turn`.

| Файл | Что |
|---|---|
| `turn1.json` | тело первого хода (`POST /v1/messages?beta=true`) |
| `turn2.json` | тело второго хода: та же история, ответ модели и результат `Read` с содержимым `notes.txt` |
| `resume.json` | тело первого хода после `--resume`: вся прежняя история и новое сообщение «Ещё раз» |
| `headers.json` | метод, путь и заголовки запросов `HEAD /api/hello`, запроса названия сессии и ходов (без `authorization`, `host`, `content-length`) |

Замены в записях (кроме этого — ничего не менялось):

- путь к каталогу профиля записи (временный каталог на машине разработки) в разделе о памяти системной части —
  `C:\Users\dev\.claude`;
- `device_id` в `metadata.user_id` — 64 нуля.
