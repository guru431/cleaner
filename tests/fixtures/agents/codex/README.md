# Записи запросов Codex

Настоящие тела запросов Codex к провайдеру по протоколу OpenAI Responses, записанные заглушкой
`scripts/agent_capture.py` (спецификация 2026-10-28, раздел 18, проверки 1–2; план 5В, задача 1). Основа тестов
протокола Responses в шлюзе.

- Codex 0.163.0 (`codex_exec/0.163.0`), Windows, 29.10.2026; `codex exec -s workspace-write -c windows.sandbox=unelevated`.
- Свой провайдер в свежем `CODEX_HOME` (пустой каталог: без памяти, навыков владельца и серверов MCP):
  `base_url = "http://127.0.0.1:38917/v1"`, `wire_api = "responses"`, `env_key = "CAPTURE_KEY"`.
- Вымышленный репозиторий `C:\cleaner-capture\contoso-repo` (git) с `notes.txt` — те же контрольные значения, что в
  `../claude_code/README.md`: почта в двух регистрах, `srv-dc01.corp.contoso.ru`, `10.1.2.5`, `CONTOSO\ivanov`,
  `password=Hunter2Hunter2`.
- Два набора инструментов — по модели (каталог моделей Codex, `codex debug models`):
  - `-m gpt-5.5` — обычный: поле `tools` с `exec_command` (команда — `cmd`), `apply_patch` (свободный текст,
    `custom` с грамматикой в `format`) и др.;
  - `-m gpt-6.1-sol` (и все модели `gpt-6.x`, `gpt-5.6-*`: `tool_mode = code_mode_only`) — «code mode»: поля `tools`
    нет, инструменты — первым элементом `input` вида `additional_tools`; модель вызывает один инструмент `exec`
    (`custom_tool_call`, текст на JavaScript), а `exec_command` и `apply_patch` зовутся из него (`tools.exec_command(…)`,
    `tools.apply_patch(…)`); заголовок `x-openai-internal-codex-responses-lite: true`.
- Сценарий заглушки — `script.json` (обычный) и `script_code.json` (code mode): ход 1 — рассуждение (`reasoning` с
  `encrypted_content`), текст «Читаю файл.» и чтение `notes.txt` (`function_call` `exec_command` или `exec`); ход 2 —
  рассуждение и `apply_patch` со строкой учётной записи из результата чтения (`{{line:Учётная запись:}}`); ход 3 —
  текст «Готово…»; ход 4 (только обычный) — ответ после `codex exec resume --last "Ещё раз"`. Патч лёг в файл.

| Файл | Что |
|---|---|
| `turn1.json` | тело первого хода `gpt-5.5` (`POST /v1/responses`) |
| `turn2.json` | второй ход: прежние элементы, ответ модели (рассуждение, текст, `function_call`) и `function_call_output` с содержимым `notes.txt` |
| `turn3.json` | третий ход: ещё `custom_tool_call` `apply_patch` и `custom_tool_call_output` |
| `resume.json` | ход после `resume`: вся прежняя история, ответ «Готово…» и новое сообщение «Ещё раз» |
| `code_turn3.json` | третий ход `gpt-6.1-sol` (code mode): `additional_tools`, два вызова `exec` с их результатами |
| `headers.json` | метод, путь и заголовки этих запросов (без `authorization`, `host`, `content-length`) |
| `script.json`, `script_code.json` | сценарии заглушки (события Responses) — для повторной записи и приёмки на сервере |

Замены в записях (кроме этого — ничего не менялось): путь временного `CODEX_HOME` (каталог системных навыков в
инструкциях разработчика) — `C:\Users\dev\.codex`.
