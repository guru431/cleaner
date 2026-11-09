# Cleaner

Локальная очистка чувствительных данных перед обращением к облачным LLM.
Требования — [TZ.md](TZ.md), устройство — [спецификация](docs/superpowers/specs/2026-10-13-cleaner-design.md).
Установка — [docs/deployment.md](docs/deployment.md), публикация — [docs/publication.md](docs/publication.md),
контроль качества (эталон, `eval`, базовые замеры) — [docs/quality-control.md](docs/quality-control.md).

## Tests

Studio API: [docs/studio-api.md](docs/studio-api.md), `cleaner/integration.py`.
Точечная проверка: `.venv/Scripts/python.exe -m pytest -n 0 tests/test_integration_api.py tests/test_web_api.py`.

```yaml
tests:
  interpreter: .venv/Scripts/python.exe
  targeted: .venv/Scripts/python.exe -m pytest tests/<файл>.py
  fast: .venv/Scripts/python.exe -m pytest
  full: .venv/Scripts/python.exe -m pytest -n 0 -m "not manual"
```

На Linux интерпретатор — `.venv/bin/python`. В тестах только вымышленные данные.
Быстрый набор идёт в двух процессах pytest-xdist (`--dist=loadfile`), бюджет — 60 с,
таймаут теста — 30 с. Полный набор и замеры времени — с `-n 0`.
После правки слоёв 1–3 и восстановления: `.venv/Scripts/python.exe -m pytest -n 0 tests/test_long_input.py -m integration`.
После правки шлюза агентов: `.venv/Scripts/python.exe -m pytest -n 0 tests/test_gateway_speed.py -m integration -rP`.
Проверки соседнего серверного периметра включаются явно переменными `CLEANER_SERVER_GUARD`,
`CLEANER_PERIMETER_CONFIG` и `CLEANER_HOST_PROFILE`; пути и сети в Git не записываются.

## Разработка

Команды запуска — в [README.md](README.md). Без `--config` и `CLEANER_CONFIG` служба
слушает 127.0.0.1; данные — `data/`, скачанные модели — `models/`, оба каталога вне Git.
Внешний интерфейс требует TLS. Главный ключ и `CLEANER_GATEWAY_KEY` передаются окружением;
в базе настроек сохраняются адрес и модель локального шлюза, значения ключей туда не копируются.

Слой 5, проверка риска и распознавание сканов обращаются к локальному шлюзу.
Для OCR доступны служба `ocr-ru` или модель зрения, например `tencent/HunyuanOCR`,
на маршруте `/pages/ocr`. Адрес, модель и способ входа облачного подключения задаются в интерфейсе.
Готовые настройки клиентов шлюза агентов показываются на странице выпущенного ключа.
Запись настоящих профилей агентов — только `scripts/agent_capture.py --headers-only`:
тела могут содержать память и личные данные. Синтетические примеры — в `tests/fixtures/agents/`.

## Зависимости

Версии закреплены с хэшами. Для обновления используйте `uv pip compile` с
`--generate-hashes --exclude-newer "14 days"`, сначала `requirements.in`, затем
`requirements-dev.in`; исключения возраста для torch и certifi — в исходных замках.
Серверные замки после Windows-замков собирает `deploy/lock_linux.py`:

```bash
python deploy/lock_linux.py requirements.in requirements-linux.txt requirements.txt
python deploy/lock_linux.py requirements-dev.in requirements-dev-linux.txt requirements-dev.txt requirements.txt
```

Серверные зависимости используют CPU-сборку torch. Модели скачиваются отдельно;
содержимое моделей, база, сертификаты и настоящие тексты не включаются в публикацию.

## Приватность и установка

В публичный Git не входят реальные профили хостов, рабочие планы, журналы и прежние
эксплуатационные инструкции. Они остаются локальными игнорируемыми файлами; `export-ignore`
дополнительно исключает их из архивов. Основная ветка и GitHub имеют общую очищенную историю.
Копии исходных инструкций остаются локально в `docs/private/`.
В публичных требованиях и спецификациях имена узлов и адреса заменены вымышленными примерами.
Профиль хоста задаёт адрес, сети клиентов, внутренние сети и шлюз; `CLIENTS` должны входить в `INTERNAL`.
Установщик сохраняет профиль в `/etc/cleaner/host.env`, откуда его читают экран и проверка.
При обновлении существующие настройки, ключи, сертификат и база сохраняются.
Смена сертификата — только явным `CLEANER_REISSUE_CERT=1`; отпечаток не записывается в документы.
