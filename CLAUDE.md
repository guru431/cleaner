# Cleaner

Локальная очистка чувствительных данных перед обращением к облачным LLM.
Требования — [TZ.md](TZ.md), устройство — [спецификация](docs/superpowers/specs/2026-10-13-cleaner-design.md).

## Tests

tests:
  interpreter: .venv/Scripts/python.exe
  targeted: .venv/Scripts/python.exe -m pytest tests/<файл>.py
  fast: .venv/Scripts/python.exe -m pytest
  full: .venv/Scripts/python.exe -m pytest -m "not manual"

Данные в тестах — только вымышленные. Настоящие тексты в репозиторий не попадают.

## Запуск для разработки

```bash
.venv/Scripts/python.exe -m cleaner init --admin dev --env-file data/cleaner.env
set -a; . data/cleaner.env; set +a          # главный ключ — в окружение, как его передаёт systemd
.venv/Scripts/python.exe -m cleaner serve    # http://127.0.0.1:5464
```

Без `--config` и `CLEANER_CONFIG` действуют настройки по умолчанию: адрес 127.0.0.1, данные в `data/` (каталог в `.gitignore`).
