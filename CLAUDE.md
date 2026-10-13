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
