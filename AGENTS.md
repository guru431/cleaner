# AGENTS.md — cleaner

Локальная псевдонимизация перед облачной LLM: убирает персональные и учётные данные и сведения об
инфраструктуре из текста и документов, хранит таблицу соответствий и восстанавливает оригиналы в ответе
модели. Полные правила — `CLAUDE.md`.

## Ключевые файлы
- `TZ.md` — требования; `docs/superpowers/specs/2026-10-13-cleaner-design.md` — устройство; планы — `docs/superpowers/plans/`.
- `cleaner/` — код; запуск `python -m cleaner …` (`init`, `serve`, `models download`, `eval`).
- `deploy/` — установщик `install-cleaner.sh`, юнит `cleaner.service`, проверка `check-cleaner.sh`, выход наружу `cleaner-egress.sh`.
- `FINDINGS.md` / `IDEAS.md` — находки и идеи.

## Тесты
- Быстрый набор: `.venv/Scripts/python.exe -m pytest` (≤ 60 с); точечно — путь к файлу теста; полный — `-m "not manual"`.
- Правка слоёв 1–3 — ещё `.venv/Scripts/python.exe -m pytest tests/test_long_input.py -m integration`.

## Gotchas
- Данные в тестах — только вымышленные; настоящие тексты в репозиторий не попадают.
- Разработка идёт в основном на build-host (`D:\vsc\cleaner`); с workstation проект сводится через git.
- Прод — служба на example, `https://example:5464`, только из сети example/19; вход
  `ssh -i ~/.ssh/example -p 34012 example@example`. Правила сервера — в проекте `vLLM`.
- Слой 5 и распознавание сканов ходят в шлюз example; ключ — строка `CLEANER_GATEWAY_KEY` в `data/cleaner.env`
  (дописывает владелец), в репозиторий и в вывод не попадает.
- Зависимости — `uv pip compile … --exclude-newer "14 days"`, серверные — `deploy/lock_linux.py` (порядок — `CLAUDE.md`).
- `ufw` — только под страховкой `ufw-failsafe`; значения ключей и отпечаток сертификата в файлы не записывать.
- Репозиторий приватный (`git.example.net/xadmin/cleaner`), публиковать нельзя.
