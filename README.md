# Cleaner

Локальная псевдонимизация перед облачной LLM: убирает из текста и документов персональные и
учётные данные и сведения об инфраструктуре, хранит таблицу соответствий на сервере и
восстанавливает оригиналы в ответе модели.

Очистка идёт пятью слоями: правила, секреты, инфраструктура и словари, локальные модели
распознавания имён (CPU, без сети), локальная LLM.

## Из чего состоит

- `cleaner/` — код: `core/` (конвейер очистки, замены, восстановление, проверка утечек и риска),
  `ingest/` (документы и текстовые файлы), `storage/` (база и шифрование таблицы соответствий),
  `egress/` (отправка в облако), `web/` (веб-интерфейс: чаты, проверка, настройки), `eval/` (замеры).
- `deploy/` — установщик `install-cleaner.sh`, юнит `cleaner.service`, проверка `check-cleaner.sh`,
  ограничение выхода наружу `cleaner-egress.sh`, сборка серверных зависимостей `lock_linux.py`.
- `scripts/` — проверки компонентов и загрузка открытых наборов для замеров.
- `tests/` — тесты; данные в них только вымышленные.

## Запуск для разработки

```bash
.venv/Scripts/python.exe -m cleaner init --admin dev --env-file data/cleaner.env
.venv/Scripts/python.exe -m cleaner models download   # модели слоя 4 и Docling в models/ (около 2 ГБ)
set -a; . data/cleaner.env; set +a
.venv/Scripts/python.exe -m cleaner serve             # http://127.0.0.1:5464
```

Без `--config` и `CLEANER_CONFIG` действуют настройки по умолчанию: адрес 127.0.0.1, данные в
`data/` (каталог в `.gitignore`). Слою 5 и распознаванию сканов нужен ключ шлюза — строка
`CLEANER_GATEWAY_KEY` в `data/cleaner.env`, её дописывает владелец.

## Тесты

```bash
.venv/Scripts/python.exe -m pytest                       # быстрый набор (≤ 60 с)
.venv/Scripts/python.exe -m pytest tests/<файл>.py       # точечно
.venv/Scripts/python.exe -m pytest -m "not manual"       # полный
.venv/Scripts/python.exe -m pytest tests/test_long_input.py -m integration   # после правки слоёв 1–3
```

## Где работает

- Служба `cleaner` на example: `https://example:5464`, открывается только из сети
  example/19. Код `/opt/cleaner`, данные `/var/lib/cleaner`, настройки и ключи `/etc/cleaner/`.
- LLM для слоя 5 — шлюз example (`:30000`).
- Второй экземпляр (с 2026-10-15) — example, `https://example5464`, из домашней сети
  192.168.0.0/20 и VPN example/20. Слой 5 — роль `local-chat` шлюза llm_routers на этом же хосте
  (gemma4); распознавание сканов там не работает: маршрут `/pages/ocr` шлюза другого формата.
- Адрес, сети клиентов и шлюз хоста — профиль `deploy/hosts/<hostname -s>.conf`.
- Разработка — в основном на build-host (`D:\vsc\cleaner`), с workstation проект сводится через git.
- Установка и обновление (доставка `git archive`, установщик, проверка) — по шагам в
  [CLAUDE.md](CLAUDE.md), разделы «Установка на example» и «Установка на example». Правила
  сервера example — в проекте `vLLM`.

## Документы

- [TZ.md](TZ.md) — требования.
- [docs/superpowers/specs/2026-10-13-cleaner-design.md](docs/superpowers/specs/2026-10-13-cleaner-design.md) —
  устройство; планы — `docs/superpowers/plans/`.
- [CLAUDE.md](CLAUDE.md) — правила, запуск, установка; [AGENTS.md](AGENTS.md) — памятка.
- [FINDINGS.md](FINDINGS.md) и [IDEAS.md](IDEAS.md) — находки и идеи.
