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
Правка слоёв 1–3 — ещё `.venv/Scripts/python.exe -m pytest tests/test_long_input.py -m integration`: обход всех слоёв по длинным рядам (19 с) вынесен из быстрого набора ради нормы 60 с.

## Запуск для разработки

```bash
.venv/Scripts/python.exe -m cleaner init --admin dev --env-file data/cleaner.env
.venv/Scripts/python.exe -m cleaner models download   # модели слоя 4 и Docling в models/ (нужен интернет, около 2 ГБ)
set -a; . data/cleaner.env; set +a          # главный ключ — в окружение, как его передаёт systemd
.venv/Scripts/python.exe -m cleaner serve    # http://127.0.0.1:5464
# Открытые наборы (QA-4): скачать один раз (нужен интернет), мерить — с тем же ключом в окружении:
# eval и с --jsonl открывает базу — из неё берутся словарь, шаблоны и политики.
.venv/Scripts/python.exe scripts/fetch_open_sets.py data/open-sets
.venv/Scripts/python.exe -m cleaner eval --jsonl data/open-sets/hivetrace.jsonl --layers 1-3 1-4
```

Слой 5, проверка риска и распознавание сканов ходят в шлюз сервера (`http://example:30000/v1`, адрес задаётся на странице «Настройки → Локальная модель»). Ключ — строкой `CLEANER_GATEWAY_KEY=…` в `data/cleaner.env`, которую дописывает владелец (ключ `cleaner-dev`, `sudo ai-ctl gateway-key create cleaner-dev`); в репозиторий и в вывод сессии он не попадает.

Без `--config` и `CLEANER_CONFIG` действуют настройки по умолчанию: адрес 127.0.0.1, данные в `data/` (каталог в `.gitignore`).

## Установка на example

Сервер описан в `D:\vsc\vLLM` (его правила действуют и здесь); установщик, юнит и проверка — в `deploy/`. Доступ с этой машины (сеть `example/19`): `ssh -i ~/.ssh/example -p 34012 example@example`, у `example` sudo без пароля.

```bash
# Файлы машины разработки: uv (стоит в .venv, uv==0.12.21) не берёт версии моложе 14 дней; кэш — на D:
# (кэш по умолчанию на C: переполнял диск). Обновить пакет — дописать --upgrade-package <имя>.
for f in requirements requirements-dev; do .venv/Scripts/uv.exe pip compile $f.in --generate-hashes --emit-index-url \
  --python .venv/Scripts/python.exe --index https://pypi.org/simple --index-strategy unsafe-best-match \
  --exclude-newer "14 days" --exclude-newer-package torch=false --cache-dir D:/uv-cache -o $f.txt; done
# Зависимости сервера — после каждой пересборки requirements.txt / requirements-dev.txt.
# lock_linux.py отказывает, если версия выложена на PyPI меньше 14 дней назад (так проверяется и torch).
.venv/Scripts/python.exe deploy/lock_linux.py requirements.in requirements-linux.txt requirements.txt
.venv/Scripts/python.exe deploy/lock_linux.py requirements-dev.in requirements-dev-linux.txt requirements-dev.txt requirements.txt

# Доставка закоммиченного дерева в каталог под root, установка или обновление, проверка фактом:
git -c tar.umask=0022 archive HEAD | ssh -i ~/.ssh/example -p 34012 -o BatchMode=yes example@example \
  'sudo rm -rf /root/stage-cleaner && sudo install -d -m 0700 /root/stage-cleaner && sudo tar -xf - -C /root/stage-cleaner'
ssh -t -i ~/.ssh/example -p 34012 example@example 'sudo bash /root/stage-cleaner/deploy/install-cleaner.sh /root/stage-cleaner'
ssh -i ~/.ssh/example -p 34012 -o BatchMode=yes example@example 'sudo bash /usr/local/sbin/check-cleaner.sh; sudo rm -rf /root/stage-cleaner'
```

- Логин первого администратора — вторым аргументом установщика (после каталога доставки), только при первой установке; пароль спрашивается с клавиатуры, поэтому `ssh -t`.
- Правка `ufw` — только под страховкой `ufw-failsafe` (установщик ставит её сам); затем новое SSH-подключение и `sudo systemctl stop ufw-failsafe.timer`. Выход службы наружу ограничивает своя таблица nftables `inet cleaner_egress` (`deploy/cleaner-egress.sh`): `ufw reload` и `disable` её не трогают; проверка — `check-cleaner.sh`, раздел 5.
- После изменения `deploy/cleaner.service` — переснять эталон vLLM: `powershell -File D:\vsc\vLLM\dashboard\deploy\manifest.ps1 -Route second-net -UpdateBaseline`, затем `python dashboard/deploy/facts.py --write` в `D:\vsc\vLLM`.
- Отпечаток сертификата печатают установщик и `check-cleaner.sh`; в документы он не выписывается. Значения ключей не попадают в файлы и в вывод.
