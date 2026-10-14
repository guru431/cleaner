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

## Установка на example

Сервер описан в `D:\vsc\vLLM` (его правила действуют и здесь); установщик, юнит и проверка — в `deploy/`. Доступ с этой машины (сеть `example/19`): `ssh -i ~/.ssh/example -p 34012 example@example`, у `example` sudo без пароля.

```bash
# Зависимости сервера — после каждой пересборки requirements.txt / requirements-dev.txt:
.venv/Scripts/python.exe deploy/lock_linux.py requirements.in requirements-linux.txt requirements.txt
.venv/Scripts/python.exe deploy/lock_linux.py requirements-dev.in requirements-dev-linux.txt requirements-dev.txt requirements.txt

# Доставка закоммиченного дерева в каталог под root, установка или обновление, проверка фактом:
git -c tar.umask=0022 archive HEAD | ssh -i ~/.ssh/example -p 34012 -o BatchMode=yes example@example \
  'sudo rm -rf /root/stage-cleaner && sudo install -d -m 0700 /root/stage-cleaner && sudo tar -xf - -C /root/stage-cleaner'
ssh -t -i ~/.ssh/example -p 34012 example@example 'sudo bash /root/stage-cleaner/deploy/install-cleaner.sh /root/stage-cleaner'
ssh -i ~/.ssh/example -p 34012 -o BatchMode=yes example@example 'sudo bash /usr/local/sbin/check-cleaner.sh; sudo rm -rf /root/stage-cleaner'
```

- Логин первого администратора — вторым аргументом установщика (после каталога доставки), только при первой установке; пароль спрашивается с клавиатуры, поэтому `ssh -t`.
- Правка `ufw` — только под страховкой `ufw-failsafe` (установщик ставит её сам); затем новое SSH-подключение и `sudo systemctl stop ufw-failsafe.timer`.
- После изменения `deploy/cleaner.service` — переснять эталон vLLM: `powershell -File D:\vsc\vLLM\dashboard\deploy\manifest.ps1 -Route second-net -UpdateBaseline`, затем `python dashboard/deploy/facts.py --write` в `D:\vsc\vLLM`.
- Отпечаток сертификата печатают установщик и `check-cleaner.sh`; в документы он не выписывается. Значения ключей не попадают в файлы и в вывод.
