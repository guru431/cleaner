# Cleaner

Локальная очистка чувствительных данных перед обращением к облачным LLM.
Требования — [TZ.md](TZ.md), устройство — [спецификация](docs/superpowers/specs/2026-10-13-cleaner-design.md).

## Tests

tests:
  interpreter: .venv/Scripts/python.exe
  targeted: .venv/Scripts/python.exe -m pytest tests/<файл>.py
  fast: .venv/Scripts/python.exe -m pytest
  full: .venv/Scripts/python.exe -m pytest -n 0 -m "not manual"

Данные в тестах — только вымышленные. Настоящие тексты в репозиторий не попадают.
Быстрый набор по умолчанию идёт в двух процессах pytest-xdist, файлы распределяются целиком (`--dist=loadfile`); порог 60 с и таймаут каждого теста прежние. Полный набор и замеры времени — с `-n 0`, чтобы параллельные тесты не искажали числа.
Правка слоёв 1–3 и восстановления — ещё `.venv/Scripts/python.exe -m pytest -n 0 tests/test_long_input.py -m integration`: обход всех слоёв по длинным рядам и сторожа линейности (около 40 с) вынесены из быстрого набора ради нормы 60 с, пороги в секундах краснеют от нагрузки машины.
Правка шлюза агентов — ещё `.venv/Scripts/python.exe -m pytest -n 0 tests/test_gateway_speed.py -m integration -rP`: добавка шлюза по разделу 13 спецификации 2026-10-28 (полный путь до заглушки провайдера на петле, `-rP` печатает p50, p95 и добавку); мерить на машине без нагрузки.

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
# Ключ доступа к /api/v1 для своих скриптов (тоже с главным ключом в окружении; печатается один раз) и проверка API
# запущенной службы — ключ только в переменной окружения, не в аргументах:
.venv/Scripts/python.exe -m cleaner apikey add dev --name local
CLEANER_API_KEY=ck_… .venv/Scripts/python.exe scripts/api_smoke.py --url http://127.0.0.1:5464
```

Слой 5, проверка риска и распознавание сканов ходят в шлюз сервера (`http://example:30000/v1`, адрес задаётся на странице «Настройки → Локальная модель»). Ключ — строкой `CLEANER_GATEWAY_KEY=…` в `data/cleaner.env`, которую дописывает владелец (ключ `cleaner-dev`, `sudo ai-ctl gateway-key create cleaner-dev`); в репозиторий и в вывод сессии он не попадает.

Без `--config` и `CLEANER_CONFIG` действуют настройки по умолчанию: адрес 127.0.0.1, данные в `data/` (каталог в `.gitignore`).

Claude Code через шлюз агентов (план 5Б) на машине разработки: подключение с протоколом Anthropic на странице «Настройки → Облачные подключения», ключ шлюза к нему — на странице «Ключи» (доступ к модели) или `cleaner apikey add dev --name agent --provider <id подключения> --model <модель>` с главным ключом в окружении (ключ печатается один раз). Затем в проекте, где работает агент, — `claude-switch.ps1 cleaner` (мастер в `claude-bundle`): `CLEANER_URL` (`http://127.0.0.1:5464` без TLS или `https://…` с сертификатом), `CLEANER_KEY`, `CLEANER_CA_FILE` (сертификат службы для Node), `CLEANER_MODEL` — в окружении или в `.env` переключателя; ключ — и через `-KeyHelper`. Записи настоящих запросов агента — `scripts/agent_capture.py` (заглушка Anthropic, Chat Completions и Responses по пути, `--headers-only` — для настоящих профилей; только стандартная библиотека), их разбор и итоги проверок — спецификация 2026-10-28, раздел 18.

Codex, OpenCode и подписки через шлюз (план 5В): ключ к подключению Responses — для Codex, к подключению OpenAI-совместимому (Chat Completions) — для OpenCode и SDK OpenAI; ключ с подпиской (`--subscription claude|chatgpt`) выпускает только администратор. Готовые настройки — на странице ключа после выпуска. Codex — своим провайдером (`-c model_provider=…` или `~/.codex/config.toml` с `base_url = "<адрес>/agent/openai/v1"`, `wire_api = "responses"`, `env_http_headers = { "X-Cleaner-Key" = "CLEANER_KEY" }`; по ключу — `env_key`, по подписке ChatGPT — `requires_openai_auth = true`), сертификат — `CODEX_CA_CERTIFICATE`: Codex (rustls) не принимает сертификат с `CA:TRUE`, нужен выпущенный с `CA:FALSE`. OpenCode — провайдер `@ai-sdk/openai-compatible` в `opencode.json`, сертификат — `NODE_EXTRA_CA_CERTS`. Claude Code по своей подписке — `claude-switch.ps1 cleaner-sub` (ключ — в `ANTHROPIC_CUSTOM_HEADERS`, вход claude.ai остаётся). Настоящий профиль Codex сам шлёт и фоновую консолидацию памяти (`request_kind: memory`, сотни килобайт памяти профиля): её получит и заглушка записи, и шлюз — записывать такой профиль только с `--headers-only`.

Модели OpenCode Go (подписка владельца, ключ `OPENCODE_GO_KEY_1` в vault `local-config` — только в поле формы подключения) — подключения на странице «Настройки → Облачные подключения»: протокол Anthropic — адрес `https://opencode.ai/zen/go`, способ входа `x-api-key` (`Authorization: Bearer` там — 401); Responses (Codex) и OpenAI-совместимый (Chat Completions, OpenCode) — `https://opencode.ai/zen/go/v1`, способ входа `bearer`. Без заголовка `x-opencode-session` OpenCode Go отвечает 400 `MissingSessionID` на всех трёх протоколах; его добавляет egress сам по узлу `opencode.ai` (одно значение на разговор), в настройки подключения и агента его не вписывать.

## Установка на example

Сервер описан в `D:\vsc\vLLM` (его правила действуют и здесь); установщик, юнит и проверка — в `deploy/`. Доступ с build-host (сеть `example/19`): `ssh -i ~/.ssh/example -p 34012 example@example`; с workstation — по WireGuard через debian: `ssh -i ~/.ssh/studio_deploy_key -p 34012 deploy@example` (ключ `example` там только в профиле `Services` на build-host). У `example` и `deploy` sudo без пароля; команды ниже — с любым из адресов.

```bash
# Файлы машины разработки: uv (стоит в .venv, uv==0.12.21) не берёт версии моложе 14 дней; кэш — на D:
# (кэш по умолчанию на C: переполнял диск). Обновить пакет — дописать --upgrade-package <имя>.
# На workstation диска D: нет: --cache-dir — временный каталог, а --custom-compile-command "<эта же команда с D:/uv-cache>"
# держит шапку файлов прежней. Нет .venv/Scripts/uv.exe — .venv/Scripts/python.exe -m pip install uv==0.12.21.
# certifi — без карантина (набор корней: свежая версия отзывает доверие), см. AGE_EXEMPT в lock_linux.py.
for f in requirements requirements-dev; do .venv/Scripts/uv.exe pip compile $f.in --generate-hashes --emit-index-url \
  --python .venv/Scripts/python.exe --index https://pypi.org/simple --index-strategy unsafe-best-match \
  --exclude-newer "14 days" --exclude-newer-package torch=false --exclude-newer-package certifi=false \
  --cache-dir D:/uv-cache -o $f.txt; done
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
- Сертификат, выпущенный до 28.10.2026, Claude Code (Bun) не принимает: в нём нет `keyCertSign`, и шлюз агентов отвечает «SSL certificate verification failed» (Node и curl его принимают). Перевыпуск — `sudo env CLEANER_REISSUE_CERT=1 bash …/install-cleaner.sh …`: отпечаток меняется, браузеры и агенты принимают сертификат заново, прежний остаётся рядом (`cert.pem.prev-*`). На example и example перевыпущен 29.10.2026.
- Быстрый набор на сервере (Python 3.12) — до удаления `/root/stage-cleaner`: тестовые пакеты (`pytest`, `pytest-timeout`, `pytest-xdist`, `execnet`, `iniconfig`, `httpx2`, `httpcore2`, `truststore` — то, чем `requirements-dev-linux.txt` шире `requirements-linux.txt`) с их строками `--hash` из него — файлом в `/root/stage-cleaner/extra-test.txt`, затем `sudo /opt/cleaner/.venv/bin/python -m pip install --require-hashes --only-binary=:all: --no-deps --target /root/stage-testlib -r /root/stage-cleaner/extra-test.txt` и `cd /root/stage-cleaner && PYTHONPATH=/root/stage-testlib /opt/cleaner/.venv/bin/python -m pytest -q -p no:cacheprovider` (и `-n 0 -m integration tests/test_long_input.py`); после — `rm -rf /root/stage-testlib`. Два теста пропускаются: сверку с vLLM там делает `check-cleaner.sh`, а сверку с периметром llm_routers — машина разработки (репозитория на сервере нет).
- Сверка с эталоном vLLM без правки юнита: `powershell -File D:\vsc\vLLM\dashboard\deploy\manifest.ps1 -Route second-net` — «расхождений нет».
- Всё, что зависит от хоста (адрес, сети клиентов, внутренние сети, шлюз, сверка с `ai-egress-guard`), — в
  профиле `deploy/hosts/<hostname -s>.conf`; установщик кладёт его в `/etc/cleaner/host.env`, оттуда его читают
  `cleaner-egress.sh` и `check-cleaner.sh`. Новый хост — новый профиль; `CLIENTS` обязаны входить в `INTERNAL`
  (таблица `cleaner_egress` фильтрует и ответы службы), это сторожит `tests/test_deploy.py`.

## Установка на example

Второй экземпляр с 2026-10-15: `https://example5464`, клиенты — 192.168.0.0/20 и VPN example/20
(профиль `deploy/hosts/example.conf`). Слой 5 — роль `local-chat` шлюза llm_routers на этом же хосте
(`http://127.0.0.1:4000/v1`, ключ потребителя `cleaner` — `GATEWAY_KEY_CLEANER` в vault `local-config`, на хосте —
строка `CLEANER_GATEWAY_KEY` в `/etc/cleaner/cleaner.env`). Сканы — HunyuanOCR по маршруту `/pages/ocr` (с 2026-10-16;
маршрут ключу выдан в `llm_routers/gateway/consumers.yaml`): он OpenAI-совместимый, а не ocr-ru, поэтому в настройке
«Модель распознавания сканов» — `tencent/HunyuanOCR`; слот OCR на время страницы снимает gemma4. Администратор `admin`, пароль — `CLEANER_example_ADMIN_PASSWORD`
в vault `local-config`. Доступ с workstation: `ssh -i ~/.ssh/studio_deploy_key -p 22222 deploy@example, sudo без пароля;
доставка и установка — те же команды, что для example, с этим адресом (пароль администратора при первой
установке — с клавиатуры, `ssh -t`). `ai-egress-guard.sh` и `check-egress.sh` на example нет — проверка их
пропускает. Python там тоже 3.12, `requirements-linux.txt` общий. Правила ufw для 5464 на example держит и периметр
llm_routers (`CLEANER_PORT`, `CLEANER_NETS` в `example/deploy/nets.env`; всё, чего там нет, его прогон удаляет): смена
`CLIENTS` профиля — там же, совпадение сторожит `tests/test_deploy.py`.

Интернет у example медленный (~0,1 МБ/с 2026-10-15): окружение, собранное `pip` с хоста, качалось бы часами. Колёса
берутся на workstation — `.venv/Scripts/python.exe -m pip download --no-deps --require-hashes -r requirements-linux.txt -d <каталог>
--only-binary=:all: --python-version 3.12 --implementation cp --abi cp312 --abi abi3 --abi none` плюс `--platform`
для `manylinux_2_17/2014/2_27/2_28/2_31/2_34/2_35/2_39_x86_64` и `linux_x86_64` — переносятся в `/root/cleaner-wheels`
(0700), а установщик запускается как `sudo env PIP_NO_INDEX=1 PIP_FIND_LINKS=/root/cleaner-wheels bash …/install-cleaner.sh …`;
хэши сверяются по тому же файлу. Модели — копией `models/` с workstation (`tar` по SSH в `/opt/cleaner/models`,
владелец `cleaner`, проверка — `models verify` в `check-cleaner.sh`). Настройки локальной модели на example в базе
службы: `http://127.0.0.1:4000/v1`, `local-chat`, схема JSON параметром, модель распознавания `tencent/HunyuanOCR`.
