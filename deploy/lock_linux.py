"""Файлы зависимостей для сервера: Linux x86_64, CPython 3.12, с контрольными суммами (SEC-14).

Кандидатов находит pip из .venv машины разработки: он разрешает зависимости для чужой платформы
(--platform, --python-version, только колёса) и при --dry-run ничего не ставит. Маркеры зависимостей
pip сам считает по машине, где запущен (Windows, Python 3.14): тогда пакет только для Windows без колёс
для Linux (pywin32 у docling-parse) делает разрешение невозможным. Поэтому pip запускается с маркерами
сервера (SERVER), а нужный серверу набор ещё раз пересчитывается по ним из метаданных, которые pip вернул.

Версии берутся из файлов машины разработки — на сервере работает тот же проверенный код; контрольные
суммы — оттуда же: pip-compile --generate-hashes записывает суммы всех файлов версии, в том числе
колёс для Linux.

    python deploy/lock_linux.py requirements.in requirements-linux.txt requirements.txt
    python deploy/lock_linux.py requirements-dev.in requirements-dev-linux.txt requirements-dev.txt requirements.txt

Версия, выложенная на PyPI меньше MIN_AGE_DAYS дней назад, не принимается: скомпрометированный релиз
замечают не в первый день (инцидент с LiteLLM, SEC-14), а pip-compile берёт самый новый. Отказ называет
пакет — закрепите в .in предыдущую версию (`пакет<версия`) и пересоберите файлы. Отсечь их сразу при
разрешении нельзя: pip --uploaded-prior-to отказывает целиком, если индекс без времени выкладки (сборки torch).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from packaging.requirements import Requirement

# Ubuntu 24.04 — glibc 2.39: годятся колёса manylinux_2_17 … manylinux_2_39.
PLATFORMS = [f"manylinux_2_{minor}_x86_64" for minor in range(39, 16, -1)] + ["manylinux2014_x86_64"]
SERVER = {
    "implementation_name": "cpython", "implementation_version": "3.12.3", "os_name": "posix",
    "platform_machine": "x86_64", "platform_python_implementation": "CPython", "platform_release": "",
    "platform_system": "Linux", "platform_version": "", "python_full_version": "3.12.3",
    "python_version": "3.12", "sys_platform": "linux",
}
# pip-compile пишет закреплённый пакет с дополнениями так: docling-slim[format-pdf,…]==2.139.0
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(\S+)")
_HASH = re.compile(r"--hash=(sha256:[0-9a-f]{64})")
MIN_AGE_DAYS = 14
# pip в отдельном процессе с маркерами сервера: packaging берёт окружение из default_environment() при каждой проверке.
_PIP_WITH_SERVER_MARKERS = (
    "import json, sys\n"
    "from pip._vendor.packaging import markers\n"
    "server = json.loads(sys.argv[1])\n"
    "markers.default_environment = lambda: dict(server)\n"
    "from pip._internal.cli.main import main\n"
    "sys.exit(main(sys.argv[2:]))\n"
)


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_lock(path: Path) -> dict[str, tuple[str, list[str]]]:
    """Пакет → (версия, контрольные суммы) из файла pip-compile --generate-hashes."""
    pins: dict[str, tuple[str, list[str]]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if pin := _PIN.match(line):
            current = canonical(pin.group(1))
            pins[current] = (pin.group(2), [])
        elif current and (digest := _HASH.search(line)):
            pins[current][1].append(digest.group(1))
    return pins


def candidates(
    wanted: list[str], pins: dict[str, tuple[str, list[str]]], indexes: list[str] = (),
) -> dict[str, list[str]]:
    """Пакет → его Requires-Dist для всего, что pip выбрал бы при версиях из pins."""
    with tempfile.TemporaryDirectory() as tmp:
        constraints, report = Path(tmp) / "constraints.txt", Path(tmp) / "report.json"
        constraints.write_text("".join(f"{name}=={version}\n" for name, (version, _) in pins.items()), encoding="utf-8")
        subprocess.run(
            [
                sys.executable, "-c", _PIP_WITH_SERVER_MARKERS, json.dumps(SERVER),
                "install", "--dry-run", "--ignore-installed", "--quiet",
                "--report", str(report), "--python-version", "3.12", "--implementation", "cp", "--abi", "cp312",
                "--only-binary=:all:", *(f"--platform={platform}" for platform in PLATFORMS),
                *(part for option in indexes for part in option.split(maxsplit=1)),
                "-c", str(constraints), *wanted,
            ],
            check=True,
        )
        installed = json.loads(report.read_text(encoding="utf-8"))["install"]
    return {canonical(item["metadata"]["name"]): item["metadata"].get("requires_dist", []) for item in installed}


def closure(wanted: list[str], metadata: dict[str, list[str]]) -> tuple[list[str], list[str]]:
    """Нужные серверу пакеты по маркерам SERVER и те, которых pip не предложил (тогда файл не собрать)."""
    needed: set[str] = set()
    missing: set[str] = set()
    seen: set[tuple[str, str]] = set()
    queue = [Requirement(line) for line in wanted]
    while queue:
        requirement = queue.pop()
        name = canonical(requirement.name)
        if name not in metadata:
            missing.add(name)
            continue
        needed.add(name)
        for extra in ("", *requirement.extras):
            if (name, extra) in seen:
                continue
            seen.add((name, extra))
            for spec in metadata[name]:
                dependency = Requirement(spec)
                if dependency.marker is None or dependency.marker.evaluate({**SERVER, "extra": extra}):
                    queue.append(dependency)
    return sorted(needed), sorted(missing)


def pypi_published(name: str, version: str) -> datetime | None:
    """Когда версия появилась на PyPI: самый ранний из её файлов. None — на PyPI её нет."""
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as response:
            files = json.load(response)["urls"]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return min((datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")) for f in files), default=None)


def too_young(
    pins: dict[str, tuple[str, list[str]]], names: list[str], now: datetime,
    published: Callable[[str, str], datetime | None] = pypi_published,
) -> list[str]:
    """Пакеты, версия которых выложена меньше MIN_AGE_DAYS дней назад. Сборка torch «+cpu» — по версии без «+cpu»."""
    young = []
    for name in names:
        version = pins[name][0].split("+")[0]
        when = published(name, version)
        if when is not None and now - when < timedelta(days=MIN_AGE_DAYS):
            young.append(f"{name}=={version} ({when:%d.%m.%Y})")
    return young


def main(argv: list[str], now: datetime | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    source, target, *locks = (Path(arg) for arg in argv)
    pins: dict[str, tuple[str, list[str]]] = {}
    for lock in locks:
        pins.update(read_lock(lock))
    # Строки «-c …» не передаются: файл с контрольными суммами включил бы у pip режим --require-hashes.
    lines = [line.strip() for line in source.read_text(encoding="utf-8").splitlines()]
    wanted = [line for line in lines if line and not line.startswith(("#", "-"))]
    # Индексы (сборка torch без CUDA) — и разрешению зависимостей, и установщику на сервере: pip читает их из файла.
    indexes = [line for line in lines if line.startswith(("--extra-index-url ", "--index-url "))]
    names, missing = closure(wanted, candidates(wanted, pins, indexes))
    missing += [name for name in names if name not in pins]
    if missing:
        print(f"не собрать: {', '.join(sorted(missing))} — нет у pip для этой платформы или в файлах машины разработки")
        return 1
    if young := too_young(pins, names, now or datetime.now(timezone.utc)):
        print(f"моложе {MIN_AGE_DAYS} дней: {', '.join(young)} — закрепите в {source.name} предыдущую версию и пересоберите")
        return 1
    lines = [
        f"# Сервер: Linux x86_64, CPython 3.12. Собран deploy/lock_linux.py из {source.name};",
        f"# версии и контрольные суммы — из {', '.join(lock.name for lock in locks)}. Руками не править.",
        *indexes,
    ]
    for name in names:
        version, hashes = pins[name]
        lines.append(f"{name}=={version} \\")
        lines += [f"    --hash={digest} \\" for digest in hashes[:-1]] + [f"    --hash={hashes[-1]}"]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{target}: {len(names)} пакетов")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
