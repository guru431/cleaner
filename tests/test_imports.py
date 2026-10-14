"""SEC-1: сетевые библиотеки доступны только модулям выхода в сеть."""
import ast
from collections.abc import Iterator
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "cleaner"
FORBIDDEN = ("httpx", "requests", "aiohttp", "socket", "urllib.request", "http.client")
ALLOWED_FILES = {PACKAGE / "local_llm.py"}
ALLOWED_DIR = PACKAGE / "egress"


def _imports(path: Path) -> Iterator[str]:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module
            yield from (f"{node.module}.{alias.name}" for alias in node.names)


def test_network_libraries_are_imported_only_by_egress_modules():
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        if path in ALLOWED_FILES or ALLOWED_DIR in path.parents:
            continue
        for name in _imports(path):
            if any(name == bad or name.startswith(bad + ".") for bad in FORBIDDEN):
                offenders.append(f"{path.relative_to(PACKAGE)}: {name}")
    assert offenders == []


def test_source_parses_as_python_3_12():
    """Сервер работает на Python 3.12, разработка — на 3.14: новый синтаксис туда не доедет."""
    for path in PACKAGE.rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 12))


HEAVY = ("torch", "transformers", "gliner", "docling", "huggingface_hub", "pymorphy3", "pypdfium2")


def test_heavy_libraries_are_imported_lazily():
    """Модели и разбор документов грузятся по первому обращению: импорт пакета их не тянет (быстрый набор, запуск службы)."""
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            offenders += [f"{path.relative_to(PACKAGE)}: {n}" for n in names if n.split(".")[0] in HEAVY]
    assert offenders == []
