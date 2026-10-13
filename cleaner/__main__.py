"""Командная строка Cleaner."""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cleaner", description="Очистка данных перед облачными LLM")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify", help="самопроверка очистки и восстановления на подложенных значениях")
    args = parser.parse_args(argv)
    if args.command == "verify":
        from cleaner import selfcheck

        return selfcheck.run(print)
    return 2


if __name__ == "__main__":
    sys.exit(main())
