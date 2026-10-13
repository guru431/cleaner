from cleaner import selfcheck
from cleaner.__main__ import main
from cleaner.core.detect import rules


def test_selfcheck_passes():
    lines: list[str] = []
    assert selfcheck.run(lines.append) == 0
    assert lines == [f"OK: подложенные значения скрыты и восстановлены ({len(selfcheck.CANARIES)})"]


def test_selfcheck_fails_when_a_layer_finds_nothing(monkeypatch):
    monkeypatch.setattr(rules, "detect", lambda text, ctx: [])
    lines: list[str] = []
    assert selfcheck.run(lines.append) == 1
    assert any("7707083893" in line for line in lines)


def test_command_line_entry_point(capsys):
    assert main(["verify"]) == 0
    assert capsys.readouterr().out.startswith("OK")
