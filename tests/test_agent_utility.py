"""Вымышленные задачи с проверяемым результатом; без модели и без внешней сети.

Проверяется сохранение смысла замены и восстановления на полном пути шлюза.
Это отдельная мера от задержки, расхода контекста и качества настоящей модели.
"""
import re
import shlex
import subprocess
import sys

import pytest

from tests.agent_bodies import agent_blocks, body, model_turn
from tests.test_agent_service import gw, stub  # noqa: F401 — общий стенд шлюза на петле


@pytest.mark.parametrize("task", ["file", "address", "command"])
def test_synthetic_agent_task_keeps_a_verifiable_result(gw, tmp_path, task):
    host, mail = "srv-audit.corp.contoso.ru", "audit.person@contoso.ru"

    def respond(request):
        wire = request["messages"][0]["content"][-1]["text"]
        masked_host = re.search(r"host-\d+\.sub-\d+\.domain-\d+\.example", wire).group()
        masked_mail = re.search(r"<EMAIL_\d+>", wire).group()
        if task == "file":
            return model_turn("", ("toolu_write", "Write", {
                "file_path": "service.ini", "content": f"server={masked_host}\nmail={masked_mail}\nretries=3\n",
            }))
        if task == "command":
            return model_turn("", ("toolu_cmd", "Bash", {"command": f'python -c "print(\'{masked_host}\')"'}))
        return model_turn(f"Ответ отправить на {masked_mail}")

    gw.stub.script.append(respond)
    blocks = agent_blocks(gw.send(body(
        f"Исправь retries=2 на retries=3 в service.ini, узел {host}, почта {mail}. "
        "Сохрани адрес и подготовь команду Python, которая печатает имя узла."
    )))
    assert host not in gw.stub.bodies() and mail not in gw.stub.bodies()
    if task == "file":
        tool = next(b["input"] for b in blocks if b["type"] == "tool_use")
        path = tmp_path / tool["file_path"]
        path.write_text(tool["content"], encoding="utf-8")
        assert path.read_text(encoding="utf-8") == f"server={host}\nmail={mail}\nretries=3\n"
    elif task == "command":
        tool = next(b["input"] for b in blocks if b["type"] == "tool_use")
        arguments = shlex.split(tool["command"])
        assert arguments[:2] == ["python", "-c"]
        result = subprocess.run([sys.executable, *arguments[1:]], capture_output=True, text=True, timeout=3, check=True)
        assert result.stdout.strip() == host
    else:
        assert next(b["text"] for b in blocks if b["type"] == "text") == f"Ответ отправить на {mail}"
