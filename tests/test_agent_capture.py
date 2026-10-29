"""Заглушка записи запросов агента (scripts/agent_capture.py): подстановки в шаги сценария из запроса — так сценарий
«прочитать файл → правка» берёт строку файла в том виде, в каком её увидела модель за шлюзом (приёмка AC-5.1)."""
import json

from scripts import agent_capture

REQUEST = {"messages": [
    {"role": "user", "content": "Прочитай notes.txt"},
    {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {}}]},
    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
        {"type": "text", "text": '     1\tУзел host-1.sub-2.domain-1.example\n     2\tПочта: "<EMAIL_2>" \\ отчёты\n'},
    ]}]},
]}


def test_steps_take_lines_and_matches_from_the_last_tool_result():
    step = [
        {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(
            {"old_string": "{{line:Почта:}}", "command": "ping {{re:host-\\d+(?:\\.[\\w-]+)+}}"}, ensure_ascii=False,
        )}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "Строка: {{line:Узел}}"}},
    ]
    rendered = agent_capture.render(step, REQUEST)
    assert json.loads(rendered[0]["delta"]["partial_json"]) == {
        "old_string": 'Почта: "<EMAIL_2>" \\ отчёты', "command": "ping host-1.sub-2.domain-1.example",
    }
    assert rendered[1]["delta"]["text"] == "Строка: Узел host-1.sub-2.domain-1.example"
    assert agent_capture.render(step, {"messages": []}) == step          # подставить нечего — как есть
