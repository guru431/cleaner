"""Приёмка этапов 2 и 4 на уровне приложения: AC-2.1, AC-2.4, AC-4.1, AC-4.2 (TZ.md, раздел 11).

Настоящие модели, документы и шлюз — в наборе integration и в приёмке на сервере (план 2+4, задача 26).
"""
import json
import logging

from cleaner.core.detect.llm import LlmLayer
from cleaner.core.types import EntityType as T
from cleaner.local_llm import LocalLLMError

OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + "EncryptedPackage".encode("utf-16-le")
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def test_ac_2_1_one_label_for_three_cases_and_the_lone_surname(ivan, repo, engines):
    names = ("Иванов Иван Иванович", "Иванову Ивану Ивановичу", "Иванова Ивана Ивановича", "Иванов")
    engines.ner_layer.marks = {name: T.PERSON for name in names}
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/input", text="Иванов Иван Иванович написал. Позвоните Иванову Ивану Ивановичу.")
    ivan.post(f"/chats/{chat_id}/input", text="Нет Иванова Ивана Ивановича. Иванов ответит.")
    assert [i.sanitized for i in repo.items(chat_id)] == [
        "<PERSON_1> написал. Позвоните <PERSON_1>.", "Нет <PERSON_1>. <PERSON_1> ответит.",
    ]


def test_ac_2_4_password_protected_file_is_refused_with_a_clear_message(ivan, repo):
    chat_id = ivan.chat()
    ivan.upload(f"/chats/{chat_id}/upload", "Отчёт.xlsx", OLE)
    page = ivan.get(f"/chats/{chat_id}").text
    assert "Не обработан: Файл защищён паролем: снимите защиту и загрузите его снова" in page


def test_ac_4_1_second_pass_finds_a_password_without_a_key_word(ivan, repo, engines):
    answer = {"items": [{"text": "sunflower77", "type": "SECRET"}, {"text": "Пётр Сидоров", "type": "PERSON"}]}
    engines.completer.answers = [json.dumps(answer, ensure_ascii=False)]
    engines.second = LlmLayer(engines.completer)
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/layers", layer="llm", enabled="yes")
    ivan.post(f"/chats/{chat_id}/input", text="Для общего ящика на стикере записано: sunflower77")
    [item] = repo.items(chat_id)
    assert item.sanitized == "Для общего ящика на стикере записано: <SECRET_1>"     # строки не из текста отброшены
    assert [s["source"] for s in item.model_spans if s["source"] == "llm"] == ["llm"]


def test_ac_4_2_unavailable_local_model_refuses_and_disabling_layer_5_helps(ivan, repo, engines):
    engines.completer.error = LocalLLMError("unavailable", "локальная модель недоступна")
    engines.second = LlmLayer(engines.completer)
    chat_id = ivan.chat()
    ivan.post(f"/chats/{chat_id}/layers", layer="llm", enabled="yes")
    ivan.post(f"/chats/{chat_id}/input", text="почта a@x.example")
    [item] = repo.items(chat_id)
    assert (item.status, item.sanitized) == ("failed", None)
    assert "Слой 5: локальная модель недоступна" in ivan.get(f"/chats/{chat_id}").text
    ivan.post(f"/chats/{chat_id}/layers", layer="llm", enabled="no")
    ivan.post(f"/chats/{chat_id}/items/{item.id}/retry")
    assert repo.item(chat_id, item.id).sanitized == "почта <EMAIL_1>"


def test_new_stage_data_stays_out_of_the_file_the_logs_and_the_journal(ivan, repo, engines, tmp_path, caplog):
    """AC-1.8 для данных этапов 2 и 4: имя файла, распознанный текст, догадки модели, эталон."""
    caplog.set_level(logging.DEBUG)
    engines.ocr_text = "Скан: Кк93 почта scan93@x.example"
    engines.completer.answers = [json.dumps({"guesses": [{"kind": "org", "guess": "Ромашка Rr93", "clue": ""}]}, ensure_ascii=False)]
    chat_id = ivan.chat()
    ivan.upload(f"/chats/{chat_id}/upload", "Секретный Zz93.png", PNG)
    item_id = repo.items(chat_id)[0].id
    ivan.post(f"/chats/{chat_id}/items/{item_id}/risk")
    ivan.post(f"/chats/{chat_id}/items/{item_id}/gold")
    assert len(repo.gold()) == 1 and repo.item_risk(chat_id, item_id)["guesses"]
    repo.conn.execute("PRAGMA wal_checkpoint(FULL)")
    raw = b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
    journal = json.dumps([(a.event, a.details) for a in repo.audit_events(limit=1000)], ensure_ascii=False)
    for value in ("Кк93", "scan93", "Rr93", "Zz93"):
        assert value.encode("utf-8") not in raw and value.encode("utf-16-le") not in raw, value
        assert value not in journal and value not in caplog.text, value
