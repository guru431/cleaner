-- Версия 7: отмена последней правки правил чата (раздел 14, «Правка на экране проверки»). Снимок состояния до
-- правки зашифрован ключом чата, как state_enc (SEC-4); undo_action — вид правки без значений; undo_version — версия
-- чата, которую дала правка: снимок действует, только пока версия та же, — любая другая запись состояния его гасит.
-- Глубина одна: следующая правка снимок перезаписывает, отмена стирает. NULL — отменять нечего.
ALTER TABLE chats ADD COLUMN undo_enc BLOB;
ALTER TABLE chats ADD COLUMN undo_action TEXT;
ALTER TABLE chats ADD COLUMN undo_version INTEGER;
