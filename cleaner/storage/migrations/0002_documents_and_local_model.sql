-- Версия 2 (этапы 2 и 4): фоновая обработка элементов, документы, слои 4 и 5, эталонный набор.
-- source: paste | file | pasted_answer (план «3» добавит api, local).
-- status: queued | running | done | failed (план «3» добавит partial) — без CHECK: новое значение не требует пересборки таблицы.
-- meta: вид файла, страницы, слои, ход и причина отказа — без текста пользователя.
-- model_spans: находки слоёв 4–5 (позиции, тип, источник) для повторной очистки без моделей.
ALTER TABLE items ADD COLUMN source TEXT NOT NULL DEFAULT 'paste';
ALTER TABLE items ADD COLUMN status TEXT NOT NULL DEFAULT 'done';
ALTER TABLE items ADD COLUMN meta TEXT NOT NULL DEFAULT '{}';
ALTER TABLE items ADD COLUMN model_spans TEXT NOT NULL DEFAULT '[]';
ALTER TABLE items ADD COLUMN risk_status TEXT NOT NULL DEFAULT '';
ALTER TABLE items ADD COLUMN risk_enc BLOB;
UPDATE items SET source = 'pasted_answer' WHERE kind = 'answer';

-- Явные решения пользователя о слоях 4 и 5 в этом чате: {"ner": false}; без записи действует умолчание.
ALTER TABLE chats ADD COLUMN layers TEXT NOT NULL DEFAULT '{}';

-- Эталонные примеры (FR-6.10, QA-1): текст и разметка под общим ключом.
CREATE TABLE gold (
    id         TEXT PRIMARY KEY,
    user_id    TEXT,
    text_enc   BLOB NOT NULL,
    spans_enc  BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX items_by_status ON items(status);
