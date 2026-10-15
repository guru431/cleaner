-- Версия 3 (этап 3): подключения к облачным моделям и выбор подключения в чате (FR-8.1, FR-8.3).
-- api_key_enc — под общим ключом (aad providers.api_key:<id>); extra_body — объект JSON без ключей.
-- items.source получает api (ответ облака) и local (ответ локальной модели), status — partial (неполный ответ);
-- инструкция пользователя для модели — входной элемент с source = 'instruction'. Столбцы прежние.
CREATE TABLE providers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    base_url    TEXT NOT NULL,
    auth_style  TEXT NOT NULL,
    api_key_enc BLOB NOT NULL,
    models      TEXT NOT NULL DEFAULT '[]',
    max_tokens  INTEGER NOT NULL DEFAULT 4096,
    extra_body  TEXT NOT NULL DEFAULT '{}',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL
);

ALTER TABLE chats ADD COLUMN provider_id TEXT;
ALTER TABLE chats ADD COLUMN model TEXT NOT NULL DEFAULT '';
