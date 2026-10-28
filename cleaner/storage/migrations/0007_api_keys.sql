-- Версия 7: ключи доступа программ (план 5А; спецификация 2026-10-28, раздел 6.1). Хранится хэш SHA-256 ключа и его
-- последние четыре знака, имя — под общим ключом. Столбцы шлюза (доступ к модели, слои, чат шлюза) добавит план 5Б.
CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_enc     BLOB NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    tail         TEXT NOT NULL,
    disabled     INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX api_keys_by_user ON api_keys(user_id, created_at);
