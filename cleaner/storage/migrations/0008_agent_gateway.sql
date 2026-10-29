-- Версия 8: шлюз для агентов (план 5Б; спецификация 2026-10-28, разделы 6.1, 6.3, 7). Доступ ключа к модели, вид чата,
-- разговоры агентов и журнал отправленного. Содержимое журнала — под ключом чата, как элементы.
ALTER TABLE api_keys ADD COLUMN upstream TEXT;
ALTER TABLE api_keys ADD COLUMN models TEXT NOT NULL DEFAULT '[]';
ALTER TABLE api_keys ADD COLUMN layers TEXT NOT NULL DEFAULT '{}';
ALTER TABLE api_keys ADD COLUMN chat_id TEXT REFERENCES chats(id) ON DELETE SET NULL;
ALTER TABLE chats ADD COLUMN kind TEXT NOT NULL DEFAULT 'chat';

CREATE TABLE agent_conversations (
    id         TEXT PRIMARY KEY,                -- HMAC отпечатка разговора (спецификация, 6.3)
    chat_id    TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    key_id     TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    session    TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    requests   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX agent_conversations_by_chat ON agent_conversations(chat_id, last_seen);

CREATE TABLE agent_ledger (
    conversation TEXT NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    direction    TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    digest       TEXT NOT NULL,
    local_enc    BLOB NOT NULL,
    wire_enc     BLOB NOT NULL,
    withheld     TEXT NOT NULL DEFAULT '',
    counts       TEXT NOT NULL DEFAULT '{}',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    PRIMARY KEY (conversation, direction, digest)
);
