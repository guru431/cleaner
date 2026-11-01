-- Persistent namespace for clients without a conversation id; request receipts use the chat encryption key.
ALTER TABLE api_keys ADD COLUMN agent_epoch INTEGER NOT NULL DEFAULT 0;
CREATE TABLE agent_receipts (
    id TEXT PRIMARY KEY,
    conversation TEXT NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    content_enc BLOB NOT NULL
);
CREATE INDEX agent_receipts_by_conversation ON agent_receipts(conversation, created_at);
