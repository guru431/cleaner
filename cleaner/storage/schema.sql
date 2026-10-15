-- Схема Cleaner, версия 1. Столбцы *_enc зашифрованы (раздел 12 спецификации).
CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    login         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf         TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE chats (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title_enc   BLOB NOT NULL,
    dek_wrapped BLOB NOT NULL,
    state_enc   BLOB NOT NULL,
    version     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE items (
    id            TEXT PRIMARY KEY,
    chat_id       TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('input', 'answer')),
    original_enc  BLOB NOT NULL,
    sanitized_enc BLOB,
    spans         TEXT NOT NULL DEFAULT '[]',
    notices       TEXT NOT NULL DEFAULT '[]',
    exposed       TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    UNIQUE (chat_id, seq)
);

CREATE TABLE dictionary (
    id          TEXT PRIMARY KEY,
    list        TEXT NOT NULL CHECK (list IN ('always', 'never')),
    type        TEXT,
    value_enc   BLOB NOT NULL,
    aliases_enc BLOB NOT NULL,
    comment_enc BLOB NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE patterns (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL,
    regex   TEXT NOT NULL,
    type    TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE policies (
    type   TEXT PRIMARY KEY,
    policy TEXT NOT NULL
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    user_id TEXT,
    chat_id TEXT,
    event   TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX items_by_chat ON items(chat_id, seq);
CREATE INDEX chats_by_user ON chats(user_id, updated_at);
