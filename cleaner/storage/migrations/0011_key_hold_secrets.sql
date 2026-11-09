-- Gateway key setting: tool arguments keep SECRET and ACCOUNT replacements inside addresses of unknown hosts (on by default).
ALTER TABLE api_keys ADD COLUMN hold_secrets INTEGER NOT NULL DEFAULT 1;
