-- Optional review metadata is encrypted with the gold corpus key, like text and spans.
ALTER TABLE gold ADD COLUMN metadata_enc BLOB;
