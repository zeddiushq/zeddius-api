-- make target columns nullable with no db defaults
-- "null" means the user hasn't set a target yet, which is distinct from any specific value
ALTER TABLE users
    ALTER COLUMN target_calories DROP DEFAULT,
    ALTER COLUMN target_calories DROP NOT NULL,
    ALTER COLUMN target_protein_g DROP DEFAULT,
    ALTER COLUMN target_protein_g DROP NOT NULL,
    ALTER COLUMN target_sleep_hours DROP DEFAULT,
    ALTER COLUMN target_sleep_hours DROP NOT NULL;

-- drop redundant indexes — UNIQUE constraints already create indexes in postgres
DROP INDEX IF EXISTS idx_access_tokens_token_hash;
DROP INDEX IF EXISTS idx_refresh_tokens_token_hash;
DROP INDEX IF EXISTS idx_users_email;
