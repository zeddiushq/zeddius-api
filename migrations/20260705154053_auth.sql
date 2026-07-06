CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL UNIQUE,
    username            TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL,
    password_hash       TEXT,
    onboarding_complete BOOLEAN NOT NULL DEFAULT FALSE,
    height_cm           REAL,
    birthdate           DATE,
    target_calories     INT NOT NULL DEFAULT 2300,
    target_protein_g    INT NOT NULL DEFAULT 190,
    target_sleep_hours  REAL NOT NULL DEFAULT 7.5,
    timezone            TEXT NOT NULL DEFAULT 'UTC',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_accounts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_user_id)
);

CREATE TABLE access_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- indexes for token lookups (hit on every authenticated request)
CREATE INDEX idx_access_tokens_token_hash ON access_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- indexes for user lookups by auth credentials
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);
