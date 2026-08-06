-- Full-entropy opaque token (same generation/hashing as access/refresh
-- tokens), not a short code — this is delivered via a clicked link, not
-- manually typed back into the same session, so no attempt-lockout is
-- needed the way the 6-digit verification code required one.
ALTER TABLE users
    ADD COLUMN password_reset_token_hash TEXT,
    ADD COLUMN password_reset_token_expires_at TIMESTAMPTZ;
