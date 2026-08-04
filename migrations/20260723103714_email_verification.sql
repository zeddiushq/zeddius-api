ALTER TABLE users
    ADD COLUMN email_verified_at TIMESTAMPTZ,
    ADD COLUMN email_verification_code_hash TEXT,
    ADD COLUMN email_verification_code_expires_at TIMESTAMPTZ;

-- Existing rows predate this feature and were reachable in production before
-- any verification step existed — grandfather them in rather than locking out
-- accounts that were never given a chance to verify.
UPDATE users SET email_verified_at = created_at;

-- Uniqueness now only applies to verified emails. An unverified row is a
-- pending claim, not a binding one — multiple can coexist under the same
-- email until one of them actually proves ownership.
ALTER TABLE users DROP CONSTRAINT users_email_key;
CREATE UNIQUE INDEX users_email_verified_unique ON users (email) WHERE email_verified_at IS NOT NULL;
