-- Bounds how many wrong guesses a single verification code tolerates before
-- being burned, independent of the IP-keyed rate limiter — a token issued
-- unconditionally at registration is enough for the holder to brute-force
-- their own row's code otherwise, regardless of which email it was registered under.
ALTER TABLE users
    ADD COLUMN email_verification_attempts INT NOT NULL DEFAULT 0;
