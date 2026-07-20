ALTER TABLE refresh_tokens
    ADD COLUMN access_token_id UUID REFERENCES access_tokens(id);

CREATE INDEX idx_refresh_tokens_access_token_id ON refresh_tokens(access_token_id);
