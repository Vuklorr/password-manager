CREATE TABLE vault_user (
    id UUID PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    salt VARCHAR(44) NOT NULL,
    verifier VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE vault_session (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES vault_user(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX session_expiry_idx ON vault_session(expires_at);
CREATE TABLE vault_entry (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES vault_user(id) ON DELETE CASCADE,
    iv VARCHAR(16) NOT NULL,
    ciphertext TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX vault_entry_user_idx ON vault_entry(user_id);
