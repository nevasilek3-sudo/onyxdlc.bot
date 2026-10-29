CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    telegram_id BIGINT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email_hash TEXT NOT NULL UNIQUE,
    email_enc TEXT NOT NULL,
    hwid_hash TEXT,
    hwid_enc TEXT,
    sub_plan TEXT NOT NULL DEFAULT 'none',
    sub_issued_at TIMESTAMPTZ,
    sub_expires_at TIMESTAMPTZ,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
