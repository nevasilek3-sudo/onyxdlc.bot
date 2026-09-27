DROP TABLE IF EXISTS users;

CREATE TABLE users (
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
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
