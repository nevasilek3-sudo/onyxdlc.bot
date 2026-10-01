CREATE TABLE IF NOT EXISTS cloud_configs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    share_key TEXT NOT NULL UNIQUE,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS cloud_themes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    share_key TEXT NOT NULL UNIQUE,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_cloud_configs_user ON cloud_configs(user_id);
CREATE INDEX IF NOT EXISTS idx_cloud_themes_user ON cloud_themes(user_id);
CREATE INDEX IF NOT EXISTS idx_cloud_configs_key ON cloud_configs(share_key);
CREATE INDEX IF NOT EXISTS idx_cloud_themes_key ON cloud_themes(share_key);

CREATE TABLE IF NOT EXISTS cloud_friends (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nick TEXT NOT NULL,
    alias TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, nick)
);

CREATE INDEX IF NOT EXISTS idx_cloud_friends_user ON cloud_friends(user_id);
