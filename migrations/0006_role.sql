ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';

-- Переносим старых админов (is_admin) в новую ролевую колонку.
UPDATE users SET role = 'admin' WHERE is_admin = TRUE AND role = 'user';
