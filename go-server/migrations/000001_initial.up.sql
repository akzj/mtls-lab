-- PBAC Schema: Permission-Based Access Control
-- Combined migration: schema + seed data

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS user_permissions (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    granted_by VARCHAR(255) DEFAULT 'system',
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_user_permissions_user_id ON user_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_permission_id ON user_permissions(permission_id);

-- Seed users
INSERT INTO users (username, email) VALUES
    ('admin', 'admin@lab.local'),
    ('ops', 'ops@lab.local'),
    ('dev', 'dev@lab.local')
ON CONFLICT (username) DO NOTHING;

-- Seed permissions
INSERT INTO permissions (name, description) VALUES
    ('devices:view', 'View devices'),
    ('devices:view_all', 'View all devices'),
    ('dc2:access', 'Access DC2'),
    ('tunnel:create', 'Create SSH tunnels'),
    ('tunnel:view', 'View SSH tunnels'),
    ('shell:dc1', 'Shell access to DC1'),
    ('shell:dc2', 'Shell access to DC2')
ON CONFLICT (name) DO NOTHING;

-- Admin gets all permissions
INSERT INTO user_permissions (user_id, permission_id)
SELECT u.id, p.id FROM users u, permissions p
WHERE u.username = 'admin'
  AND p.name IN ('devices:view', 'devices:view_all', 'dc2:access', 'tunnel:create', 'tunnel:view', 'shell:dc1', 'shell:dc2')
ON CONFLICT DO NOTHING;

-- Ops gets most permissions (not dc2:access, not shell:dc2)
INSERT INTO user_permissions (user_id, permission_id)
SELECT u.id, p.id FROM users u, permissions p
WHERE u.username = 'ops'
  AND p.name IN ('devices:view', 'devices:view_all', 'tunnel:create', 'tunnel:view', 'shell:dc1')
ON CONFLICT DO NOTHING;

-- Dev gets limited permissions
INSERT INTO user_permissions (user_id, permission_id)
SELECT u.id, p.id FROM users u, permissions p
WHERE u.username = 'dev'
  AND p.name IN ('devices:view', 'tunnel:view', 'shell:dc1')
ON CONFLICT DO NOTHING;
