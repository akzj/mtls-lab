-- Seed data: Users matching current RBAC config
INSERT INTO users (username, email) VALUES
    ('admin', 'admin@lab.local'),
    ('ops', 'ops@lab.local'),
    ('dev', 'dev@lab.local')
ON CONFLICT (username) DO NOTHING;

-- Seed data: Permissions matching current RBAC resources
INSERT INTO permissions (name, description) VALUES
    ('devices:view', 'View devices'),
    ('devices:view_all', 'View all devices'),
    ('dc2:access', 'Access DC2'),
    ('tunnel:create', 'Create SSH tunnels'),
    ('tunnel:view', 'View SSH tunnels'),
    ('shell:dc1', 'Shell access to DC1'),
    ('shell:dc2', 'Shell access to DC2')
ON CONFLICT (name) DO NOTHING;

-- Map users to permissions matching current group-based RBAC:
-- admin-group → all permissions
-- ops-group → devices:view, devices:view_all, tunnel:create, tunnel:view, shell:dc1
-- dev-group → devices:view, tunnel:view, shell:dc1

-- admin (admin-group replacement)
INSERT INTO user_permissions (user_id, permission_id)
SELECT u.id, p.id FROM users u, permissions p
WHERE u.username = 'admin'
  AND p.name IN ('devices:view', 'devices:view_all', 'dc2:access', 'tunnel:create', 'tunnel:view', 'shell:dc1', 'shell:dc2')
ON CONFLICT DO NOTHING;

-- ops (ops-group replacement)
INSERT INTO user_permissions (user_id, permission_id)
SELECT u.id, p.id FROM users u, permissions p
WHERE u.username = 'ops'
  AND p.name IN ('devices:view', 'devices:view_all', 'tunnel:create', 'tunnel:view', 'shell:dc1')
ON CONFLICT DO NOTHING;

-- dev (dev-group replacement)
INSERT INTO user_permissions (user_id, permission_id)
SELECT u.id, p.id FROM users u, permissions p
WHERE u.username = 'dev'
  AND p.name IN ('devices:view', 'tunnel:view', 'shell:dc1')
ON CONFLICT DO NOTHING;
