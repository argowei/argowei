-- Device groups and per-device trust level (classification only).
--
-- Enforcement is a later feature (policy engine); a group's default behavior
-- is stored here as data so that engine can consume it instead of reading it
-- from code. Known `defaults` keys: internet (allow | block | schedule),
-- lan (allow | block | block_trusted), dns_filter, tracker_block,
-- category_blocking, hardening_checks, essential_services_only,
-- manual_release. Unknown keys are kept as given.
--
-- System groups are identified by a stable `slug`; custom groups have none.
CREATE TABLE device_groups (
    id SERIAL PRIMARY KEY,
    slug VARCHAR UNIQUE,
    name VARCHAR NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT false,
    defaults JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT device_groups_system_has_slug CHECK (is_system = (slug IS NOT NULL))
);

-- Names are unique regardless of case, so "iot" cannot shadow "IoT".
CREATE UNIQUE INDEX ix_device_groups_name ON device_groups (lower(name));

-- Safe to run again: existing system groups are left exactly as they are
-- (including any edits made to their description or defaults).
CREATE FUNCTION seed_system_groups() RETURNS void AS $$
BEGIN
    INSERT INTO device_groups (slug, name, description, is_system, defaults) VALUES
        ('unassigned', 'Unassigned', 'Devices that have not been classified yet. New devices start here.', true,
         '{}'),
        ('trusted', 'Trusted', 'Full LAN and internet access, no restrictions.', true,
         '{"internet": "allow", "lan": "allow"}'),
        ('servers', 'Servers', 'Full access; regular hardening checks.', true,
         '{"internet": "allow", "lan": "allow", "hardening_checks": true}'),
        ('guest', 'Guest', 'Internet only, no LAN access, DNS filter active.', true,
         '{"internet": "allow", "lan": "block", "dns_filter": true}'),
        ('iot', 'IoT', 'Internet allowed, no access to trusted devices, trackers blocked.', true,
         '{"internet": "allow", "lan": "block_trusted", "tracker_block": true}'),
        ('kids', 'Kids', 'Internet on a schedule, category blocking active.', true,
         '{"internet": "schedule", "lan": "allow", "category_blocking": true}'),
        ('quarantine', 'Quarantine', 'No internet, no LAN, essential services only; released manually.', true,
         '{"internet": "block", "lan": "block", "essential_services_only": true, "manual_release": true}'),
        ('blocked', 'Blocked', 'Completely blocked.', true,
         '{"internet": "block", "lan": "block"}')
    ON CONFLICT (slug) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

SELECT seed_system_groups();

-- Every device is in exactly one group: a single NOT NULL column. New and
-- existing devices start in the "Unassigned" system group (the column default
-- is its id, resolved here because a default cannot contain a subquery).
-- Deleting a group that still has devices is refused rather than silently
-- moving them.
DO $$
BEGIN
    EXECUTE format(
        'ALTER TABLE devices ADD COLUMN group_id INTEGER NOT NULL DEFAULT %s '
        'REFERENCES device_groups (id) ON DELETE RESTRICT',
        (SELECT id FROM device_groups WHERE slug = 'unassigned')
    );
END
$$;

ALTER TABLE devices
    ADD COLUMN trust_level VARCHAR NOT NULL DEFAULT 'unknown'
        CONSTRAINT devices_trust_level_valid
        CHECK (trust_level IN ('trusted', 'normal', 'restricted', 'unknown', 'suspicious'));

CREATE INDEX ix_devices_group_id ON devices (group_id);
