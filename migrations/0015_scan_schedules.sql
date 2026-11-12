-- Scheduled port scans (#16).
--
-- A schedule says when (cron, evaluated in the server's time zone), how
-- (profile) and what (one device, a group, or every device) to scan.
-- next_run_at is stored so schedules survive restarts; a run that was missed
-- while the server was down is skipped, not replayed (see the scheduler).
-- target_id is not a foreign key because it points at a device or a group
-- depending on target_kind; a target that no longer exists simply scans
-- nothing.
CREATE TABLE scan_schedules (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    cron VARCHAR NOT NULL,
    profile VARCHAR NOT NULL
        CONSTRAINT scan_schedules_profile_valid CHECK (profile IN ('quick', 'service', 'full')),
    target_kind VARCHAR NOT NULL
        CONSTRAINT scan_schedules_target_kind_valid CHECK (target_kind IN ('device', 'group', 'all')),
    target_id INTEGER,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    CONSTRAINT scan_schedules_target_shape CHECK ((target_kind = 'all') = (target_id IS NULL)),
    CONSTRAINT scan_schedules_next_run_when_enabled CHECK (NOT enabled OR next_run_at IS NOT NULL)
);

CREATE UNIQUE INDEX ux_scan_schedules_name ON scan_schedules (lower(name));
CREATE INDEX ix_scan_schedules_due ON scan_schedules (next_run_at) WHERE enabled;

-- Which schedule queued a scan (null: started by a user). Lets a schedule
-- skip a run while its previous run is still going, across restarts too.
ALTER TABLE scans
    ADD COLUMN schedule_id INTEGER REFERENCES scan_schedules (id) ON DELETE SET NULL;
CREATE INDEX ix_scans_schedule_active ON scans (schedule_id) WHERE status IN ('queued', 'running');
