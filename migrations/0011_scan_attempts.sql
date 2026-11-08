-- An attempt is evidence about the collector, not evidence of device absence.
-- Only completed attempts point to a committed discovery scan. A database
-- outage cannot itself be journaled here; the scheduler still logs that error.
CREATE TABLE scan_attempts (
    id BIGSERIAL PRIMARY KEY,
    interface VARCHAR NOT NULL,
    -- Outcome time: for completed scans this equals discovery_scans.scanned_at.
    attempted_at TIMESTAMPTZ NOT NULL,
    outcome VARCHAR NOT NULL CHECK (outcome IN ('completed', 'failed', 'skipped')),
    scan_id BIGINT UNIQUE REFERENCES discovery_scans (id),
    failure_kind VARCHAR CHECK (failure_kind IN ('scanner', 'task')),
    CONSTRAINT scan_attempt_shape CHECK (
        (outcome = 'completed' AND scan_id IS NOT NULL AND failure_kind IS NULL)
        OR (outcome = 'failed' AND scan_id IS NULL AND failure_kind IS NOT NULL)
        OR (outcome = 'skipped' AND scan_id IS NULL AND failure_kind IS NULL)
    )
);

CREATE INDEX ix_scan_attempts_interface_time
    ON scan_attempts (interface, attempted_at, id);
