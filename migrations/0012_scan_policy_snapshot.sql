-- Replay must know which production thresholds were actually used when a
-- completed scan updated presence. Older attempts cannot be backfilled from
-- current settings, so their snapshots remain NULL and are not auditable.
ALTER TABLE scan_attempts
    ADD COLUMN offline_after_missed_scans BIGINT,
    ADD COLUMN offline_after_secs BIGINT,
    ADD CONSTRAINT scan_attempt_policy_shape CHECK (
        (outcome = 'completed' AND (
            (offline_after_missed_scans IS NULL AND offline_after_secs IS NULL)
            OR (offline_after_missed_scans IS NOT NULL AND offline_after_secs IS NOT NULL
                AND offline_after_missed_scans > 0 AND offline_after_secs >= 0)
        ))
        OR (outcome <> 'completed' AND offline_after_missed_scans IS NULL
            AND offline_after_secs IS NULL)
    );
