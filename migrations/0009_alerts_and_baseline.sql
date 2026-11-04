-- Alerts, and the baseline that keeps a fresh install from raising one for
-- every device already on the network.
--
-- An alert is something the user should look at, with a life cycle
-- (open -> acknowledged -> resolved). `device.new` is the first type; others
-- (anomalies, new CVEs, ...) reuse the same table.
CREATE TABLE alerts (
    id BIGSERIAL PRIMARY KEY,
    type VARCHAR NOT NULL,
    severity VARCHAR NOT NULL DEFAULT 'warning'
        CONSTRAINT alerts_severity_valid CHECK (severity IN ('info', 'warning', 'critical')),
    -- The alert outlives its device (the device row may be removed later).
    device_id INTEGER REFERENCES devices (id) ON DELETE SET NULL,
    status VARCHAR NOT NULL DEFAULT 'open'
        CONSTRAINT alerts_status_valid CHECK (status IN ('open', 'acknowledged', 'resolved')),
    created_at TIMESTAMPTZ NOT NULL,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by VARCHAR,
    resolved_at TIMESTAMPTZ,
    resolved_by VARCHAR,
    -- What was observed when the alert was raised.
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_alerts_status_created ON alerts (status, created_at DESC, id DESC);
CREATE INDEX ix_alerts_device ON alerts (device_id);

-- A device is new exactly once. The unique index makes "exactly one alert
-- per new device" a property of the database, not just of the code path.
CREATE UNIQUE INDEX ix_alerts_one_new_device_alert
    ON alerts (device_id) WHERE type = 'device.new';

-- When each interface was first scanned. Devices found during an
-- interface's first scan (and within the configured window after it) are
-- learned silently instead of alerting. Kept apart from `discovery_scans` so
-- that cleaning up old scans can never make an interface look new again.
CREATE TABLE baselines (
    interface VARCHAR PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL
);

-- Small key/value store for settings that are data rather than code.
CREATE TABLE system_settings (
    key VARCHAR PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
