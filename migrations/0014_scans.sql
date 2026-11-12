-- nmap port scans (#14).
--
-- One row per requested scan. The target is the device's address at request
-- time (devices move), the profile names a fixed nmap argument set defined in
-- code. raw_xml keeps nmap's own output as evidence, so later analyses can
-- re-read details the parsed columns leave out.
CREATE TABLE scans (
    id BIGSERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    target_ip VARCHAR NOT NULL,
    profile VARCHAR NOT NULL
        CONSTRAINT scans_profile_valid CHECK (profile IN ('quick', 'service', 'full')),
    status VARCHAR NOT NULL DEFAULT 'queued'
        CONSTRAINT scans_status_valid
        CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'timed_out')),
    requested_by VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error TEXT,
    nmap_version VARCHAR,
    raw_xml TEXT,
    CONSTRAINT scans_finished_shape CHECK (
        (status IN ('queued', 'running')) = (finished_at IS NULL)
    )
);

-- At most one active scan per device: a second request is a conflict, and
-- the database settles the race between two requests at the same moment.
CREATE UNIQUE INDEX ux_scans_one_active_per_device
    ON scans (device_id) WHERE status IN ('queued', 'running');
CREATE INDEX ix_scans_device ON scans (device_id, id DESC);

-- Every port nmap listed for a scan (open, closed, filtered, ...).
CREATE TABLE scan_ports (
    scan_id BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    protocol VARCHAR NOT NULL,
    port INTEGER NOT NULL CONSTRAINT scan_ports_port_valid CHECK (port BETWEEN 0 AND 65535),
    state VARCHAR NOT NULL,
    reason VARCHAR,
    service VARCHAR,
    product VARCHAR,
    version VARCHAR,
    extra_info VARCHAR,
    PRIMARY KEY (scan_id, protocol, port)
);
