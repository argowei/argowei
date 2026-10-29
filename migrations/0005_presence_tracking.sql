-- Presence tracking built on recorded observations.
--
-- A device's online/offline flag is a *derived* view; the evidence behind it
-- is kept so presence can be analyzed later (timelines, availability,
-- flapping, time-of-day patterns) instead of only the current state.
--
--   discovery_scans   one row per completed scan: when, where, how, how many
--   device_sightings  which devices answered in which scan (and from which IP)
--   events            state transitions (device.discovered / .online / .offline)
--
-- A device that did NOT answer a scan is recognised by the absence of a
-- sighting for a scan that did run, so "missed scans" is a query, not a
-- counter that can drift.
CREATE TABLE discovery_scans (
    id BIGSERIAL PRIMARY KEY,
    interface VARCHAR NOT NULL,
    -- Observation method; 'arp' today, room for passive sources later.
    method VARCHAR NOT NULL DEFAULT 'arp',
    scanned_at TIMESTAMPTZ NOT NULL,
    hosts_seen INTEGER NOT NULL
);

CREATE INDEX ix_discovery_scans_interface_time
    ON discovery_scans (interface, scanned_at DESC);

CREATE TABLE device_sightings (
    scan_id BIGINT NOT NULL REFERENCES discovery_scans (id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ip_address VARCHAR NOT NULL,
    PRIMARY KEY (scan_id, device_id, ip_address)
);

CREATE INDEX ix_device_sightings_device ON device_sightings (device_id, scan_id DESC);

-- Interface of the scan that last saw the device. Scans of other interfaces
-- say nothing about a device's presence on this one, so missed scans are
-- counted per interface. Devices recorded before this migration have no
-- value and are not marked offline until they are seen again.
ALTER TABLE devices ADD COLUMN last_seen_interface VARCHAR;

-- Generic event stream; the event timeline API/UI builds on this table.
CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    type VARCHAR NOT NULL,
    severity VARCHAR NOT NULL DEFAULT 'info'
        CHECK (severity IN ('info', 'warning', 'critical')),
    -- Kept (set to NULL) if the device is deleted, so history survives.
    device_id INTEGER REFERENCES devices (id) ON DELETE SET NULL,
    -- Structured evidence for the event (what was observed and why).
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_events_occurred_at ON events (occurred_at DESC, id DESC);
CREATE INDEX ix_events_device ON events (device_id, occurred_at DESC);
CREATE INDEX ix_events_type ON events (type, occurred_at DESC);
