-- What devices are called, per source.
--
-- Several sources can name one device and may disagree (the router's DNS says
-- one thing, the device itself another). Every source's latest answer is kept
-- in `device_names`; `devices.name` holds the one chosen for display by a fixed
-- priority, and `devices.name_source` says whose it is (NULL while the name is
-- still just the MAC address). A name the user types is the separate `label`
-- and is never touched here.
ALTER TABLE devices
    ADD COLUMN name_source VARCHAR
        CONSTRAINT devices_name_source_valid
        CHECK (name_source IN ('dhcp', 'mdns', 'netbios', 'rdns')),
    -- When names were last looked up for this device. Lookups are repeated at
    -- an interval (and sooner while no name is known), not on every scan.
    ADD COLUMN names_checked_at TIMESTAMPTZ;

CREATE TABLE device_names (
    device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    source VARCHAR NOT NULL
        CONSTRAINT device_names_source_valid CHECK (source IN ('dhcp', 'mdns', 'netbios', 'rdns')),
    name VARCHAR NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (device_id, source)
);
