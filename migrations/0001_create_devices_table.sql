-- A device is identified by its MAC address, not by an IP address: the same
-- device can hold several IP addresses at once (an IPv4 address resolved via
-- ARP, plus one or more IPv6 addresses resolved via NDP — link-local, a
-- stable SLAAC address, and often a rotating privacy-extension address).
-- Splitting device identity from its addresses avoids treating each of those
-- as a separate "device" once NDP discovery is added.
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    mac_address VARCHAR NOT NULL,
    is_online BOOLEAN NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ix_devices_mac_address ON devices (mac_address);

-- One row per address currently or previously seen for a device. A device
-- can have multiple simultaneous addresses (IPv4 via ARP, several IPv6
-- addresses via NDP); keeping history here (rather than overwriting a single
-- column) is also what later scan-diffing ("a new address appeared") needs.
CREATE TYPE ip_protocol AS ENUM ('ipv4', 'ipv6');

CREATE TABLE device_addresses (
    id SERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ip_address VARCHAR NOT NULL,
    protocol ip_protocol NOT NULL,
    -- How this address was learned: 'arp' or 'ndp' today, room for e.g. 'dhcp'
    -- lease observation later without another migration.
    source VARCHAR NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ix_device_addresses_ip_address ON device_addresses (ip_address);
CREATE INDEX ix_device_addresses_device_id ON device_addresses (device_id);
