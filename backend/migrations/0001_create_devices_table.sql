CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    ip_address VARCHAR NOT NULL,
    mac_address VARCHAR,
    is_online BOOLEAN NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ix_devices_ip_address ON devices (ip_address);
CREATE UNIQUE INDEX ix_devices_mac_address ON devices (mac_address);
