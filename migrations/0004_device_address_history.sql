-- Keep address history per device.
--
-- The original unique index on `ip_address` alone allowed one row per IP, so
-- when an IP moved from device A to device B (DHCP lease change, device swap)
-- the only options were to steal A's row, losing the fact that A ever held it,
-- or to fail. Uniqueness is now per (device, address); the current holder of
-- an IP is the row with the newest `last_seen`.
DROP INDEX ix_device_addresses_ip_address;

CREATE UNIQUE INDEX ix_device_addresses_device_ip
    ON device_addresses (device_id, ip_address);

CREATE INDEX ix_device_addresses_ip_last_seen
    ON device_addresses (ip_address, last_seen DESC);
