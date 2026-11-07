-- Synthetic dashboard fixture. Use only in a disposable, freshly migrated
-- database. RFC 5737 documentation addresses and locally administered MACs
-- ensure that no real network identity is represented.
INSERT INTO devices
    (name, mac_address, is_online, first_seen, last_seen, last_seen_interface,
     label, trust_level, inferred_type, inferred_confidence)
VALUES
    ('lab-router', '02:00:00:00:00:01', true, now() - interval '12 days', now() - interval '2 minutes', 'lab0',
     'Lab router', 'trusted', 'router', 90),
    ('lab-server', '02:00:00:00:00:02', true, now() - interval '10 days', now() - interval '4 minutes', 'lab0',
     'Build server', 'trusted', 'server', 85),
    ('lab-laptop', '02:00:00:00:00:03', true, now() - interval '7 days', now() - interval '8 minutes', 'lab0',
     'Test laptop', 'normal', 'laptop', 75),
    ('lab-printer', '02:00:00:00:00:04', false, now() - interval '5 days', now() - interval '3 hours', 'lab0',
     'Office printer', 'unknown', 'printer', 70),
    ('lab-sensor', '02:00:00:00:00:05', true, now() - interval '2 days', now() - interval '6 minutes', 'lab0',
     'Temperature sensor', 'restricted', 'iot', 65);

INSERT INTO device_addresses (device_id, ip_address, protocol, source, first_seen, last_seen)
SELECT id,
       ('192.0.2.' || right(mac_address, 2)::integer)::varchar,
       'ipv4'::ip_protocol,
       'arp',
       first_seen,
       last_seen
FROM devices
WHERE mac_address LIKE '02:00:00:00:00:%';
