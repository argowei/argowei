-- User-provided label and notes for a device.
--
-- `name` keeps what discovery derived (the MAC until a hostname source
-- exists); `label` is what the user typed. They are separate columns so
-- discovery can keep refreshing `name` without ever touching user input, and
-- a label always wins when both are present.
ALTER TABLE devices
    ADD COLUMN label VARCHAR,
    ADD COLUMN notes TEXT NOT NULL DEFAULT '';
