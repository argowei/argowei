-- Device type: what the classifier infers, and what the user says.
--
-- The inference (with its confidence and the evidence behind it) and the
-- manual override live in separate columns, so re-classifying a device on
-- every scan can never overwrite a user's decision. The effective type is
-- the override if there is one, otherwise the inferred type.
--
-- Existing devices start as 'unknown' and are classified the next time a scan
-- sees them.
ALTER TABLE devices
    ADD COLUMN type_override VARCHAR
        CONSTRAINT devices_type_override_valid
        CHECK (type_override IN ('smartphone', 'laptop', 'server', 'iot', 'printer', 'router', 'unknown')),
    ADD COLUMN inferred_type VARCHAR NOT NULL DEFAULT 'unknown'
        CONSTRAINT devices_inferred_type_valid
        CHECK (inferred_type IN ('smartphone', 'laptop', 'server', 'iot', 'printer', 'router', 'unknown')),
    ADD COLUMN inferred_confidence SMALLINT NOT NULL DEFAULT 0
        CONSTRAINT devices_inferred_confidence_valid
        CHECK (inferred_confidence BETWEEN 0 AND 100),
    -- Every rule that fired: [{"kind", "detail", "type", "weight"}, ...]
    ADD COLUMN inferred_evidence JSONB NOT NULL DEFAULT '[]'::jsonb;
