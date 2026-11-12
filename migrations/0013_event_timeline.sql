-- Event timeline (#17).
--
-- schema_version: version of the payload schema for the event's type (see
-- argowei-core events.rs and docs/EVENTS.md). Existing rows are all v1.
--
-- tx_id: the transaction that wrote the event. The timeline pages by
-- (tx_id, id) and only serves events of transactions older than every running
-- one, so an event committed late can never land behind a reader's cursor
-- (ids are handed out at insert, not at commit). Existing rows all get this
-- migration's transaction id and keep their id order.
ALTER TABLE events
    ADD COLUMN schema_version SMALLINT NOT NULL DEFAULT 1
        CONSTRAINT events_schema_version_positive CHECK (schema_version > 0),
    ADD COLUMN tx_id xid8 NOT NULL DEFAULT pg_current_xact_id();

CREATE INDEX ix_events_timeline ON events (tx_id DESC, id DESC);
CREATE INDEX ix_events_device_timeline ON events (device_id, tx_id DESC, id DESC);
