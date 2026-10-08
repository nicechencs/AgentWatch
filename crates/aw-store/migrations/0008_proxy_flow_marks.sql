-- P3-PIPE-01. Columns a proxy rewrite needs on `http`.
--
-- net_flows.via_proxy and net_flows.direct already exist (0001_init.sql, both
-- INTEGER NOT NULL DEFAULT 0). This file does not ALTER net_flows and does not
-- rebuild the timeline view.
--
-- http (0006) has no field_evidence and no na_reason. A direct or QUIC flow has
-- no URL; that absence is NA(direct_bypass_proxy) or NA(quic). The http table's
-- url column is NOT NULL, so the reason cannot live there as an empty string.
-- These two columns are NULL when the row has nothing to add. They are not
-- given a default: a default of '' or 0 would mean "unknown".
--
-- SQLite parses a script before it runs, and it has no ADD COLUMN IF NOT EXISTS.
-- An unconditional ALTER fails on a database that already has the column.
-- migrate::apply_proxy_schema probes sqlite_master-equivalent table_info and
-- runs each statement below only when that column is absent. Do not execute
-- this file with execute_batch on a database whose http was built by hand
-- with these columns already on it; call apply_proxy_schema.
--
-- direct:true and via_proxy:true are already fields of the filter compiler
-- (query::compile, Field::Direct and Field::ViaProxy, kind net, columns
-- net_flows.direct and net_flows.via_proxy). This migration does not register
-- them again. schema_meta has no filter table to insert into.
--
-- schema_version is written by the migrator, not by this file.

ALTER TABLE http ADD COLUMN field_evidence TEXT;

ALTER TABLE http ADD COLUMN na_reason TEXT;
