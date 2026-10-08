-- P3-STORE-01. Rebuild `timeline` so the http and findings branches exist.
--
-- 0004_timeline_file.sql UNIONs processes, net_flows, dns, gaps, and
-- file_access. This script drops that view and creates the same five branches
-- plus http and findings. It does not add process_images, agent_events, ipc,
-- or rpc: those tables are not in this database yet (0001 comment).
--
-- Run this only after 0003 (file_access) and 0006 (http, findings). The view
-- reads all three. A database that has not created file_access cannot build it;
-- query::ensure_timeline still installs the P1 view for that database, and
-- does not run this script (CREATE VIEW IF NOT EXISTS would keep the old one).
--
-- Column mapping, unchanged from 0004 except for the two new branches:
--   * processes has no `id`. The view's `id` is `proc_uid`, `cat` is 'proc',
--     and the time column is `start_ns`.
--   * dns.proc_uid stays NULL when the row has no process. It is not 0.
--   * gaps have no proc_uid. `evidence` is the literal 'E1' (storage.md §3.1).
--   * file_access uses `first_ns`, `id`, and `proc_uid`. `cat` is 'file'.
--   * http uses `ts_ns`. `proc_uid` is nullable and stays NULL. `cat` is 'http'.
--   * findings uses `first_ns` and has no process column, so `proc_uid` is NULL.
--     `cat` is 'finding' (storage.md §3.1). `id` is findings.id.
--
-- The column list is still (session_id, ts_ns, cat, id, proc_uid, evidence).
-- Query-layer keyset pagination stays (ts_ns, id).

DROP VIEW IF EXISTS timeline;

CREATE VIEW timeline AS
  SELECT session_id,
         start_ns AS ts_ns,
         'proc' AS cat,
         proc_uid AS id,
         proc_uid,
         evidence
  FROM processes
  UNION ALL
  SELECT session_id,
         start_ns AS ts_ns,
         'net' AS cat,
         id,
         proc_uid,
         evidence
  FROM net_flows
  UNION ALL
  SELECT session_id,
         ts_ns,
         'dns' AS cat,
         id,
         proc_uid,
         evidence
  FROM dns
  UNION ALL
  SELECT session_id,
         from_ns AS ts_ns,
         'gap' AS cat,
         id,
         NULL AS proc_uid,
         'E1' AS evidence
  FROM gaps
  UNION ALL
  SELECT session_id,
         first_ns AS ts_ns,
         'file' AS cat,
         id,
         proc_uid,
         evidence
  FROM file_access
  UNION ALL
  SELECT session_id,
         ts_ns,
         'http' AS cat,
         id,
         proc_uid,
         evidence
  FROM http
  UNION ALL
  SELECT session_id,
         first_ns AS ts_ns,
         'finding' AS cat,
         id,
         NULL AS proc_uid,
         evidence
  FROM findings;
