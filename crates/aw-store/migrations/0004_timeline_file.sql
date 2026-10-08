-- P2-STORE-01. Rebuild `timeline` so the file_access branch exists.
--
-- 0002_timeline_view.sql (applied by query::ensure_timeline, not by the
-- versioned runner) UNIONs processes, net_flows, dns, and gaps. This script
-- drops that view and creates the same four branches plus file_access.
-- It does not add http, process_images, agent_events, ipc, rpc, or findings:
-- those tables are not in this database yet (0001 comment).
--
-- Column mapping, unchanged from 0002 except for the new branch:
--   * processes has no `id`. The view's `id` is `proc_uid`, `cat` is 'proc',
--     and the time column is `start_ns`.
--   * dns.proc_uid stays NULL when the row has no process. It is not 0.
--   * gaps have no proc_uid. `evidence` is the literal 'E1' (storage.md §3.1).
--   * file_access uses `first_ns`, `id`, and `proc_uid`. `cat` is 'file'.
--
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
  FROM file_access;
