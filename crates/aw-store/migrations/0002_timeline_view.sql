-- P1 timeline view (storage.md §3.1, narrowed by P1-STORE-02).
--
-- The documented view UNIONs file_access, net_flows, dns, http, process_images,
-- agent_events, ipc_channels, agent_rpc, findings, and gaps. P1 only has
-- processes, net_flows, dns, and gaps (0001_init.sql). The other tables are
-- later migrations. This script does not ALTER any P1 table.
--
-- Column mapping, where 0001_init.sql disagrees with the documented view:
--   * processes has no `id`. The view's `id` is `proc_uid`, and `cat` is 'proc'.
--     storage.md uses process_images (ts_ns, id) for 'proc'; that table exists
--     but the task says the P1 union is processes, not process_images.
--   * processes time column is `start_ns`, not `ts_ns`.
--   * dns.proc_uid is nullable. A NULL stays NULL; it is not coerced to 0.
--   * gaps have no proc_uid and no evidence column. `proc_uid` is NULL.
--     `evidence` is the literal 'E1' from storage.md §3.1 (a gap is itself an
--     observation, not a guessed event). `id` is gaps.id.
--   * net_flows uses `start_ns` and net_flows.id, matching the documented branch.
--
-- Keyset pagination in the query layer is (ts_ns, id), not (ts_ns, cat, id).
-- `cat` is still selected so callers can tell the branches apart.

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
  FROM gaps;
