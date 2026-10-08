/**
 * Minimal client-side check of the shared filter grammar
 * (docs/01-architecture/api-and-cli.md §4.2). It only catches what the UI can
 * report before a request: unbalanced quotes and parentheses, and unknown
 * fields. The daemon parser stays authoritative and its 400 carries the column.
 */

const FIELDS = new Set([
  "kind", "time", "evidence", "source", "proc", "pid", "proc_uid", "subtree", "tag",
  "exe", "argv", "cwd", "path", "dir", "op", "access", "bytes_read", "bytes_written",
  "domain", "ip", "port", "remote.ip", "remote.port", "local.port", "proto",
  "bytes_up", "bytes_down", "direct", "via_proxy", "qname", "qtype", "rcode",
  "method", "url", "host", "status", "req_bytes", "resp_bytes", "tool", "agent",
  "ipc_kind", "peer", "channel", "target", "rule", "severity",
]);

export interface FilterIssue {
  column: number;
  message: string;
  suggestion?: string;
}

function editDistance(a: string, b: string): number {
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  const cur = new Array<number>(b.length + 1);
  for (let i = 1; i <= a.length; i += 1) {
    cur[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    for (let j = 0; j <= b.length; j += 1) prev[j] = cur[j];
  }
  return prev[b.length];
}

function suggest(field: string): string | undefined {
  let best: string | undefined;
  let bestScore = 3;
  for (const known of FIELDS) {
    const score = editDistance(field, known);
    if (score < bestScore) {
      best = known;
      bestScore = score;
    }
  }
  return best;
}

export function checkFilter(input: string): FilterIssue | null {
  let quote: string | null = null;
  let depth = 0;
  let token = "";
  let tokenAt = 0;
  const flush = (column: number): FilterIssue | null => {
    if (!token) return null;
    const op = token.search(/[:~=<>!]/);
    if (op > 0) {
      const field = token.slice(0, op).toLowerCase();
      if (/^[a-z_][a-z0-9_.]*$/.test(field) && !FIELDS.has(field)) {
        return { column: tokenAt + 1, message: `未知字段 ${field}`, suggestion: suggest(field) };
      }
    }
    token = "";
    tokenAt = column;
    return null;
  };

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (quote) {
      if (ch === "\\" && quote === '"') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const issue = flush(i);
      if (issue) return issue;
      quote = ch;
      continue;
    }
    if (ch === "(") {
      depth += 1;
      continue;
    }
    if (ch === ")") {
      depth -= 1;
      if (depth < 0) return { column: i + 1, message: "多余的右括号" };
      continue;
    }
    if (/\s/u.test(ch)) {
      const issue = flush(i);
      if (issue) return issue;
      tokenAt = i + 1;
      continue;
    }
    if (!token) tokenAt = i;
    token += ch;
  }
  if (quote) return { column: input.length, message: "引号未闭合" };
  if (depth > 0) return { column: input.length, message: "括号未闭合" };
  return flush(input.length);
}
