import type { ApiErrorBody } from "./types";

/** Shape check: a 501 or proxy page may answer JSON that is not `{error: {...}}`. */
function errorPart(body: unknown): Partial<ApiErrorBody["error"]> | null {
  if (typeof body !== "object" || body === null) return null;
  const inner = (body as { error?: unknown }).error;
  return typeof inner === "object" && inner !== null ? (inner as Partial<ApiErrorBody["error"]>) : null;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly column: number | null;
  readonly suggestion: string | null;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    const part = errorPart(body);
    super(typeof part?.message === "string" && part.message ? part.message : fallback);
    this.name = "ApiError";
    this.status = status;
    this.code = typeof part?.code === "string" ? part.code : "unknown";
    this.column = typeof part?.column === "number" ? part.column : null;
    this.suggestion = typeof part?.suggestion === "string" ? part.suggestion : null;
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

type T = (key: string, vars?: Record<string, string | number>) => string;

/**
 * What to tell the user about a failed request. Common daemon errors are
 * English developer text ("bearer token required", "session not found");
 * those become a plain sentence. Anything else keeps the daemon's message, and
 * an empty one says which status came back instead of printing nothing.
 */
export function describeError(error: unknown, t: T): string {
  if (error instanceof ApiError) {
    if (error.status === 401 || error.code === "unauthorized") return t("error.unauthorized");
    if (error.status === 403 || error.code === "forbidden") return t("error.forbidden");
    if (error.status === 501 || error.code === "not_implemented") return t("error.notImplemented");
    if (error.status === 404 && /session/iu.test(error.message)) return t("error.sessionNotFound");
    if (error.status === 404) return t("error.notFound");
    if (error.message && error.message !== "unknown") return error.message;
    return t("error.status", { status: error.status });
  }
  if (error instanceof Error && error.message) return error.message;
  return t("error.unknown");
}
