import type { ApiErrorBody } from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly column: number | null;
  readonly suggestion: string | null;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.error.message ?? fallback);
    this.name = "ApiError";
    this.status = status;
    this.code = body?.error.code ?? "unknown";
    this.column = body?.error.column ?? null;
    this.suggestion = body?.error.suggestion ?? null;
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}
