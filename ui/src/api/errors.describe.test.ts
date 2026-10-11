/**
 * Error text the root page and the new-session form show. A non-JSON body
 * must not crash, and a launch refusal is a plain Chinese sentence rather
 * than the daemon's English.
 */
import { describe, expect, it } from "vitest";
import { ApiError, describeError } from "@/api/errors";
import zh from "@/i18n/zh.json";

const ZH = zh as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

describe("error text", () => {
  it("a non-JSON or 501 body does not crash and reads in Chinese", () => {
    const err = new ApiError(501, { not: "error-shaped" } as never, "Not Implemented");
    expect(describeError(err, t)).toBe(ZH["error.notImplemented"]);
    expect(describeError(new ApiError(401, null, ""), t)).toMatch(/aw ui/u);
    expect(describeError(new ApiError(500, null, ""), t)).toContain("500");
  });

  it("a wrong program is worded in Chinese, not the daemon's English", () => {
    const err = new ApiError(400, { error: { code: "program_not_found", message: "the program or the working directory was not found" } }, "x");
    const text = describeError(err, t);
    expect(text).toBe(ZH["error.programNotFound"]);
    expect(text).not.toMatch(/entity|not found/u);
    // Launch refusals are 403s with their own plain Chinese sentence, never
    // the daemon's English and never "open a terminal".
    for (const code of ["launch_other_user", "caller_unidentified", "caller_unknown", "drop_failed"]) {
      const said = describeError(new ApiError(403, { error: { code, message: "the daemon starts programs only as its own user; use `aw run -- <cmd>`" } }, "x"), t);
      expect(said).not.toMatch(/\b[a-z]{4,}\b|终端|aw run/u);
      expect(said).not.toBe(ZH["error.forbidden"]);
    }
  });

  it("uses the measured database-lock wait in the localized busy sentence", () => {
    const err = new ApiError(
      503,
      {
        error: {
          code: "db_busy",
          message: "The session database is busy (the service is writing). Waited 8 s and still couldn't get in; try again later.",
        },
      },
      "x",
    );
    expect(describeError(err, t)).toBe("会话数据库正忙（后台在写入），等了 8 秒还是没轮到，请稍后再试。");
  });
});
