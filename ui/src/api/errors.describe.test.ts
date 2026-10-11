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

  it("a launch error keeps the daemon sentence that names the failed input", () => {
    const err = new ApiError(400, { error: { code: "program_not_found", message: "找不到程序「tool」，请检查名字或路径" } }, "x");
    const text = describeError(err, t);
    expect(text).toBe("找不到程序「tool」，请检查名字或路径");
    // Launch refusals are 403s with their own plain Chinese sentence, never
    // the daemon's English and never "open a terminal".
    for (const code of ["caller_unidentified", "caller_unknown", "drop_failed"]) {
      const said = describeError(new ApiError(403, { error: { code, message: "the daemon starts programs only as its own user; use `aw run -- <cmd>`" } }, "x"), t);
      expect(said).not.toMatch(/\b[a-z]{4,}\b|终端|aw run/u);
      expect(said).not.toBe(ZH["error.forbidden"]);
    }
  });

  it("uses the structured database-lock wait in the localized busy sentence", () => {
    const err = new ApiError(
      503,
      {
        error: {
          code: "db_busy",
          message: "developer detail without a wait count",
          waited_seconds: 8,
        },
      },
      "x",
    );
    expect(describeError(err, t)).toBe("会话数据库正忙（后台在写入），等了 8 秒还是没轮到，请稍后再试。");
  });

  it("omits a missing or zero database-lock wait without saying zero seconds", () => {
    for (const waited_seconds of [undefined, 0]) {
      const text = describeError(
        new ApiError(503, { error: { code: "db_busy", message: "Waited 9 s", waited_seconds } }, "x"),
        t,
      );
      expect(text).toBe("会话数据库正忙（后台在写入），请稍后再试。");
      expect(text).not.toContain("等了 0 秒");
    }
  });

  it("uses the agreed Chinese wording for Windows peer-identity failures", () => {
    const cases = [
      ["unidentified_peer", "后台认不出你是哪个用户，已拒绝这次请求。请确认 `aw` 和后台是同一个版本，还不行就重启后台。"],
      ["daemon_untrusted_server", "连上的不是 AgentWatch 后台，可能有别的程序占用了这个通信口。为防内容被它拿到，这次没有发送任何内容。"],
      ["daemon_server_unverified", "没法确认连上的是不是 AgentWatch 后台，为防连到冒充的程序，这次没有发送任何内容。请重启后台后再试。"],
    ] as const;
    for (const [code, expected] of cases) {
      expect(describeError(new ApiError(403, { error: { code, message: "developer detail" } }, "x"), t)).toBe(expected);
    }
  });

  it("uses the daemon-owner-only code and account name", () => {
    const message = "这个后台是「runner」自己运行的，只能替「runner」启动程序，已拒绝。请用你自己运行的后台，或者用管理员运行的后台。";
    expect(
      describeError(
        new ApiError(
          403,
          { error: { code: "daemon_owner_only", message, detail: { daemon_owner: "runner" } } },
          "x",
        ),
        t,
      ),
    ).toBe(message);
  });
});
