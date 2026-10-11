import { describe, expect, it } from "vitest";
import en from "@/i18n/en.json";
import zh from "@/i18n/zh.json";
import { sessionStatus } from "@/lib/session-status";

const catalogs = { zh, en } as const;

const expected = {
  zh: {
    stopped: ["已停止记录", null],
    exited: ["程序已退出", null],
    user_stop: ["已停止记录", null],
    program_exit: ["程序已退出", null],
    daemon_restart: ["记录已中断", "后台重启，记录已中断"],
    daemon_shutdown: ["记录已中断", "后台重启，记录已中断"],
    stop: ["停止记录", "程序还在运行，只是不再记录"],
  },
  en: {
    stopped: ["Recording stopped", null],
    exited: ["Program exited", null],
    user_stop: ["Recording stopped", null],
    program_exit: ["Program exited", null],
    daemon_restart: ["Recording interrupted", "The background service restarted; recording was interrupted"],
    daemon_shutdown: ["Recording interrupted", "The background service restarted; recording was interrupted"],
    stop: ["Stop recording", "The program is still running; it is just no longer recorded"],
  },
} as const;

for (const lang of ["zh", "en"] as const) {
  const t = (key: string) => (catalogs[lang] as Record<string, string>)[key] ?? key;

  describe(`session status (${lang})`, () => {
    it.each(["stopped", "exited", "user_stop", "program_exit", "daemon_restart", "daemon_shutdown"] as const)("maps %s", (reason) => {
      const [label, explanation] = expected[lang][reason];
      expect(sessionStatus({ ended_ns: 2, end_reason: reason }, t)).toEqual({
        kind: reason === "user_stop" || reason === "stopped" ? "user_stop" : reason.startsWith("daemon_") ? "daemon_restart" : "program_exit",
        label,
        explanation,
      });
    });

    it("has the exact stop action and success notice", () => {
      expect([t("session.stop"), t("session.stopNotice")]).toEqual(expected[lang].stop);
    });

    it("treats null and unknown ended reasons as program exit", () => {
      expect(sessionStatus({ ended_ns: 2, end_reason: null }, t).label).toBe(t("session.stopped"));
      expect(sessionStatus({ ended_ns: 2, end_reason: "future_reason" }, t).label).toBe(t("session.stopped"));
    });
  });
}
