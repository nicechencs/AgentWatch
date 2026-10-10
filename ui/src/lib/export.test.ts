/**
 * Export. In the desktop app it goes through the shell's Save As dialog; in
 * a browser it stays a normal download, and CSV is a named zip.
 * The native dialog itself is covered in app/src-tauri/src/export.rs.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { exportToFile } from "@/api/client";
import { isApiError } from "@/api/errors";
import zh from "@/i18n/zh.json";
import en from "@/i18n/en.json";

const ZH = zh as Record<string, string>;
const EN = en as Record<string, string>;
const t = (key: string, vars?: Record<string, string | number>) =>
  (ZH[key] ?? key).replace(/\{(\w+)\}/gu, (_, name: string) => String(vars?.[name] ?? `{${name}}`));

type W = { __TAURI_INTERNALS__?: { invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> } };

afterEach(() => {
  delete (window as unknown as W).__TAURI_INTERNALS__;
  vi.restoreAllMocks();
});

describe("export to file", () => {
  it("in the app, export goes through the shell's Save As and reports the path", async () => {
    const invoke = vi.fn(async (cmd: string, args?: Record<string, unknown>) => {
      expect(cmd).toBe("aw_save_export");
      // The reader's UTC offset rides along so the report shows local times.
      expect(args).toEqual({ sid: "s-1", format: "md", tz: -new Date().getTimezoneOffset() });
      return { status: 200, path: "/home/u/Documents/s-1.md", cancelled: false, error_body: null, bytes: 10 };
    });
    (window as unknown as W).__TAURI_INTERNALS__ = { invoke };
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await expect(exportToFile("s-1", "md")).resolves.toEqual({ kind: "saved", path: "/home/u/Documents/s-1.md" });
    // No webview download link, so nothing lands in the launch directory.
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(t("export.savedTo", { path: "/home/u/Documents/s-1.md" })).toBe("已保存到 /home/u/Documents/s-1.md");
  });

  it("a cancelled dialog is silent; a daemon error is the daemon's error", async () => {
    let answer: unknown = { status: 200, path: null, cancelled: true, error_body: null, bytes: 0 };
    (window as unknown as W).__TAURI_INTERNALS__ = { invoke: async () => answer };
    await expect(exportToFile("s-1", "csv")).resolves.toEqual({ kind: "cancelled" });
    answer = { status: 404, path: null, cancelled: false, error_body: '{"error":{"code":"not_found","message":"session not found"}}', bytes: 0 };
    const caught = await exportToFile("s-1", "md").catch((err: unknown) => err);
    expect(isApiError(caught) && caught.status === 404 && caught.code === "not_found").toBe(true);
  });

  it("in a browser it stays a normal download; CSV is named and labelled as a zip", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(new Uint8Array([0x50, 0x4b]), { status: 200 }));
    URL.createObjectURL = vi.fn(() => "blob:x");
    URL.revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    await expect(exportToFile("s-1", "csv")).resolves.toEqual({ kind: "downloaded", name: "s-1.csv.zip" });
    expect(click).toHaveBeenCalledOnce();
    expect(ZH["session.export.csv"]).toBe("CSV（压缩包）");
    expect(EN["session.export.csv"]).toBe("CSV (zip)");
  });
});
