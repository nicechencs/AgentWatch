import { describe, expect, it } from "vitest";
import { platformName } from "@/lib/platform";

describe("platform names", () => {
  it("uses the same reader-facing names as the daemon Markdown export", () => {
    expect(platformName("linux")).toBe("Linux");
    expect(platformName("LINUX")).toBe("Linux");
    expect(platformName(" macos ")).toBe("macOS");
    expect(platformName("darwin")).toBe("macOS");
    expect(platformName("mac")).toBe("macOS");
    expect(platformName("windows")).toBe("Windows");
    expect(platformName("win32")).toBe("Windows");
  });

  it("keeps an unknown value unchanged, including its case", () => {
    expect(platformName("freebsd")).toBe("freebsd");
    expect(platformName("Haiku")).toBe("Haiku");
  });
});
