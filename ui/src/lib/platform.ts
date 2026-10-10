/**
 * Reader-facing platform names, the same mapping the daemon Markdown export
 * uses (`platform_name` in crates/aw-daemon/src/export/markdown.rs). An unknown
 * value is kept verbatim so a newer platform is shown rather than hidden.
 * Empty / whitespace is not a name — callers render 「不可得」 themselves.
 */
export function platformName(platform: string): string {
  switch (platform.trim().toLowerCase()) {
    case "linux":
      return "Linux";
    case "macos":
    case "darwin":
    case "mac":
      return "macOS";
    case "windows":
    case "win32":
      return "Windows";
    default:
      return platform;
  }
}
