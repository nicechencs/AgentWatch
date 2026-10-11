/**
 * Preview of a custom redaction rule. The daemon compiles the pattern as a
 * regular expression (aw-pipeline `redact/engine.rs`), so the preview does
 * too; it used to replace the literal text, which disagreed with the label
 * and with what the daemon would do. JavaScript and Rust regex agree on the
 * common syntax; a pattern JavaScript cannot compile is reported, not guessed.
 */
export function redactPreview(pattern: string, sample: string): { text: string; invalid: boolean } {
  if (!pattern) return { text: sample, invalid: false };
  try {
    return { text: sample.replace(new RegExp(pattern, "gu"), "«redacted:custom»"), invalid: false };
  } catch {
    return { text: sample, invalid: true };
  }
}
