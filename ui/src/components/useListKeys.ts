import { useEffect } from "react";

interface Options {
  count: number;
  cursor: number;
  setCursor: (next: number) => void;
  onOpen: () => void;
  onClose: () => void;
  enabled?: boolean;
}

/**
 * j/k move, Enter opens, Esc closes (ui §4). Skipped while typing in a field,
 * so the filter box keeps its own keys.
 */
export function useListKeys({ count, cursor, setCursor, onOpen, onClose, enabled = true }: Options) {
  useEffect(() => {
    if (!enabled) return;
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) {
        return;
      }
      if (event.key === "j" || event.key === "ArrowDown") {
        event.preventDefault();
        setCursor(Math.min(count - 1, cursor + 1));
      } else if (event.key === "k" || event.key === "ArrowUp") {
        event.preventDefault();
        setCursor(Math.max(0, cursor - 1));
      } else if (event.key === "Enter") {
        event.preventDefault();
        onOpen();
      } else if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [enabled, count, cursor, setCursor, onOpen, onClose]);
}
