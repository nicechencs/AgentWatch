import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Lang } from "./i18n";

export type Theme = "system" | "light" | "dark";
export type TimeFormat = "local" | "utc";

interface Prefs {
  lang: Lang;
  theme: Theme;
  timeFormat: TimeFormat;
  setLang: (lang: Lang) => void;
  setTheme: (theme: Theme) => void;
  setTimeFormat: (format: TimeFormat) => void;
}

const KEY = "aw.prefs";

interface Stored {
  lang?: Lang;
  theme?: Theme;
  timeFormat?: TimeFormat;
}

function read(): Stored {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Stored) : {};
  } catch {
    return {};
  }
}

const PrefsContext = createContext<Prefs | null>(null);

export function usePrefs(): Prefs {
  const value = useContext(PrefsContext);
  if (!value) throw new Error("usePrefs outside PrefsProvider");
  return value;
}

/** Appearance only. The auth token is deliberately never stored here. */
export function PrefsProvider({ children }: { children: ReactNode }) {
  const initial = read();
  const [lang, setLang] = useState<Lang>(initial.lang ?? "zh");
  const [theme, setTheme] = useState<Theme>(initial.theme ?? "system");
  const [timeFormat, setTimeFormat] = useState<TimeFormat>(initial.timeFormat ?? "local");

  useEffect(() => {
    const stored: Stored = { lang, theme, timeFormat };
    try {
      localStorage.setItem(KEY, JSON.stringify(stored));
    } catch {
      /* private mode */
    }
    document.documentElement.lang = lang;
    const dark =
      theme === "dark" ||
      (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
  }, [lang, theme, timeFormat]);

  const value = useMemo(
    () => ({ lang, theme, timeFormat, setLang, setTheme, setTimeFormat }),
    [lang, theme, timeFormat],
  );
  return <PrefsContext.Provider value={value}>{children}</PrefsContext.Provider>;
}
