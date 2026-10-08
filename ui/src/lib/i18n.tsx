import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";
import en from "@/i18n/en.json";
import zh from "@/i18n/zh.json";

export type Lang = "zh" | "en";

const catalogs: Record<Lang, Record<string, string>> = { zh, en };

interface I18nValue {
  lang: Lang;
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nValue>({
  lang: "zh",
  t: (key) => key,
});

export function I18nProvider({ lang, children }: { lang: Lang; children: ReactNode }) {
  const t = useCallback(
    (key: string, vars?: Record<string, string | number>) => {
      const template = catalogs[lang][key] ?? catalogs.en[key] ?? key;
      if (!vars) return template;
      return template.replace(/\{(\w+)\}/g, (_, name: string) =>
        vars[name] === undefined ? `{${name}}` : String(vars[name]),
      );
    },
    [lang],
  );
  const value = useMemo(() => ({ lang, t }), [lang, t]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  return useContext(I18nContext);
}
