import type { Config } from "tailwindcss";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const here = dirname(createRequire(import.meta.url).resolve("./tailwind.config.ts"));

export default {
  content: [join(here, "index.html"), join(here, "src/**/*.{ts,tsx}")],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Noto Sans SC",
          "sans-serif",
        ],
        mono: ["ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
      },
      colors: {
        ink: {
          DEFAULT: "rgb(var(--ink) / <alpha-value>)",
          soft: "rgb(var(--ink-soft) / <alpha-value>)",
          faint: "rgb(var(--ink-faint) / <alpha-value>)",
        },
        paper: {
          DEFAULT: "rgb(var(--paper) / <alpha-value>)",
          raised: "rgb(var(--paper-raised) / <alpha-value>)",
          sunken: "rgb(var(--paper-sunken) / <alpha-value>)",
        },
        line: "rgb(var(--line) / <alpha-value>)",
        accent: "rgb(var(--accent) / <alpha-value>)",
        gap: "rgb(var(--gap) / <alpha-value>)",
        sensitive: "rgb(var(--sensitive) / <alpha-value>)",
      },
    },
  },
  plugins: [],
} satisfies Config;
