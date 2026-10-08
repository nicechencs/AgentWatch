import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import tailwind from "tailwindcss";
import autoprefixer from "autoprefixer";
import { defineConfig } from "vite";

const root = fileURLToPath(new URL(".", import.meta.url));

// Dev server proxies /api to the local daemon. Production builds are embedded
// by aw-daemon (rust-embed) and served from the same origin, so no proxy.
export default defineConfig({
  root,
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  css: {
    postcss: {
      plugins: [tailwind(fileURLToPath(new URL("./tailwind.config.ts", import.meta.url))), autoprefixer()],
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        manualChunks: {
          echarts: ["echarts/core", "echarts/charts", "echarts/components", "echarts/renderers"],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:7456", changeOrigin: false },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
});
