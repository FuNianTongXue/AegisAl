import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backendTarget = process.env.SECFLOW_DEV_BACKEND_URL || "http://127.0.0.1:18781";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    proxy: {
      "/api": backendTarget,
      "/health": backendTarget,
    },
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    target: "es2022",
    minify: process.env.TAURI_ENV_DEBUG ? false : "esbuild",
    sourcemap: Boolean(process.env.TAURI_ENV_DEBUG),
  },
});
