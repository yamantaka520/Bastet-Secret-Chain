import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The daemon embeds `dist/` and serves it from `/`. In development, Vite
// proxies the API to a locally running `bsc serve`.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false, target: "es2022" },
  server: { port: 5173, proxy: { "/v1": { target: "http://127.0.0.1:8787", changeOrigin: false } } },
});
