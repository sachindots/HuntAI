import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Dev server proxies API calls to the FastAPI backend on :8000.
export default defineConfig({
  plugins: [svelte()],
  build: { outDir: "dist" },
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
