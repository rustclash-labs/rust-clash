import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/version": "http://127.0.0.1:9090",
      "/configs": "http://127.0.0.1:9090",
      "/proxies": "http://127.0.0.1:9090",
      "/rules": "http://127.0.0.1:9090",
      "/connections": "http://127.0.0.1:9090",
      "/dns": "http://127.0.0.1:9090",
      "/tools": "http://127.0.0.1:9090",
      "/profiles": "http://127.0.0.1:9090",
      "/traffic": { target: "http://127.0.0.1:9090", ws: true },
      "/memory": { target: "http://127.0.0.1:9090", ws: true },
      "/logs": { target: "http://127.0.0.1:9090", ws: true },
    },
  },
});
