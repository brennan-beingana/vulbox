import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // Bind all interfaces by default so the VM's dev server is reachable from
    // the host without passing `--host` every time (same as `npm run dev --host`).
    host: true,
    port: 5173,
  },
  preview: {
    // `npm run preview` serves the production build (used by the systemd unit).
    // Same bind/port as dev so the URL is stable across both.
    host: true,
    port: 5173,
  },
});
