import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Dev access over Tailscale/VM port-forwarding: bind all interfaces
    // and allow any Host header, since Vite's host-allowlist otherwise
    // blocks requests that don't say "localhost"/"127.0.0.1".
    host: true,
    allowedHosts: true,
  },
})
