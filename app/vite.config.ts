import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Proxy API calls to the zero-knowledge Axum server (cargo run -p server).
    // Avoids cross-origin/CORS in dev; the app talks to a same-origin /api.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:7777',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
      // BIN -> issuing bank lookup (binlist sends no CORS header; proxy it in dev).
      '/binlist': {
        target: 'https://lookup.binlist.net',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/binlist/, ''),
      },
    },
  },
})
