import { defineConfig, type Plugin } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Dev-server-only CSP relaxation: Vite injects <style> tags for HMR, which the
// production policy (style-src 'self') correctly blocks. The shipped
// index.html keeps the strict policy; this transform never runs for builds.
function devCsp(): Plugin {
  return {
    name: 'dev-csp-style-inline',
    apply: 'serve',
    transformIndexHtml(html) {
      return html.replace("style-src 'self';", "style-src 'self' 'unsafe-inline';")
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), devCsp()],
  server: {
    // Proxy API calls to the zero-knowledge Axum server (cargo run -p server).
    // Avoids cross-origin/CORS in dev; the app talks to a same-origin /api.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:7777',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
})
