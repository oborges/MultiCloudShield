import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': 'http://localhost:8080', '/healthz': 'http://localhost:8080' } },
  build: { sourcemap: false },
  test: { environment: 'jsdom', exclude: ['e2e/**', 'node_modules/**'] },
})
