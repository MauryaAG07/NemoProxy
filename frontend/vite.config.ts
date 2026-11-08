import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // When the FastAPI backend runs locally (default :8000), /api/* is
      // proxied to it so the frontend never needs a hardcoded backend URL.
      // If no backend is running, the app falls back to labelled mock mode.
      '/api': 'http://127.0.0.1:8000',
    },
  },
})
