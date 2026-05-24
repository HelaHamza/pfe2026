import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { // ← toutes les requêtes commençant par /api seront proxyfiées vers le backend
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''), // ← supprime le préfixe /api avant de proxyfier vers le backend
      },
    },
  },
})