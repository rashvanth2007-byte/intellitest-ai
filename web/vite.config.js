import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8787', changeOrigin: false },
      '/healthz': 'http://127.0.0.1:8787',
    },
  },
  build: { outDir: 'dist', emptyOutDir: true, target: 'es2022' },
});
