import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// The RACCOON UI is a fully offline single-page app. It is embedded in the Go
// binary and served from the server root, so the build output goes to web/dist
// and never references a remote asset.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Stable, unhashed names keep `scripts/check_dist.sh` diffs meaningful.
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name].js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    restoreMocks: true,
  },
})
