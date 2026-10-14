import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard bundle `tunlion dashboard` serves. It ships INSIDE the cli
// crate (cli/dashboard-dist), embedded with include_bytes!, so the names are
// fixed (no content hashes) and the output is committed. CI rebuilds it and
// fails if the committed copy differs.
//
// Self-contained: no public/ assets, no CDN, no fonts (system stacks), one JS
// file and one CSS file, so the page runs under the dashboard's
// `default-src 'none'; script-src 'self'` policy.
export default defineConfig({
  plugins: [react()],
  publicDir: false,
  base: './',
  build: {
    outDir: '../cli/dashboard-dist',
    emptyOutDir: true,
    modulePreload: false,
    cssCodeSplit: false,
    sourcemap: false,
    rollupOptions: {
      input: 'dashboard.html',
      output: {
        entryFileNames: 'dashboard.js',
        chunkFileNames: 'dashboard-[name].js',
        assetFileNames: (info) => (info.name && info.name.endsWith('.css') ? 'dashboard.css' : '[name][extname]'),
        inlineDynamicImports: true,
      },
    },
  },
})
