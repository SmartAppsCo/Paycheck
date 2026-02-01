import { defineConfig } from 'tsup';

export default defineConfig([
  // Node.js / bundler build (external deps for smaller package)
  {
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
  },
  // Browser build (all deps bundled for direct <script> usage)
  {
    entry: ['src/index.ts'],
    format: ['esm'],
    outDir: 'dist/browser',
    noExternal: [/.*/], // Bundle everything
  },
]);
