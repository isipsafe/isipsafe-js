import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
    sourcemap: true,
    target: 'node18',
  },
  {
    entry: { bin: 'src/bin.ts' },
    format: ['esm'],
    target: 'node18',
    platform: 'node',
    banner: { js: '#!/usr/bin/env node' },
  },
]);
