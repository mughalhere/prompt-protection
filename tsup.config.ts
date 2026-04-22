import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/middleware/express.ts',
    'src/middleware/nextjs.ts',
    'src/react/usePromptProtection.ts',
    'src/adapters/claude.ts',
  ],
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: false,
  target: 'es2020',
  platform: 'neutral',
  treeshake: true,
  outDir: 'dist',
  banner: {
    js: '/* prompt-protection — MIT License — https://github.com/mughalhere/prompt-protection */',
  },
});
