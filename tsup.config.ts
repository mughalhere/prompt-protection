import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/middleware/express.ts',
    'src/middleware/nextjs.ts',
    'src/react/usePromptProtection.ts',
    'src/adapters/claude.ts',
    'src/adapters/openai.ts',
    'src/adapters/vercel.ts',
    'src/mcp/server.ts',
    'src/mcp/bin.ts',
  ],
  format: ['esm', 'cjs'],
  dts: true,
  // Optional peer deps are dynamic-imported at runtime; keep them external so
  // they are never bundled into the output (base package stays zero-dependency).
  external: [
    '@modelcontextprotocol/sdk',
    'zod',
    'ai',
    '@anthropic-ai/sdk',
    'openai',
    'express',
    'react',
    'next',
  ],
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
