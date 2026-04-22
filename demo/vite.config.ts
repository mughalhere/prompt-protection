import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      'prompt-protection/react': resolve(__dirname, '../src/react/usePromptProtection.ts'),
      'prompt-protection': resolve(__dirname, '../src/index.ts'),
    },
  },
  base: '/prompt-protection/',
});
