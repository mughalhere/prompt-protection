/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/patterns/index.ts',  // barrel re-export, no executable functions
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 85,
      lines: 85,
      statements: 85,
    },
  },
  testMatch: ['**/*.test.ts'],
  moduleNameMapper: {
    '^prompt-protection$': '<rootDir>/src/index.ts',
    '^prompt-protection/(.*)$': '<rootDir>/src/$1',
    // Strip .js extensions from relative imports so Jest resolves .ts files
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: {
        module: 'CommonJS',
        moduleResolution: 'node',
        verbatimModuleSyntax: false,
      },
    }],
  },
};
