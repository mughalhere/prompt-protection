/** @type {import('jest').Config} */
// ReDoS safety suite: fuzzes every shipped regex with `recheck`. Separate from
// the main config so it never dilutes coverage and can run on one Node version.
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests/regex-safety'],
  testMatch: ['**/*.test.ts'],
  testTimeout: 60000,
  collectCoverage: false,
  moduleNameMapper: {
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
