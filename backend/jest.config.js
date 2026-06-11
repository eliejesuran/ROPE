module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/src/__tests__/**/*.test.js'],
  setupFiles: ['./src/__tests__/env.setup.js'],
  testTimeout: 30000,
  verbose: true,
  moduleNameMapper: {
    'expo-server-sdk': '<rootDir>/src/__tests__/__mocks__/expo-server-sdk.js',
  },
};
