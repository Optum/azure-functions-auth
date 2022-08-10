module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '^.+\\.(t|j)sx?$': 'ts-jest',
  },
  testRegex: '(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  moduleNameMapper: {
    '^jose/webcrypto/(.*)$': '<rootDir>/node_modules/jose/dist/node/cjs/$1',
  },
  collectCoverage: true,
  clearMocks: true,
  coverageDirectory: 'coverage',
};
