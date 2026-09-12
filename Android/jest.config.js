module.exports = {
  preset: 'react-native',

  // Трансформируем src/crypto через стандартный Babel
  // (не исключаем из transform, как делает RN preset для node_modules)
  transformIgnorePatterns: [
    'node_modules/(?!(react-native|@react-native|@react-navigation)/)',
  ],

  // Проекты: отдельные конфиги для крипто-тестов (node) и RN-тестов (react-native)
  projects: [
    {
      // Крипто-тесты — pure JS, запускаются в Node без RN-зависимостей
      displayName: 'crypto',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/src/crypto/__tests__/**/*.test.[jt]s?(x)'],
      transform: {
        '^.+\\.[jt]sx?$': 'babel-jest',
      },
      transformIgnorePatterns: [
        'node_modules/(?!(react-native-quick-crypto|@noble|@scure)/)',
      ],
      // @noble/* / @scure/* use "exports" with .js suffixes — custom resolver handles this
      resolver: '<rootDir>/jest-noble-resolver.js',
    },
    {
      // Селектор точек входа — pure JS без платформенных импортов, поэтому
      // node-окружение; RN-проект его игнорирует, чтобы тесты не шли дважды.
      displayName: 'selector',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/src/services/__tests__/*.test.[jt]s?(x)'],
      transform: {
        '^.+\\.[jt]sx?$': 'babel-jest',
      },
      // The island-list tests sign with @noble, so the signatures they verify
      // are real rather than mocked.
      resolver: '<rootDir>/jest-noble-resolver.js',
      transformIgnorePatterns: ['node_modules/(?!(@noble|@scure)/)'],
    },
    {
      // Интеграционные тесты failover — гоняют НАСТОЯЩИЙ NetworkService против
      // живого бэкенда через управляемые точки входа. Требуют поднятого сервера
      // (см. src/services/__tests__/integration/README.md), поэтому не входят
      // в `npm test`: запускать `npm run test:failover`.
      displayName: 'integration',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/src/services/__tests__/integration/*.test.[jt]s?(x)'],
      setupFiles: ['<rootDir>/src/services/__tests__/integration/helpers/setup.js'],
      transform: {
        '^.+\\.[jt]sx?$': 'babel-jest',
      },
      moduleNameMapper: {
        '^react-native$': '<rootDir>/src/services/__tests__/integration/helpers/reactNativeStub.js',
        '^@react-native-async-storage/async-storage$': '<rootDir>/src/services/__tests__/integration/helpers/asyncStorageStub.js',
        '^react-native-keychain$': '<rootDir>/src/services/__tests__/integration/helpers/keychainStub.js',
      },
      // @noble/* uses "exports" with .js suffixes — same resolver as the crypto
      // project, and the same transform exception (the packages ship ESM).
      resolver: '<rootDir>/jest-noble-resolver.js',
      transformIgnorePatterns: ['node_modules/(?!(@noble|@scure)/)'],
    },
    {
      // RN-тесты — компоненты, экраны и т.д.
      displayName: 'react-native',
      preset: 'react-native',
      testMatch: [
        '<rootDir>/__tests__/**/*.test.[jt]s?(x)',
        '<rootDir>/src/**/!(crypto)/**/__tests__/**/*.test.[jt]s?(x)',
      ],
      testPathIgnorePatterns: ['<rootDir>/src/services/__tests__/'],
      // Integration tests need a live backend; they never run by default.

      transformIgnorePatterns: [
        'node_modules/(?!(react-native|@react-native|@react-navigation|react-native-quick-crypto|react-native-screens|react-native-gesture-handler|react-native-safe-area-context)/)',
      ],
    },
  ],
};
