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
      // RN-тесты — компоненты, экраны и т.д.
      displayName: 'react-native',
      preset: 'react-native',
      testMatch: [
        '<rootDir>/__tests__/**/*.test.[jt]s?(x)',
        '<rootDir>/src/**/!(crypto)/**/__tests__/**/*.test.[jt]s?(x)',
      ],
      transformIgnorePatterns: [
        'node_modules/(?!(react-native|@react-native|@react-navigation|react-native-quick-crypto|react-native-screens|react-native-gesture-handler|react-native-safe-area-context)/)',
      ],
    },
  ],
};
