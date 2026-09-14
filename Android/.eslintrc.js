module.exports = {
  root: true,
  extends: '@react-native',
  // The React Native preset declares the RN globals and nothing else, so every
  // file that touches a Web or Node global - which is most of the crypto and
  // network layer - reported them as undefined. Three hundred of those drown
  // the findings that matter, which is the same as having no lint at all.
  globals: {
    globalThis: 'readonly',
    crypto: 'readonly',
    TextEncoder: 'readonly',
    TextDecoder: 'readonly',
    atob: 'readonly',
    btoa: 'readonly',
    Buffer: 'readonly',
    BigInt: 'readonly',
    URL: 'readonly',
    URLSearchParams: 'readonly',
    AbortController: 'readonly',
    WebSocket: 'readonly',
    fetch: 'readonly',
    // Set by the React Native build; false in a release bundle.
    __DEV__: 'readonly',
  },
  rules: {
    // `catch (_e) {}` is the project's way of saying "this failure is expected
    // and handled by the line below"; the leading underscore is the marker.
    'no-unused-vars': ['error', {
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
      caughtErrorsIgnorePattern: '^_',
    }],
    // The screens register their listeners once and reach current state through
    // refs - deliberately, because a dependency array that re-runs them
    // accumulates mitt subscribers on every keystroke (see Android/CLAUDE.md,
    // "Event Listener Pattern"). The rule cannot see that, so it advises rather
    // than blocks.
    'react-hooks/exhaustive-deps': 'warn',
  },
  overrides: [
    {
      // TypeScript files go through a different unused-vars rule; the project's
      // underscore convention has to be spelled out for it as well.
      files: ['*.ts', '*.tsx'],
      rules: {
        '@typescript-eslint/no-unused-vars': ['error', {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        }],
      },
    },
    {
      files: ['**/__tests__/**', '*.test.js', 'jest.config.js', 'jest-noble-resolver.js'],
      env: { jest: true, node: true },
    },
  ],
};
