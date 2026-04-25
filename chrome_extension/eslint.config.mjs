import js from "@eslint/js";
import globals from "globals";

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "script",
      globals: {
        ...globals.browser,
        ...globals.webextensions,
        ...globals.serviceworker,
        // Project-specific globals (see CLAUDE.md "Global Namespace" + rpc.js).
        __wsCrypto: "readonly",
        Notifications: "readonly",
        connectPort: "readonly",
        safePost: "readonly",
        rpcOnMessage: "readonly",
        rpcOffMessage: "readonly",
        rpcOnConnect: "readonly",
        rpcOnDisconnect: "readonly",
        rpcDisconnect: "readonly",
        rpcGetPort: "readonly",
      },
    },
    rules: {
      eqeqeq: ["error", "smart"],
      "no-var": "error",
      "prefer-const": "warn",
      "no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // {}.hasOwnProperty(...) is used in places; this rule is too noisy here.
      "no-prototype-builtins": "off",
      // panel.html loads panel.js / panel-crypto.js / panel-ui.js as separate <script> tags
      // sharing one global scope. The whole codebase relies on implicit globals across
      // files (function declared in panel.js, called from panel-ui.js). ESLint lints each
      // file in isolation, so both no-undef and no-implicit-globals fire constantly with
      // false positives. Full fix would require migrating to ES modules.
      "no-undef": "off",
      "no-implicit-globals": "off",
      // Empty catch blocks are an intentional "swallow this error" pattern in many places.
      // Keep the rule on for empty if/while/etc. blocks (which often are real bugs).
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
  {
    // Vendored Emscripten output — not our code, do not lint.
    ignores: ["argon2id/**", "node_modules/**"],
  },
];
