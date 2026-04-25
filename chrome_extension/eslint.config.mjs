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
      "no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // {}.hasOwnProperty(...) is used in places; this rule is too noisy here.
      "no-prototype-builtins": "off",
      // panel.html loads panel.js / panel-crypto.js / panel-ui.js as separate <script> tags
      // sharing one global scope. ESLint lints each file in isolation and cannot see
      // cross-file references — a `let` declared in panel.js but reassigned only from
      // panel-ui.js looks unreassigned to ESLint, and prefer-const --fix would convert
      // it to `const`, breaking the runtime. Disable the whole family of cross-file
      // scope-aware rules until/unless we migrate to ES modules.
      "no-undef": "off",
      "no-implicit-globals": "off",
      "prefer-const": "off",
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
