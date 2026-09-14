import tseslint from "typescript-eslint";

const AUTHORED_WEB_FILES = ["eslint.config.mjs", "graph/viewer-src/**/*.ts", "scripts/**/*.mjs"];

export default [
  {
    ignores: [
      "**/.build/**",
      "**/node_modules/**",
      "**/archive/**",
      "**/generated/**",
      "graph/src/rootstock_graph/resources/viewer/**",
    ],
  },
  {
    files: AUTHORED_WEB_FILES,
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    rules: {
      complexity: ["error", { max: 8, variant: "classic" }],
    },
  },
];
