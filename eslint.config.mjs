/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

export default [
  {
    files: ["web/js/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        AbortController: "readonly",
        Blob: "readonly",
        FormData: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        clearTimeout: "readonly",
        document: "readonly",
        fetch: "readonly",
        localStorage: "readonly",
        setTimeout: "readonly",
        window: "readonly",
      },
    },
    rules: {
      "no-constant-condition": "error",
      "no-undef": "error",
      "no-unreachable": "error",
      "no-unused-vars": "error",
    },
  },
];
