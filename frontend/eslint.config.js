import js from "@eslint/js";
import tseslint from "typescript-eslint";

// Security rules of this template. Changing them needs security review (CODEOWNERS).
const rawHtml = "Raw HTML bypasses React's escaping and the Trusted Types policy.";
const useClient = "Use the generated Connect client in src/lib/api.ts.";
const noStorage = "No tokens or data in browser storage; the session is an HttpOnly cookie.";

const securityRules = {
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
  "no-restricted-syntax": [
    "error",
    { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: rawHtml },
    { selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]", message: rawHtml },
    { selector: "MemberExpression[property.value=/^(innerHTML|outerHTML)$/]", message: rawHtml },
    { selector: "CallExpression[callee.property.name=/^(insertAdjacentHTML|write|writeln)$/]", message: rawHtml },
  ],
  "no-restricted-globals": [
    "error",
    { name: "fetch", message: useClient },
    { name: "XMLHttpRequest", message: useClient },
    { name: "localStorage", message: noStorage },
    { name: "sessionStorage", message: noStorage },
  ],
  "no-restricted-properties": [
    "error",
    ...["window", "globalThis", "self"].flatMap((object) => [
      { object, property: "fetch", message: useClient },
      { object, property: "XMLHttpRequest", message: useClient },
      { object, property: "localStorage", message: noStorage },
      { object, property: "sessionStorage", message: noStorage },
    ]),
  ],
};

export default tseslint.config(
  { ignores: ["src/gen"] },
  // In app code, inline eslint-disable comments are ignored: an exception goes through this file.
  { files: ["src/**"], linterOptions: { noInlineConfig: true, reportUnusedDisableDirectives: "error" } },
  js.configs.recommended,
  tseslint.configs.base,
  // Strict style rules for our code; components/ui is vendored shadcn code.
  { files: ["**/*.{ts,tsx}"], ignores: ["src/components/ui/**"], extends: [tseslint.configs.strict] },
  // Security rules for everything, vendored components included.
  {
    languageOptions: { globals: { window: "readonly", document: "readonly", navigator: "readonly", location: "readonly" } },
    rules: securityRules,
  },
);
