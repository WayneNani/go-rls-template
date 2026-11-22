// Trusted Types default policy. The CSP enforces Trusted Types and allows only this
// policy, so every string that reaches innerHTML & co. passes through here. Our own code
// never writes raw HTML (ESLint); the allowlist holds the exact strings dependencies need.
// A new dependency that writes other HTML throws here and shows up as a CSP report.
// script and script URL sinks have no handler, so they are always blocked.

const allowedHTML = new Set<string>([
  // Radix Select hides the viewport scrollbar with an inline <style>.
  "[data-radix-select-viewport]{scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;}[data-radix-select-viewport]::-webkit-scrollbar{display:none}",
]);

type PolicyFactory = {
  createPolicy(name: string, rules: { createHTML: (input: string) => string | null }): unknown;
};

const factory = (window as { trustedTypes?: PolicyFactory }).trustedTypes;

factory?.createPolicy("default", {
  // null (not throw) makes the browser block the write *and* send a CSP violation report.
  createHTML: (input) => (allowedHTML.has(input) ? input : null),
});
