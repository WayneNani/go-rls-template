import { setNonce } from "get-nonce";

// The server puts a fresh nonce into index.html on every request and allows only
// <style> tags that carry it (style-src 'nonce-...'; no 'unsafe-inline'). Components that
// inject <style> tags get it here: react-remove-scroll (dialogs) through get-nonce, Radix
// Select through its nonce prop (src/components/ui/select.tsx). Undefined under `make dev`,
// where Vite serves the page without a CSP.
export const cspNonce =
  document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content || undefined;

if (cspNonce) setNonce(cspNonce);
