// Sends every CSP / Trusted Types violation to the server log (POST /csp-report).
// Done from the page because browsers send native report-uri/report-to reports
// unreliably (batched, delayed, or not at all); the event fires in every browser.
// The SPA's index.html is static, so no violation can happen before this runs.

document.addEventListener("securitypolicyviolation", (e) => {
  navigator.sendBeacon(
    "/csp-report",
    JSON.stringify({
      directive: e.effectiveDirective,
      disposition: e.disposition,
      blocked: e.blockedURI,
      sample: e.sample,
      source: `${e.sourceFile}:${e.lineNumber}:${e.columnNumber}`,
      page: location.pathname,
    }),
  );
});
