import { defineConfig, devices } from "@playwright/test";

// Smoke tests against the real stack: Go server, Postgres, mock IdP (make e2e).
export default defineConfig({
  testDir: "e2e",
  forbidOnly: !!process.env.CI,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: "http://localhost:8090", trace: "retain-on-failure" },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: "make -C .. run",
    url: "http://localhost:8090/healthz",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
