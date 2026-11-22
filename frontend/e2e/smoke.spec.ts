import { expect, type Page, test } from "@playwright/test";

// Collects what the page sends to /csp-report. A dependency update that changes the
// HTML it injects (see src/trusted-types.ts) shows up here instead of in production.
function cspReports(page: Page): string[] {
  const reports: string[] = [];
  page.on("request", (r) => {
    if (new URL(r.url()).pathname === "/csp-report") reports.push(r.postData() ?? "");
  });
  return reports;
}

async function signIn(page: Page, user: string, claims?: object) {
  await page.goto("/");
  await page.getByRole("link", { name: "Sign in" }).click();
  await page.getByPlaceholder("Enter any user/subject").fill(user);
  if (claims) await page.getByPlaceholder(/Optional claims/).fill(JSON.stringify(claims));
  await page.getByRole("button", { name: "Sign-in" }).click();
  await expect(page.getByText("Your access")).toBeVisible();
}

test("an editor creates a project without any CSP or Trusted Types violation", async ({ page }) => {
  const reports = cspReports(page);
  await signIn(page, "alice");

  const name = `E2E ${Date.now()}`;
  await page.getByRole("button", { name: "New project" }).click();
  await page.getByRole("combobox", { name: "Organization" }).click();
  await page.getByRole("option", { name: "Acme" }).click();
  await page.getByLabel("Name", { exact: true }).fill(name);
  await page.getByRole("button", { name: "Create" }).click();

  await expect(page.getByRole("cell", { name, exact: true })).toBeVisible();
  expect(reports).toEqual([]);
});

test("a rule from proto shows its message at the field", async ({ page }) => {
  await signIn(page, "alice");
  await page.getByRole("button", { name: "New project" }).click();
  await page.getByRole("combobox", { name: "Organization" }).click();
  await page.getByRole("option", { name: "Acme" }).click();
  const name = page.getByLabel("Name", { exact: true });
  await name.fill("x".repeat(101));
  await page.getByRole("button", { name: "Create" }).click();

  await expect(name).toHaveAttribute("aria-invalid", "true");
  await expect(name).toHaveAccessibleDescription("Must be 1 to 100 characters.");
  await expect(page.getByText("Must be 1 to 100 characters.")).toBeVisible();
});

// Project names are unique per org (migration 00006); the database's verdict arrives at the
// field like a proto rule. Names start with "E2E ": make e2e deletes them afterwards.
test("a taken name shows at the field in create and rename; the filter narrows the list", async ({ page }) => {
  await signIn(page, "alice");
  const stamp = `${Date.now()}`;
  const [alpha, beta] = [`E2E ${stamp} alpha`, `E2E ${stamp} beta`];
  const create = async (name: string) => {
    await page.getByRole("button", { name: "New project" }).click();
    await page.getByRole("combobox", { name: "Organization" }).click();
    await page.getByRole("option", { name: "Acme" }).click();
    await page.getByLabel("Name", { exact: true }).fill(name);
    await page.getByRole("button", { name: "Create" }).click();
  };
  const taken = "A project with this name already exists.";

  await create(alpha);
  await expect(page.getByRole("cell", { name: alpha, exact: true })).toBeVisible();
  await create(alpha);
  const name = page.getByLabel("Name", { exact: true });
  await expect(name).toHaveAttribute("aria-invalid", "true");
  await expect(name).toHaveAccessibleDescription(taken);
  await page.getByRole("button", { name: "Cancel" }).click();
  await create(beta);
  await expect(page.getByRole("cell", { name: beta, exact: true })).toBeVisible();

  // Filter: case-insensitive, matched by the server.
  const filter = page.getByRole("searchbox", { name: "Filter projects" });
  await filter.fill(`${stamp} BETA`);
  await expect(page.getByRole("cell", { name: alpha, exact: true })).toHaveCount(0);
  await expect(page.getByRole("cell", { name: beta, exact: true })).toBeVisible();

  await page.getByRole("button", { name: `Rename ${beta}` }).click();
  const rename = page.getByLabel("Name", { exact: true });
  await rename.fill(alpha);
  await page.getByRole("button", { name: "Rename", exact: true }).click();
  await expect(rename).toHaveAccessibleDescription(taken);
  await expect(page.getByText(taken)).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();

  await filter.fill(`${stamp} gamma`);
  await expect(page.getByText(`Nothing matches “${stamp} gamma”.`)).toBeVisible();
});

test("a viewer gets no create button", async ({ page }) => {
  await signIn(page, "bob");
  await expect(page.getByRole("cell").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "New project" })).toHaveCount(0);
});

test("an IdP group grants a role at sign-in", async ({ page }) => {
  await signIn(page, "dave", { groups: ["acme-editors"] });
  await expect(page.getByText("idp", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "New project" })).toBeVisible();
});

test("raw HTML is blocked and reported", async ({ page }) => {
  const reports = cspReports(page);
  await page.goto("/");
  const blocked = await page.evaluate(() => {
    try {
      // eslint-disable-next-line no-restricted-syntax -- the attack this test expects to be blocked
      document.body.insertAdjacentHTML("beforeend", "<img src=x>");
      return false;
    } catch {
      return true;
    }
  });
  expect(blocked).toBe(true);
  await expect.poll(() => reports.length).toBe(1);
});
