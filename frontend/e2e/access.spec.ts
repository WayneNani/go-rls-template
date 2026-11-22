import { expect, type Page, test } from "@playwright/test";

import { expectAccessible } from "./axe";

async function signIn(page: Page, user: string, claims?: object) {
  await page.goto("/");
  await page.getByRole("link", { name: "Sign in" }).click();
  await page.getByPlaceholder("Enter any user/subject").fill(user);
  if (claims) await page.getByPlaceholder(/Optional claims/).fill(JSON.stringify(claims));
  await page.getByRole("button", { name: "Sign-in" }).click();
  await expect(page.getByText("Your access")).toBeVisible();
}

test("an admin grants and revokes a role, and maps an IdP group", async ({ page }) => {
  const reports: string[] = [];
  page.on("request", (r) => {
    if (new URL(r.url()).pathname === "/csp-report") reports.push(r.postData() ?? "");
  });
  await signIn(page, "alice");
  await page.getByRole("button", { name: "Access" }).click();
  await expect(page.getByText("Members of Acme")).toBeVisible();

  // The filter matches display name or subject, on the server.
  const filter = page.getByRole("searchbox", { name: "Filter by name" });
  await filter.fill("BOB");
  await expect(page.getByRole("row", { name: /Bob Viewer/ })).toBeVisible();
  await expect(page.getByRole("row", { name: /Alice Admin/ })).toHaveCount(0);
  await filter.fill("");

  // Your own roles have no revoke button.
  const self = page.getByRole("row", { name: /Alice Admin \(you\)/ });
  await expect(self.getByRole("button")).toHaveCount(0);

  // Grant bob editor, then revoke it again (keeps the dev data unchanged).
  await page.getByRole("button", { name: "Grant role" }).click();
  await page.getByLabel("Email").fill("bob@example.com");
  await page.getByRole("combobox", { name: "Role" }).click();
  await page.getByRole("option", { name: "editor" }).click();
  await page.getByRole("button", { name: "Grant", exact: true }).click();
  const revoke = page.getByRole("button", { name: "Revoke editor from Bob Viewer" });
  await expect(revoke).toBeVisible();
  await revoke.click();
  await expect(revoke).toHaveCount(0);

  // Unknown users are reported, not created.
  await page.getByRole("button", { name: "Grant role" }).click();
  await page.getByLabel("Email").fill("nobody@example.com");
  await page.getByRole("combobox", { name: "Role" }).click();
  await page.getByRole("option", { name: "viewer" }).click();
  await page.getByRole("button", { name: "Grant", exact: true }).click();
  await expect(page.getByText(/after their first sign-in/)).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();

  // Map a group, then remove the mapping.
  const group = `e2e-${Date.now()}`;
  await page.getByPlaceholder("Group ID").fill(group);
  await page.getByRole("combobox", { name: "Mapping role" }).click();
  await page.getByRole("option", { name: "viewer" }).click();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  const remove = page.getByRole("button", { name: `Remove mapping ${group} to viewer` });
  await expect(remove).toBeVisible();
  await remove.click();
  await expect(remove).toHaveCount(0);

  expect(reports).toEqual([]);
});

test("a viewer does not see the access page", async ({ page }) => {
  await signIn(page, "bob");
  await expect(page.getByRole("button", { name: "Access" })).toHaveCount(0);
  await page.goto("/#access");
  await expect(page.getByText("Members of")).toHaveCount(0);
});

test("changing access after an old sign-in asks to confirm identity first", async ({ page }) => {
  // The mock IdP takes auth_time from the claims: an IdP session from an hour ago.
  await signIn(page, "alice", { auth_time: Math.floor(Date.now() / 1000) - 3600 });
  await page.getByRole("button", { name: "Access" }).click();
  const grant = async () => {
    await page.getByRole("button", { name: "Grant role" }).click();
    await page.getByLabel("Email").fill("bob@example.com");
    await page.getByRole("combobox", { name: "Role" }).click();
    await page.getByRole("option", { name: "editor" }).click();
    await page.getByRole("button", { name: "Grant", exact: true }).click();
  };
  await grant();

  const confirm = page.getByRole("dialog", { name: "Confirm it's you" });
  await expect(confirm).toBeVisible();
  await expectAccessible(page, "confirm identity dialog");
  await confirm.getByRole("link", { name: "Sign in again" }).click();

  // The IdP asks again (max_age=0, prompt=login) and sends us back to the access page.
  await expect(page).toHaveURL(/max_age=0/);
  await page.getByPlaceholder("Enter any user/subject").fill("alice");
  await page.getByRole("button", { name: "Sign-in" }).click();
  await expect(page).toHaveURL(/\/#access$/);
  await expect(page.getByText("Members of Acme")).toBeVisible();

  // Nothing was granted before; repeating the action works now. Revoke keeps the dev data unchanged.
  const revoke = page.getByRole("button", { name: "Revoke editor from Bob Viewer" });
  await expect(revoke).toHaveCount(0);
  await grant();
  await expect(revoke).toBeVisible();
  await revoke.click();
  await expect(revoke).toHaveCount(0);
});
