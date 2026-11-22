import { expect, type Page, test } from "@playwright/test";

import { expectAccessible } from "./axe";

// axe on every screen and every open overlay, desktop and mobile (the two projects).

async function signIn(page: Page, user: string) {
  await page.goto("/");
  await expectAccessible(page, "sign-in");
  await page.getByRole("link", { name: "Sign in" }).click();
  await page.getByPlaceholder("Enter any user/subject").fill(user);
  await page.getByRole("button", { name: "Sign-in" }).click();
  await expect(page.getByText("Your access")).toBeVisible();
}

test("projects screen, its dialog, select and menu", async ({ page }) => {
  await signIn(page, "alice");
  await expect(page.getByRole("cell").first()).toBeVisible();
  await expectAccessible(page, "projects");

  await page.getByRole("button", { name: "New project" }).click();
  await expectAccessible(page, "new project dialog");
  await page.getByRole("combobox", { name: "Organization" }).click();
  await expectAccessible(page, "organization select");
  await page.getByRole("option", { name: "Acme" }).click();
  await page.getByLabel("Name", { exact: true }).fill("x".repeat(101));
  await page.getByRole("button", { name: "Create" }).click();
  await expect(page.getByText("Must be 1 to 100 characters.")).toBeVisible();
  await expectAccessible(page, "new project dialog with a field error");
  await page.keyboard.press("Escape");

  await page.getByRole("searchbox", { name: "Filter projects" }).fill("no project has this name");
  await expect(page.getByText(/^Nothing matches/)).toBeVisible();
  await expectAccessible(page, "projects filtered to nothing");

  await page.getByRole("button", { name: "Alice" }).click();
  await expectAccessible(page, "user menu");
});

test("access screen, its dialogs and selects", async ({ page }) => {
  await signIn(page, "alice");
  await page.getByRole("button", { name: "Access" }).click();
  await expect(page.getByText("Members of Acme")).toBeVisible();
  await expectAccessible(page, "access");

  await page.getByRole("combobox", { name: "Mapping role" }).click();
  await expectAccessible(page, "mapping role select");
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: "Grant role" }).click();
  await expectAccessible(page, "grant role dialog");
  await page.getByRole("combobox", { name: "Role" }).click();
  await expectAccessible(page, "grant role select");
});

test("a screen without privileges", async ({ page }) => {
  await signIn(page, "nobody-a11y");
  await expectAccessible(page, "projects without roles");
});
