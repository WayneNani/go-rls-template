import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";

// Fix a violation in the component; a rule disabled here needs a written reason.
export async function expectAccessible(page: Page, screen: string) {
  // Overlays animate in; axe would measure contrast mid-fade.
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running"));
  const axe = new AxeBuilder({ page });
  // An open select list or menu is checked on its own. Radix makes everything else inert
  // while it is open (aria-hidden on #root plus a focus trap), so page-level rules would
  // only report that intended state; the page behind was checked before it opened.
  const popup = '[role="listbox"], [role="menu"]';
  if (await page.locator(popup).count()) axe.include(popup);
  const { violations } = await axe.analyze();
  const found = violations.map(
    (v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => `${n.target.join(" ")} ${n.failureSummary ?? ""}`).join(" | ")}`,
  );
  expect(found, screen).toEqual([]);
}
