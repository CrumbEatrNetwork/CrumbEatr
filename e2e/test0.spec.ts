import { test, expect } from "@playwright/test";

test("Sanity check", async ({ page }) => {
    await page.goto("/");

    await page.getByRole("heading", { name: "ENTER" }).click();
    await expect(page).toHaveTitle("CRUMBEATR");
    await expect(
        page.getByText("Your content. Your community. Your Platform."),
    ).toBeVisible();
});

test("Important links work", async ({ page }) => {
    await page.goto("/");

    await page.getByRole("link", { name: "WHITE PAPER" }).click();
    await expect(
        page.getByRole("heading", { name: "WHITE PAPER" }),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "Arbiters" })).toBeVisible();
    await page.goBack();

    await page.getByRole("link", { name: "DASHBOARD" }).click();
    await expect(page.getByText("LAST UPGRADE")).toBeVisible();
    await page.goBack();
    await expect(page).toHaveTitle("CRUMBEATR");
});
