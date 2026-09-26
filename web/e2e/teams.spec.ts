import { execFileSync } from "node:child_process";
import { test, expect } from "@playwright/test";

test("team vault keeps item plaintext client-side", async ({ page }) => {
  test.setTimeout(300000);

  const email = `team-e2e-${Date.now()}@example.com`;
  const master = "PUBLIC TEAM E2E MASTER PASSWORD";
  const title = "Team-only demo login";
  const username = "team-user@example.com";
  const secret = "FAKE-TEAM-E2E-SECRET-NOT-FOR-USE";
  const notes = "Private team notes for ciphertext boundary testing";
  const apiBodies: string[] = [];
  const failedResponses: string[] = [];

  page.on("request", (request) => {
    if (request.url().includes("/api/")) apiBodies.push(request.postData() || "");
  });
  page.on("response", async (response) => {
    if (response.url().includes("/api/") && !response.ok()) {
      failedResponses.push(
        `${response.status()} ${new URL(response.url()).pathname}: ${await response.text()}`,
      );
    }
  });

  await page.goto("/");
  await page.getByRole("button", { name: "New here? Create an account" }).click();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(master);
  await page.getByRole("button", { name: "Create encrypted vault", exact: true }).click();
  await expect(page.getByRole("heading", { name: "All items", exact: true })).toBeVisible();

  // Team creation intentionally requires a verified account. The E2E backend uses an
  // isolated SQLite database, so satisfy that prerequisite in test state without
  // adding any verification bypass to the production API.
  execFileSync("python", [
    "-c",
    "import sqlite3,sys; db=sqlite3.connect('/tmp/vaultpass-e2e.db'); db.execute('update users set verified=1 where email=?',(sys.argv[1],)); db.commit(); db.close()",
    email,
  ]);

  await page.getByRole("button", { name: "Sharing", exact: true }).click();
  const sharingError = page.locator(".error[role=alert]");
  await expect(
    page.getByRole("button", { name: "Enable encrypted sharing", exact: true }).or(sharingError),
  ).toBeVisible();
  if (await sharingError.isVisible()) {
    throw new Error(`Sharing setup failed: ${await sharingError.textContent()}; ${failedResponses.join("; ")}`);
  }
  await page.getByRole("button", { name: "Enable encrypted sharing", exact: true }).click();
  await expect(page.getByText("Your public-key fingerprint", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Teams", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Team vaults", exact: true })).toBeVisible();
  await page.getByLabel("New team name").fill("E2E Team");
  await page.getByRole("button", { name: "Create team vault", exact: true }).click();

  const teamButton = page.getByRole("button").filter({ hasText: "E2E Team" });
  const teamError = page.locator(".error[role=alert]");
  await expect(teamButton.or(teamError)).toBeVisible({ timeout: 30000 });
  if (await teamError.isVisible()) {
    throw new Error(`Team creation failed: ${await teamError.textContent()}; ${failedResponses.join("; ")}`);
  }
  await teamButton.click();
  await expect(page.getByRole("heading", { name: "E2E Team", exact: true })).toBeVisible();

  await page.getByLabel("Title", { exact: true }).fill(title);
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password / secret", { exact: true }).fill(secret);
  await page.getByLabel("Notes", { exact: true }).fill(notes);
  await page.getByRole("button", { name: "Add encrypted team item", exact: true }).click();

  await expect(page.getByText(title, { exact: true })).toBeVisible();
  await expect(page.getByText(username, { exact: true })).toBeVisible();

  const wire = apiBodies.join("\n");
  expect(wire).not.toContain(master);
  expect(wire).not.toContain(title);
  expect(wire).not.toContain(username);
  expect(wire).not.toContain(secret);
  expect(wire).not.toContain(notes);
});
