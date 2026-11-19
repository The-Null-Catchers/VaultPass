import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test, expect, type Page } from "@playwright/test";

// All accounts, item values, and passwords in this suite are synthetic.
const master = "PUBLIC SYNTHETIC ACCEPTANCE MASTER PASSWORD";
const accountEmail = () => "acceptance-" + randomUUID() + "@example.com";

async function register(page: Page, email: string) {
  await page.goto("/");
  await page.getByRole("button", { name: "New here? Create an account" }).click();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(master);
  await page.getByRole("button", { name: "Create encrypted vault", exact: true }).click();
  await expect(page.getByRole("heading", { name: "All items", exact: true })).toBeVisible();
}

async function signIn(page: Page, email: string) {
  await page.goto("/");
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(master);
  await page.getByRole("button", { name: "Unlock vault", exact: true }).click();
  await expect(page.getByRole("heading", { name: "All items", exact: true })).toBeVisible();
}

async function addItem(page: Page, title: string, secret: string) {
  await page.getByRole("button", { name: "Add item", exact: true }).click();
  await page.getByLabel("Title", { exact: true }).fill(title);
  await page.getByLabel("Password / secret", { exact: true }).fill(secret);
  await page.getByRole("button", { name: "Save encrypted item", exact: true }).click();
  await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
}

function recordApiBodies(page: Page): string[] {
  const bodies: string[] = [];
  page.on("request", request => {
    if (new URL(request.url()).pathname.startsWith("/api/")) {
      bodies.push(request.postData() || "");
    }
  });
  return bodies;
}

test("two browser clients reject stale writes without losing either synthetic edit", async ({ page, browser }) => {
  test.setTimeout(300_000);
  console.log("VaultPass two-client acceptance", {
    sha: process.env.GITHUB_SHA || "local",
    browser: browser.version(),
    playwrightProject: test.info().project.name,
  });

  const email = accountEmail();
  const original = "Shared synthetic item";
  const winner = "First client committed edit";
  const stale = "Second client uncommitted edit";
  const preserved = "Preserved second-client copy";
  const secret = "FAKE-ONLY-ACCEPTANCE-SECRET";
  const firstBodies = recordApiBodies(page);

  await register(page, email);
  await addItem(page, original, secret);

  const secondContext = await browser.newContext();
  try {
    const second = await secondContext.newPage();
    const secondBodies = recordApiBodies(second);
    await signIn(second, email);

    // Keep a stale editor open before the first browser commits a newer revision.
    await second.locator("button.item").filter({ hasText: original }).click();
    await second.getByRole("button", { name: "Edit item", exact: true }).click();
    await second.getByLabel("Title", { exact: true }).fill(stale);

    await page.getByRole("button", { name: "Edit item", exact: true }).click();
    await page.getByLabel("Title", { exact: true }).fill(winner);
    await page.getByRole("button", { name: "Save encrypted item", exact: true }).click();
    await expect(page.getByRole("heading", { name: winner, exact: true })).toBeVisible();

    const [conflict] = await Promise.all([
      second.waitForResponse(response =>
        response.url().includes("/api/vaults/") &&
        response.request().method() === "PUT" &&
        response.status() === 409
      ),
      second.getByRole("button", { name: "Save encrypted item", exact: true }).click(),
    ]);
    expect(conflict.status()).toBe(409);
    await expect(second.getByRole("dialog").getByRole("alert")).toBeVisible();
    // A rejected save must leave the local draft visible, not silently discard it.
    await expect(second.getByLabel("Title", { exact: true })).toHaveValue(stale);

    await second.getByRole("button", { name: "Close editor" }).click();
    await second.getByRole("button", { name: "Sync vault" }).click();
    await expect(second.locator("button.item").filter({ hasText: winner })).toBeVisible();
    await expect(second.locator("button.item").filter({ hasText: stale })).toHaveCount(0);

    // Explicit user-directed resolution: preserve the rejected content as a new item.
    await addItem(second, preserved, secret);
    await page.getByRole("button", { name: "Sync vault" }).click();
    await expect(page.locator("button.item")).toHaveCount(2);
    await expect(page.locator("button.item").filter({ hasText: winner })).toBeVisible();
    await expect(page.locator("button.item").filter({ hasText: preserved })).toBeVisible();

    for (const wire of [firstBodies.join("\n"), secondBodies.join("\n")]) {
      expect(wire).not.toContain(master);
      expect(wire).not.toContain(secret);
      expect(wire).not.toContain(original);
      expect(wire).not.toContain(winner);
      expect(wire).not.toContain(stale);
      expect(wire).not.toContain(preserved);
    }
  } finally {
    await secondContext.close();
  }
});

test("encrypted backup restores into a different synthetic account and rejects wrong password", async ({ page, browser }) => {
  test.setTimeout(300_000);
  console.log("VaultPass isolated restore acceptance", {
    sha: process.env.GITHUB_SHA || "local",
    browser: browser.version(),
    playwrightProject: test.info().project.name,
  });

  const sourceEmail = accountEmail();
  const first = "Synthetic backup login A";
  const second = "Synthetic backup login B";
  const firstSecret = "FAKE-RESTORE-SECRET-A";
  const secondSecret = "FAKE-RESTORE-SECRET-B";
  await register(page, sourceEmail);
  await addItem(page, first, firstSecret);
  await addItem(page, second, secondSecret);
  await page.getByRole("button", { name: "Settings", exact: true }).click();

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Encrypted backup", exact: true }).click(),
  ]);
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const backupText = await readFile(downloadPath!, "utf8");
  const backup = JSON.parse(backupText) as { format: string; items: unknown[] };
  expect(backup.format).toBe("vaultpass-backup-v1");
  expect(backup.items).toHaveLength(2);
  for (const cleartext of [master, first, second, firstSecret, secondSecret]) {
    expect(backupText).not.toContain(cleartext);
  }

  const destinationContext = await browser.newContext();
  try {
    const destination = await destinationContext.newPage();
    const destinationBodies = recordApiBodies(destination);
    await register(destination, accountEmail());
    await destination.getByRole("button", { name: "Settings", exact: true }).click();
    const picker = destination.locator('input[type="file"][accept="application/json"]');
    const upload = { name: "synthetic-encrypted-backup.json", mimeType: "application/json", buffer: Buffer.from(backupText) };

    // Wait for the actual browser prompt: uploading a file does not wait for
    // asynchronous File.text() parsing or the subsequent password dialog.
    await Promise.all([
      destination.waitForEvent("dialog", { timeout: 15_000 }).then(async dialog => {
        expect(dialog.type()).toBe("prompt");
        await dialog.accept("WRONG SYNTHETIC MASTER PASSWORD");
      }),
      picker.setInputFiles(upload),
    ]);
    await expect(destination.locator(".error[role=alert]").first()).toBeVisible({ timeout: 30_000 });
    await destination.getByRole("button", { name: "All items", exact: true }).click();
    await expect(destination.locator("button.item")).toHaveCount(0);

    await destination.getByRole("button", { name: "Settings", exact: true }).click();
    destination.once("dialog", dialog => { void dialog.accept(master); });
    await picker.setInputFiles(upload);
    await expect(destination.getByText("Backup restored as new encrypted copies", { exact: true })).toBeVisible({ timeout: 60_000 });
    await destination.getByRole("button", { name: "All items", exact: true }).click();
    await expect(destination.locator("button.item")).toHaveCount(2);
    await expect(destination.locator("button.item").filter({ hasText: first })).toBeVisible();
    await expect(destination.locator("button.item").filter({ hasText: second })).toBeVisible();

    // Both restored secrets are decrypted only in the destination browser.
    await destination.locator("button.item").filter({ hasText: first }).click();
    await destination.getByRole("button", { name: "Toggle password visibility" }).click();
    await expect(destination.getByText(firstSecret, { exact: true })).toBeVisible();
    await destination.locator("button.item").filter({ hasText: second }).click();
    await destination.getByRole("button", { name: "Toggle password visibility" }).click();
    await expect(destination.getByText(secondSecret, { exact: true })).toBeVisible();

    const wire = destinationBodies.join("\n");
    for (const cleartext of [master, first, second, firstSecret, secondSecret]) {
      expect(wire).not.toContain(cleartext);
    }
  } finally {
    await destinationContext.close();
  }
});
