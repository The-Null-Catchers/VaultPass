import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";

test("security notification changes persist through the web API proxy", async ({ request }) => {
  const envelope = {
    v: 1,
    nonce: Buffer.alloc(12, "n").toString("base64"),
    ciphertext: Buffer.alloc(48, "c").toString("base64"),
  };
  const registration = await request.post("/api/auth/register", {
    data: {
      id: randomUUID(),
      email: `notifications-${randomUUID()}@example.com`,
      auth_secret: "a".repeat(64),
      bundle: {
        salt: "b".repeat(32),
        profile: "argon2id-m65536-t3-p4-v1",
        account_key: envelope,
      },
      vault_id: randomUUID(),
      wrapped_vault_key: envelope,
    },
  });
  expect(registration.status()).toBe(201);
  const { access_token } = await registration.json();
  const headers = { Authorization: `Bearer ${access_token}` };
  const path = "/api/account/security-notifications";

  const initial = await request.get(path, { headers });
  expect(initial.status()).toBe(200);
  expect(await initial.json()).toEqual({ new_device_email_enabled: true });

  for (const enabled of [false, true]) {
    const updated = await request.patch(path, {
      headers,
      data: { new_device_email_enabled: enabled },
    });
    expect(updated.status()).toBe(200);
    expect(await updated.json()).toEqual({ new_device_email_enabled: enabled });

    const saved = await request.get(path, { headers });
    expect(saved.status()).toBe(200);
    expect(await saved.json()).toEqual({ new_device_email_enabled: enabled });
  }

  const unauthenticated = await request.patch(path, {
    data: { new_device_email_enabled: false },
  });
  expect(unauthenticated.status()).toBe(401);
  const unchanged = await request.get(path, { headers });
  expect(await unchanged.json()).toEqual({ new_device_email_enabled: true });
});
