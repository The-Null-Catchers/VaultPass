import assert from "node:assert/strict";
import test from "node:test";

import { clearTokens, setTokens } from "./api";
import {
  getSecurityNotifications,
  updateSecurityNotifications,
} from "./securityNotifications";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

test("security notification helper reads the authenticated preference", async () => {
  const originalFetch = globalThis.fetch;
  setTokens("access-token", "refresh-token");
  globalThis.fetch = async (input, init) => {
    assert.equal(input, "/api/account/security-notifications");
    assert.equal(init?.method, "GET");
    assert.equal(
      (init?.headers as Record<string, string>).Authorization,
      "Bearer access-token",
    );
    assert.equal(init?.body, undefined);
    return jsonResponse({ new_device_email_enabled: true });
  };

  try {
    assert.deepEqual(await getSecurityNotifications(), {
      new_device_email_enabled: true,
    });
  } finally {
    globalThis.fetch = originalFetch;
    clearTokens();
  }
});

test("security notification helper patches only the new-device email preference", async () => {
  const originalFetch = globalThis.fetch;
  setTokens("access-token", "refresh-token");
  globalThis.fetch = async (input, init) => {
    assert.equal(input, "/api/account/security-notifications");
    assert.equal(init?.method, "PATCH");
    assert.deepEqual(JSON.parse(String(init?.body)), {
      new_device_email_enabled: false,
    });
    return jsonResponse({ new_device_email_enabled: false });
  };

  try {
    assert.deepEqual(await updateSecurityNotifications(false), {
      new_device_email_enabled: false,
    });
  } finally {
    globalThis.fetch = originalFetch;
    clearTokens();
  }
});
