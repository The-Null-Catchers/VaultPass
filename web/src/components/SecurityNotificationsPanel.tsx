"use client";

import { useEffect, useState } from "react";

import { api } from "../lib/api";

type SecurityNotifications = {
  new_device_email_enabled: boolean;
};

type Props = {
  onNotice?: (message: string) => void;
};

export function SecurityNotificationsPanel({ onNotice }: Props) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    void api<SecurityNotifications>("/account/security-notifications")
      .then((value) => {
        if (active) setEnabled(value.new_device_email_enabled);
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Could not load security notification settings");
      });
    return () => {
      active = false;
    };
  }, []);

  const update = async (next: boolean) => {
    if (enabled === null || saving) return;
    const previous = enabled;
    setEnabled(next);
    setSaving(true);
    setError("");
    try {
      const value = await api<SecurityNotifications>("/account/security-notifications", "PATCH", {
        new_device_email_enabled: next,
      });
      setEnabled(value.new_device_email_enabled);
      onNotice?.(
        value.new_device_email_enabled
          ? "New-device sign-in emails enabled"
          : "New-device sign-in emails disabled",
      );
    } catch (reason) {
      setEnabled(previous);
      setError(reason instanceof Error ? reason.message : "Could not update security notification settings");
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="panel" aria-labelledby="security-notifications-title">
      <h2 id="security-notifications-title">Security notifications</h2>
      <p>
        Get an email after a new device successfully signs in. The message includes the device label only and never contains vault data.
      </p>
      {enabled === null ? (
        <p aria-live="polite">Loading security notification settings…</p>
      ) : (
        <label className="check">
          <input
            type="checkbox"
            checked={enabled}
            disabled={saving}
            onChange={(event) => void update(event.target.checked)}
          />
          Email me when a new device signs in
        </label>
      )}
      {saving && <small aria-live="polite">Saving…</small>}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
