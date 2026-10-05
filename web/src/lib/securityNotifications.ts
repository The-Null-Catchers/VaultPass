import { api } from "./api";

export type SecurityNotifications = {
  new_device_email_enabled: boolean;
};

export function getSecurityNotifications() {
  return api<SecurityNotifications>("/account/security-notifications");
}

export function updateSecurityNotifications(newDeviceEmailEnabled: boolean) {
  return api<SecurityNotifications>("/account/security-notifications", "PATCH", {
    new_device_email_enabled: newDeviceEmailEnabled,
  });
}
