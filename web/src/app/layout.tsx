import type { Metadata } from "next";
import { headers } from "next/headers";

import { SecurityNotificationsMount } from "../components/SecurityNotificationsMount";
import "./globals.css";

export const metadata: Metadata = {
  title: "VaultPass · Your private space",
  description: "Client-encrypted password and secrets workspace",
};

export default async function Layout({ children }: { children: React.ReactNode }) {
  await headers();
  return (
    <html lang="en">
      <body>
        {children}
        <SecurityNotificationsMount />
      </body>
    </html>
  );
}
