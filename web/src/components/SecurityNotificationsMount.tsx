"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

import { SecurityNotificationsPanel } from "./SecurityNotificationsPanel";

export function SecurityNotificationsMount() {
  const [target, setTarget] = useState<Element | null>(null);

  useEffect(() => {
    const locate = () => {
      const section = document.querySelector(".breadcrumb strong")?.textContent?.trim();
      setTarget(section === "Settings" ? document.querySelector(".settings-grid") : null);
    };

    locate();
    const observer = new MutationObserver(locate);
    observer.observe(document.body, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, []);

  if (!target) return null;
  return createPortal(<SecurityNotificationsPanel />, target);
}
