"use client";

import { useRouter } from "next/navigation";
import { LogOut } from "lucide-react";

export function LogoutButton() {
  const router = useRouter();

  async function onLogout(): Promise<void> {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  }

  return (
    <button type="button" className="ghost-button" onClick={onLogout}>
      <LogOut size={16} />
      Sign out
    </button>
  );
}
