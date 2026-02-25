"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { ShieldCheck, Radar, BookOpenText, LayoutDashboard, FolderKanban } from "lucide-react";
import { LogoutButton } from "@/components/logout-button";

interface ShellProps {
  children: ReactNode;
}

const LINKS = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scans/new", label: "Launch Scan", icon: Radar },
  { href: "/workspaces", label: "Workspaces", icon: FolderKanban },
  { href: "/tutorials", label: "Tutorials", icon: BookOpenText },
];

export function StudioShell({ children }: ShellProps) {
  const pathname = usePathname();

  return (
    <div className="shell-root">
      <aside className="shell-sidebar">
        <div className="brand">
          <ShieldCheck />
          <div>
            <p className="brand-kicker">Shannon</p>
            <p className="brand-title">Studio</p>
          </div>
        </div>
        <nav className="main-nav">
          {LINKS.map((link) => {
            const Icon = link.icon;
            const active =
              pathname === link.href ||
              (link.href !== "/" && pathname.startsWith(link.href));
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`nav-link ${active ? "active" : ""}`}
              >
                <Icon size={16} />
                {link.label}
              </Link>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <p>Single-admin mode</p>
          <LogoutButton />
        </div>
      </aside>
      <main className="shell-main">{children}</main>
    </div>
  );
}
