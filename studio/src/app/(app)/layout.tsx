import { redirect } from "next/navigation";
import type { ReactNode } from "react";
import { StudioShell } from "@/components/studio-shell";
import { getSessionFromCookies } from "@/lib/auth";

export default async function AppLayout({
  children,
}: {
  children: ReactNode;
}) {
  const session = await getSessionFromCookies();
  if (!session) {
    redirect("/login");
  }
  return <StudioShell>{children}</StudioShell>;
}
