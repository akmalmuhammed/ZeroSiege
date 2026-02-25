import { statusTone } from "@/lib/format";

export function StatusBadge({ status }: { status: string }) {
  return <span className={`status-pill ${statusTone(status)}`}>{status}</span>;
}
