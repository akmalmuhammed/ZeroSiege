export function formatUsd(amount: number): string {
  return `$${amount.toFixed(2)}`;
}

export function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

export function statusTone(status: string): string {
  if (status === "completed" || status === "COMPLETED") return "status-completed";
  if (status === "failed" || status === "FAILED") return "status-failed";
  if (status === "in-progress" || status === "RUNNING") return "status-running";
  return "status-unknown";
}
