/** Human-readable byte count: 1023 B / 1.5 KB / 2.4 MB / etc. */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) {
    // Sub-1KB values can be fractional now that the rate is computed
    // by dividing the byte delta by the poll interval. Cap at 2
    // decimals; integers stay clean ("23 B" not "23.00 B").
    return Number.isInteger(n) ? `${n} B` : `${n.toFixed(2)} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  for (const u of units) {
    if (v < 1024) return `${v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)} ${u}`;
    v /= 1024;
  }
  return `${v.toFixed(0)} PB`;
}

/** Per-second rate. Values < 1 KB/s show as `0 KB/s` for stable layout. */
export function formatRate(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec < 0) return "—";
  return `${formatBytes(bytesPerSec)}/s`;
}
