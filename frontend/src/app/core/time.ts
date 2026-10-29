const UNITS: [limitSeconds: number, divisor: number, unit: string][] = [
  [60, 1, 's'],
  [3600, 60, 'min'],
  [86400, 3600, 'h'],
  [30 * 86400, 86400, 'd'],
];

/** "just now", "5 min ago", "3 h ago", "12 d ago", or the date for older values. */
export function timeAgo(iso: string, now: Date = new Date()): string {
  const seconds = Math.round((now.getTime() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) return '—';
  if (seconds < 10) return 'just now';
  for (const [limit, divisor, unit] of UNITS) {
    if (seconds < limit) return `${Math.floor(seconds / divisor)} ${unit} ago`;
  }
  return new Date(iso).toLocaleDateString();
}
