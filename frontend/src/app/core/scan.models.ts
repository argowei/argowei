/** Port scans as the API returns them (`/api/scans`, `/api/devices/{id}/scans`). */

export const SCAN_PROFILES = ['quick', 'service', 'full'] as const;
export type ScanProfile = (typeof SCAN_PROFILES)[number];

export const SCAN_PROFILE_LABELS: Record<ScanProfile, string> = {
  quick: 'Quick (100 common ports)',
  service: 'Service (1000 ports, versions)',
  full: 'Full (all 65535 ports)',
};

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timed_out';

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  queued: 'queued',
  running: 'running',
  completed: 'completed',
  failed: 'failed',
  cancelled: 'cancelled',
  timed_out: 'timed out',
};

/** Still in progress: worth polling, and can be cancelled. */
export function isActive(scan: Pick<Scan, 'status'>): boolean {
  return scan.status === 'queued' || scan.status === 'running';
}

export interface Scan {
  id: number;
  device_id: number;
  target_ip: string;
  profile: ScanProfile;
  status: ScanStatus;
  requested_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  nmap_version: string | null;
  /** Open ports found (0 until completed). */
  open_ports: number;
}

export interface ScanPort {
  protocol: string;
  port: number;
  /** `open`, `closed`, `filtered`, ... */
  state: string;
  reason: string | null;
  service: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
}

export interface ScanWithPorts extends Scan {
  ports: ScanPort[];
}
