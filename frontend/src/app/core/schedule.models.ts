/** Scan schedules as `/api/scan-schedules` returns them. */
import { ScanProfile } from './scan.models';

export type ScheduleTarget =
  { kind: 'device'; id: number } | { kind: 'group'; id: number } | { kind: 'all' };

export interface ScanSchedule {
  id: number;
  name: string;
  cron: string;
  /** What the expression means, e.g. "At 03:00". */
  description: string | null;
  profile: ScanProfile;
  target: ScheduleTarget | null;
  /** Device or group name; `null` for "all" or a target that is gone. */
  target_name: string | null;
  enabled: boolean;
  created_by: string;
  created_at: string;
  last_run_at: string | null;
  next_run_at: string | null;
  /** The next runs, the first being `next_run_at`; empty while disabled. */
  upcoming: string[];
}

/** What the form sends; on update, omitted fields stay as they are. */
export interface ScheduleInput {
  name: string;
  cron: string;
  profile: ScanProfile;
  target: ScheduleTarget;
  enabled?: boolean;
}

export interface CronPreview {
  description: string;
  upcoming: string[];
}
