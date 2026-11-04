export type AlertStatus = 'open' | 'acknowledged' | 'resolved';
export type AlertSeverity = 'info' | 'warning' | 'critical';

/** What can be done about an alert; `available: false` actions are shown but disabled. */
export interface SuggestedAction {
  action: 'trust' | 'restrict' | 'block' | 'quarantine';
  label: string;
  available: boolean;
  effect?: string;
  reason?: string;
}

export interface AlertDevice {
  id: number;
  display_name: string;
  mac_address: string;
  vendor: string | null;
}

export interface Alert {
  id: number;
  type: string;
  severity: AlertSeverity;
  status: AlertStatus;
  created_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  /** `null` once the device itself is gone. */
  device: AlertDevice | null;
  payload: {
    mac?: string;
    vendor?: string | null;
    interface?: string;
    ip?: string;
    suggested_actions?: SuggestedAction[];
  };
}

export interface AlertPage {
  items: Alert[];
  /** Pass as `before` to get the next, older page; `null` on the last page. */
  next_before: number | null;
}

export type BaselineState = 'pending' | 'learning' | 'done';

export interface BaselineStatus {
  state: BaselineState;
  window_secs: number;
  /** When silent learning ends; only set while `learning`. */
  ends_at: string | null;
}

export interface AlertsStatus {
  open: number;
  acknowledged: number;
  baseline: BaselineStatus;
}

/** `active` is open plus acknowledged. */
export type AlertView = 'active' | 'resolved';
