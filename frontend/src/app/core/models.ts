export const TRUST_LEVELS = ['trusted', 'normal', 'restricted', 'unknown', 'suspicious'] as const;
export type TrustLevel = (typeof TRUST_LEVELS)[number];

export interface DeviceAddress {
  id: number;
  device_id: number;
  ip_address: string;
  protocol: 'V4' | 'V6';
  source: 'Arp' | 'Ndp';
  first_seen: string;
  last_seen: string;
}

export interface GroupRef {
  id: number;
  name: string;
}

export interface Device {
  id: number;
  /** Name derived by discovery. */
  name: string;
  /** Name chosen by the user. */
  label: string | null;
  notes: string;
  /** The label if set, otherwise `name`. */
  display_name: string;
  mac_address: string;
  vendor: string | null;
  /** MAC not assigned by a manufacturer: typically randomization. */
  locally_administered_mac: boolean;
  is_online: boolean;
  trust_level: TrustLevel;
  group_id: number | null;
  group: GroupRef | null;
  first_seen: string;
  last_seen: string;
  addresses: DeviceAddress[];
}

export interface Group {
  id: number;
  slug: string | null;
  name: string;
  description: string;
  is_system: boolean;
  defaults: Record<string, unknown>;
  device_count: number;
  created_at: string;
}

/** Fields a user may change; an omitted field stays as it is. */
export interface DevicePatch {
  label?: string | null;
  notes?: string;
  group_id?: number | null;
  trust_level?: TrustLevel;
}
