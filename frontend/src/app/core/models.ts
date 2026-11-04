export const TRUST_LEVELS = ['trusted', 'normal', 'restricted', 'unknown', 'suspicious'] as const;
export type TrustLevel = (typeof TRUST_LEVELS)[number];

export const DEVICE_TYPES = [
  'smartphone',
  'laptop',
  'server',
  'iot',
  'printer',
  'router',
  'unknown',
] as const;
export type DeviceType = (typeof DEVICE_TYPES)[number];

export const DEVICE_TYPE_LABELS: Record<DeviceType, string> = {
  smartphone: 'Smartphone',
  laptop: 'Laptop',
  server: 'Server',
  iot: 'IoT device',
  printer: 'Printer',
  router: 'Router',
  unknown: 'Unknown',
};

/** One rule that fired during classification. */
export interface Evidence {
  kind: 'vendor' | 'private_mac' | 'hostname' | 'port' | 'mdns';
  detail: string;
  type: DeviceType;
  /** Percent of confidence this one signal gives to `type`. */
  weight: number;
}

export interface Classification {
  device_type: DeviceType;
  /** 0-100; 0 when the type is unknown. */
  confidence: number;
  evidence: Evidence[];
}

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
  /** The type to show: the override if set, otherwise the inferred type. */
  device_type: DeviceType;
  type_source: 'manual' | 'inferred';
  type_override: DeviceType | null;
  inferred: Classification;
  /** Every device is in exactly one group; new ones start in "Unassigned". */
  group_id: number;
  group: GroupRef;
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
  group_id?: number;
  trust_level?: TrustLevel;
  /** A type sets the override; `null` removes it. */
  type_override?: DeviceType | null;
}
