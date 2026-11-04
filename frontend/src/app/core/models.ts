export const TRUST_LEVELS = ['trusted', 'normal', 'restricted', 'unknown', 'suspicious'] as const;
export type TrustLevel = (typeof TRUST_LEVELS)[number];

/** Where a discovered name came from. */
export type NameSource = 'dhcp' | 'mdns' | 'netbios' | 'rdns';

export const NAME_SOURCE_LABELS: Record<NameSource, string> = {
  dhcp: 'DHCP lease',
  mdns: 'mDNS',
  netbios: 'NetBIOS',
  rdns: 'Reverse DNS',
};

/** What one source last called the device. */
export interface DeviceName {
  source: NameSource;
  name: string;
  last_seen: string;
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
  /** Name derived by discovery (the MAC until a source names the device). */
  name: string;
  /** Which source `name` comes from; `null` while it is just the MAC. */
  name_source: NameSource | null;
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
  /** Every device is in exactly one group; new ones start in "Unassigned". */
  group_id: number;
  group: GroupRef;
  first_seen: string;
  last_seen: string;
  addresses: DeviceAddress[];
  /** Every source's latest answer, preferred source first. */
  names: DeviceName[];
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
}
