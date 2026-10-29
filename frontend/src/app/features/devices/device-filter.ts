import { Device, TRUST_LEVELS, TrustLevel } from '../../core/models';

export interface DeviceFilter {
  query: string;
  status: 'all' | 'online' | 'offline';
  trust: TrustLevel | 'all';
  /** A group id, `'none'` for unclassified devices, or `'all'`. */
  group: number | 'none' | 'all';
}

export const NO_FILTER: DeviceFilter = { query: '', status: 'all', trust: 'all', group: 'all' };

export type SortKey = 'name' | 'status' | 'trust' | 'group' | 'last_seen';
export type SortDirection = 'asc' | 'desc';

export function isFiltering(filter: DeviceFilter): boolean {
  return (
    filter.query.trim() !== '' ||
    filter.status !== 'all' ||
    filter.trust !== 'all' ||
    filter.group !== 'all'
  );
}

/** Words typed into the search box must all match somewhere on the device. */
function searchText(device: Device): string {
  return [
    device.display_name,
    device.name,
    device.mac_address,
    device.vendor ?? '',
    device.group?.name ?? '',
    ...device.addresses.map((address) => address.ip_address),
  ]
    .join(' ')
    .toLowerCase();
}

export function filterDevices(devices: Device[], filter: DeviceFilter): Device[] {
  const words = filter.query.toLowerCase().split(/\s+/).filter(Boolean);

  return devices.filter((device) => {
    if (filter.status === 'online' && !device.is_online) return false;
    if (filter.status === 'offline' && device.is_online) return false;
    if (filter.trust !== 'all' && device.trust_level !== filter.trust) return false;
    if (filter.group === 'none' && device.group_id !== null) return false;
    if (typeof filter.group === 'number' && device.group_id !== filter.group) return false;

    const text = searchText(device);
    return words.every((word) => text.includes(word));
  });
}

function compare(a: Device, b: Device, key: SortKey): number {
  switch (key) {
    case 'name':
      return a.display_name.localeCompare(b.display_name, undefined, {
        numeric: true,
        sensitivity: 'base',
      });
    case 'status':
      return Number(b.is_online) - Number(a.is_online);
    case 'trust':
      return TRUST_LEVELS.indexOf(a.trust_level) - TRUST_LEVELS.indexOf(b.trust_level);
    case 'group':
      // Unclassified devices sort after every group.
      if (!a.group || !b.group) return Number(!a.group) - Number(!b.group);
      return a.group.name.localeCompare(b.group.name, undefined, { sensitivity: 'base' });
    case 'last_seen':
      return new Date(a.last_seen).getTime() - new Date(b.last_seen).getTime();
  }
}

/** Stable sort; ties fall back to the name so the order never jumps around. */
export function sortDevices(
  devices: Device[],
  key: SortKey,
  direction: SortDirection,
): Device[] {
  const sign = direction === 'asc' ? 1 : -1;
  return [...devices].sort(
    (a, b) => sign * compare(a, b, key) || compare(a, b, 'name') || a.id - b.id,
  );
}
