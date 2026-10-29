import { device } from '../../testing';
import { NO_FILTER, filterDevices, isFiltering, sortDevices } from './device-filter';

const printer = device({
  id: 1,
  label: 'Office printer',
  vendor: 'Brother Industries',
  trust_level: 'normal',
  is_online: true,
  group_id: 4,
  group: { id: 4, name: 'IoT' },
  addresses: [
    {
      id: 1, device_id: 1, ip_address: '192.168.1.20', protocol: 'V4', source: 'Arp',
      first_seen: '2026-01-01T10:00:00Z', last_seen: '2026-01-01T12:00:00Z',
    },
  ],
});
const phone = device({
  id: 2,
  name: '1a:56:ce:30:fa:6c',
  locally_administered_mac: true,
  trust_level: 'suspicious',
  is_online: false,
  last_seen: '2026-01-01T08:00:00Z',
});
const tv = device({
  id: 3,
  label: 'Living room TV',
  vendor: 'Samsung',
  trust_level: 'restricted',
  group_id: 4,
  group: { id: 4, name: 'IoT' },
  last_seen: '2026-01-01T11:00:00Z',
});
const all = [printer, phone, tv];

const ids = (list: { id: number }[]) => list.map((d) => d.id);

describe('filterDevices', () => {
  it('returns everything without a filter', () => {
    expect(ids(filterDevices(all, NO_FILTER))).toEqual([1, 2, 3]);
  });

  it('searches name, label, vendor, MAC, IP and group, ignoring case', () => {
    expect(ids(filterDevices(all, { ...NO_FILTER, query: 'PRINTER' }))).toEqual([1]);
    expect(ids(filterDevices(all, { ...NO_FILTER, query: 'samsung' }))).toEqual([3]);
    expect(ids(filterDevices(all, { ...NO_FILTER, query: '1a:56' }))).toEqual([2]);
    expect(ids(filterDevices(all, { ...NO_FILTER, query: '192.168.1.20' }))).toEqual([1]);
    expect(ids(filterDevices(all, { ...NO_FILTER, query: 'iot' }))).toEqual([1, 3]);
  });

  it('requires every word of the query to match', () => {
    expect(ids(filterDevices(all, { ...NO_FILTER, query: 'iot samsung' }))).toEqual([3]);
    expect(filterDevices(all, { ...NO_FILTER, query: 'samsung printer' })).toEqual([]);
    expect(ids(filterDevices(all, { ...NO_FILTER, query: '   ' }))).toEqual([1, 2, 3]);
  });

  it('filters by status', () => {
    expect(ids(filterDevices(all, { ...NO_FILTER, status: 'online' }))).toEqual([1, 3]);
    expect(ids(filterDevices(all, { ...NO_FILTER, status: 'offline' }))).toEqual([2]);
  });

  it('filters by trust level', () => {
    expect(ids(filterDevices(all, { ...NO_FILTER, trust: 'suspicious' }))).toEqual([2]);
    expect(filterDevices(all, { ...NO_FILTER, trust: 'trusted' })).toEqual([]);
  });

  it('filters by group, including Unassigned', () => {
    expect(ids(filterDevices(all, { ...NO_FILTER, group: 4 }))).toEqual([1, 3]);
    // The phone was never classified, so it is still in the default group (id 1).
    expect(ids(filterDevices(all, { ...NO_FILTER, group: 1 }))).toEqual([2]);
  });

  it('combines filters', () => {
    expect(ids(filterDevices(all, { ...NO_FILTER, group: 4, status: 'online', query: 'tv' }))).toEqual([3]);
  });
});

describe('isFiltering', () => {
  it('is false only for the empty filter', () => {
    expect(isFiltering(NO_FILTER)).toBe(false);
    expect(isFiltering({ ...NO_FILTER, query: '  ' })).toBe(false);
    expect(isFiltering({ ...NO_FILTER, trust: 'normal' })).toBe(true);
  });
});

describe('sortDevices', () => {
  it('sorts by name naturally and in both directions', () => {
    const named = [device({ id: 10, label: 'Box 10' }), device({ id: 2, label: 'Box 2' }), device({ id: 3, label: 'alpha' })];
    expect(ids(sortDevices(named, 'name', 'asc'))).toEqual([3, 2, 10]);
    expect(ids(sortDevices(named, 'name', 'desc'))).toEqual([10, 2, 3]);
  });

  it('puts online devices first by status, ties broken by name', () => {
    // Living room TV (3) sorts before Office printer (1); the offline phone is last.
    expect(ids(sortDevices(all, 'status', 'asc'))).toEqual([3, 1, 2]);
  });

  it('orders trust from most to least trusted', () => {
    expect(ids(sortDevices(all, 'trust', 'asc'))).toEqual([1, 3, 2]);
  });

  it('sorts by group name, ties broken by device name', () => {
    expect(ids(sortDevices(all, 'group', 'asc'))).toEqual([3, 1, 2]);
  });

  it('sorts by last seen', () => {
    expect(ids(sortDevices(all, 'last_seen', 'desc'))).toEqual([1, 3, 2]);
    expect(ids(sortDevices(all, 'last_seen', 'asc'))).toEqual([2, 3, 1]);
  });

  it('does not change the input array', () => {
    const copy = [...all];
    sortDevices(all, 'name', 'desc');
    expect(all).toEqual(copy);
  });
});
