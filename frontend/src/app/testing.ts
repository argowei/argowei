import { Device, Group } from './core/models';

let nextId = 1;

/** A device with sensible defaults; override only what a test cares about. */
export function device(overrides: Partial<Device> = {}): Device {
  const id = overrides.id ?? nextId++;
  const name = overrides.name ?? `aa:bb:cc:00:00:${String(id).padStart(2, '0')}`;
  return {
    id,
    name,
    name_source: null,
    label: null,
    notes: '',
    display_name: overrides.label ?? name,
    mac_address: name,
    vendor: null,
    locally_administered_mac: false,
    is_online: true,
    trust_level: 'unknown',
    device_type: 'unknown',
    type_source: 'inferred',
    type_override: null,
    inferred: { device_type: 'unknown', confidence: 0, evidence: [] },
    group_id: 1,
    group: { id: 1, name: 'Unassigned' },
    first_seen: '2026-01-01T10:00:00Z',
    last_seen: '2026-01-01T12:00:00Z',
    addresses: [],
    names: [],
    ...overrides,
  };
}

export function group(id: number, name: string): Group {
  return {
    id,
    slug: null,
    name,
    description: '',
    is_system: false,
    defaults: {},
    device_count: 0,
    created_at: '2026-01-01T00:00:00Z',
  };
}
