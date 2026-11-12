import { TimelineEvent } from './event.models';
import { describeEvent, duration, eventTypeLabel } from './event-text';

function event(type: string, payload: Record<string, unknown>): TimelineEvent {
  return {
    id: 1,
    cursor: 'c',
    occurred_at: '2026-01-01T12:00:00Z',
    type,
    schema_version: 1,
    severity: 'info',
    device: null,
    payload,
  };
}

describe('describeEvent', () => {
  it('describes every known type from its payload', () => {
    expect(
      describeEvent(
        event('device.discovered', { ip: '192.168.1.5', interface: 'eth0', baseline: true }),
      ),
    ).toBe('First seen at 192.168.1.5 on eth0 (part of the baseline).');
    expect(describeEvent(event('device.online', { ip: '192.168.1.5', interface: 'eth0' }))).toBe(
      'Answered again at 192.168.1.5 on eth0.',
    );
    expect(describeEvent(event('device.offline', { missed_scans: 3, silent_for_secs: 900 }))).toBe(
      'Marked offline after 3 missed scans, silent for 15 min.',
    );
    expect(
      describeEvent(event('device.named', { from: 'aa:bb', to: 'iPhone', source: 'rdns' })),
    ).toBe('Renamed from "aa:bb" to "iPhone" (from Reverse DNS).');
  });

  it('copes with missing or unexpected payload fields', () => {
    expect(describeEvent(event('device.discovered', {}))).toBe('First seen.');
    expect(describeEvent(event('device.offline', { missed_scans: '3' }))).toBe('Marked offline.');
    expect(describeEvent(event('device.offline', { missed_scans: 1 }))).toBe(
      'Marked offline after 1 missed scan.',
    );
    expect(describeEvent(event('device.named', { to: 'x' }))).toBe('Name changed.');
    expect(
      describeEvent(event('device.named', { from: 'a', to: 'b', source: 'carrier pigeon' })),
    ).toBe('Renamed from "a" to "b".');
  });

  it('describes scan outcomes', () => {
    expect(
      describeEvent(
        event('scan.completed', { profile: 'quick', target: '192.168.1.5', open_ports: [22, 80] }),
      ),
    ).toBe('Quick scan of 192.168.1.5: open ports 22, 80.');
    expect(
      describeEvent(
        event('scan.completed', { profile: 'full', target: '10.0.0.1', open_ports: [] }),
      ),
    ).toBe('Full scan of 10.0.0.1: no open ports.');
    expect(
      describeEvent(
        event('scan.failed', { profile: 'service', target: '10.0.0.1', outcome: 'timed_out' }),
      ),
    ).toBe('Service scan of 10.0.0.1 timed out.');
    expect(
      describeEvent(
        event('scan.failed', {
          profile: 'quick',
          target: '10.0.0.1',
          outcome: 'failed',
          error: 'boom',
        }),
      ),
    ).toBe('Quick scan of 10.0.0.1 failed: boom.');
    expect(describeEvent(event('scan.failed', { outcome: 'cancelled' }))).toBe(
      'Port scan of the device was cancelled.',
    );
  });

  it('shows unknown types by name', () => {
    expect(describeEvent(event('port.opened', {}))).toBe('port.opened');
    expect(eventTypeLabel('device.named')).toBe('Named');
    expect(eventTypeLabel('port.opened')).toBe('port.opened');
  });
});

describe('duration', () => {
  it('picks a readable unit', () => {
    expect(duration(45)).toBe('45 s');
    expect(duration(900)).toBe('15 min');
    expect(duration(3 * 3600)).toBe('3 h');
    expect(duration(2 * 86_400)).toBe('2 d');
  });
});
