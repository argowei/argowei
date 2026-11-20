import { device } from '../../testing';
import { NEW_DEVICE_WINDOW_MS, countDevices } from './device-summary';

const FIRST_SEEN = '2026-01-01T10:00:00Z';
const SEEN_AT = Date.parse(FIRST_SEEN);

describe('countDevices', () => {
  it('counts an empty inventory without dividing anything', () => {
    expect(countDevices([], SEEN_AT)).toEqual({
      total: 0,
      online: 0,
      offline: 0,
      recentlyAdded: 0,
      needsReview: 0,
    });
  });

  it('splits devices by presence', () => {
    const counts = countDevices(
      [
        device({ id: 1, is_online: true }),
        device({ id: 2, is_online: true }),
        device({ id: 3, is_online: false }),
      ],
      SEEN_AT,
    );
    expect(counts.total).toBe(3);
    expect(counts.online).toBe(2);
    expect(counts.offline).toBe(1);
  });

  it('counts a device as new only inside the window', () => {
    const devices = [device({ id: 1, first_seen: FIRST_SEEN })];
    // At the boundary the device is still new; one millisecond later it is not.
    expect(countDevices(devices, SEEN_AT + NEW_DEVICE_WINDOW_MS).recentlyAdded).toBe(1);
    expect(countDevices(devices, SEEN_AT + NEW_DEVICE_WINDOW_MS + 1).recentlyAdded).toBe(0);
  });

  it('does not treat an unreadable first_seen as new', () => {
    // A missing or malformed timestamp is not evidence that a device is new,
    // so it must not raise the count that draws attention.
    const counts = countDevices([device({ id: 1, first_seen: 'not a date' })], SEEN_AT);
    expect(counts.recentlyAdded).toBe(0);
    expect(counts.total).toBe(1);
  });

  it('flags unknown and suspicious devices for review, not the reviewed ones', () => {
    const counts = countDevices(
      [
        device({ id: 1, trust_level: 'unknown' }),
        device({ id: 2, trust_level: 'suspicious' }),
        device({ id: 3, trust_level: 'trusted' }),
        device({ id: 4, trust_level: 'normal' }),
        device({ id: 5, trust_level: 'restricted' }),
      ],
      SEEN_AT,
    );
    // `restricted` is a decision the operator made, so it needs no review.
    expect(counts.needsReview).toBe(2);
  });

  it('counts every device exactly once across presence', () => {
    const devices = [
      device({ id: 1, is_online: true }),
      device({ id: 2, is_online: false }),
      device({ id: 3, is_online: false }),
    ];
    const counts = countDevices(devices, SEEN_AT);
    expect(counts.online + counts.offline).toBe(counts.total);
  });
});
