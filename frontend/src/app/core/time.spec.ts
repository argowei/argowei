import { timeAgo } from './time';

describe('timeAgo', () => {
  const now = new Date('2026-01-01T12:00:00Z');
  const ago = (seconds: number) => new Date(now.getTime() - seconds * 1000).toISOString();

  it('says "just now" for very recent times', () => {
    expect(timeAgo(ago(3), now)).toBe('just now');
  });

  it('uses the largest fitting unit', () => {
    expect(timeAgo(ago(45), now)).toBe('45 s ago');
    expect(timeAgo(ago(5 * 60), now)).toBe('5 min ago');
    expect(timeAgo(ago(3 * 3600 + 120), now)).toBe('3 h ago');
    expect(timeAgo(ago(12 * 86400), now)).toBe('12 d ago');
  });

  it('falls back to a date for old values and a dash for garbage', () => {
    expect(timeAgo(ago(90 * 86400), now)).toMatch(/\d/);
    expect(timeAgo('not a date', now)).toBe('—');
  });
});
