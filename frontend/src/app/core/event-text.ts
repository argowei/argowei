import { NAME_SOURCE_LABELS, NameSource } from './device.models';
import { EVENT_TYPE_LABELS, KnownEventType, TimelineEvent } from './event.models';

/** The label for a type, falling back to the raw type for unknown ones. */
export function eventTypeLabel(type: string): string {
  return EVENT_TYPE_LABELS[type as KnownEventType] ?? type;
}

/**
 * One line saying what happened, built from the payload. Payload fields are
 * read defensively: an older or newer schema version must not break the
 * timeline, it only gets a plainer description.
 */
export function describeEvent(event: TimelineEvent): string {
  const p = event.payload;
  const text = (key: string): string | null => (typeof p[key] === 'string' ? p[key] : null);
  const number = (key: string): number | null => (typeof p[key] === 'number' ? p[key] : null);
  const where = [text('ip'), text('interface') && `on ${text('interface')}`]
    .filter(Boolean)
    .join(' ');

  switch (event.type) {
    case 'device.discovered':
      return `First seen${where ? ` at ${where}` : ''}${p['baseline'] === true ? ' (part of the baseline)' : ''}.`;
    case 'device.online':
      return `Answered again${where ? ` at ${where}` : ''}.`;
    case 'device.offline': {
      const missed = number('missed_scans');
      const silent = number('silent_for_secs');
      const parts = [
        missed !== null ? `${missed} missed scan${missed === 1 ? '' : 's'}` : null,
        silent !== null ? `silent for ${duration(silent)}` : null,
      ].filter(Boolean);
      return `Marked offline${parts.length ? ` after ${parts.join(', ')}` : ''}.`;
    }
    case 'device.named': {
      const from = text('from');
      const to = text('to');
      const source = text('source') as NameSource | null;
      const via =
        source && NAME_SOURCE_LABELS[source] ? ` (from ${NAME_SOURCE_LABELS[source]})` : '';
      return from && to ? `Renamed from "${from}" to "${to}"${via}.` : 'Name changed.';
    }
    default:
      return eventTypeLabel(event.type);
  }
}

/** "45 s", "15 min", "3 h", "2 d". */
export function duration(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86_400)} d`;
}
