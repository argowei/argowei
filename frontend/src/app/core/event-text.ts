import { NAME_SOURCE_LABELS, NameSource } from './device.models';
import { EVENT_TYPE_LABELS, KnownEventType, TimelineEvent } from './event.models';
import { ServiceInfo, describeService } from './scan.models';

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
    case 'scan.completed': {
      const ports = Array.isArray(p['open_ports'])
        ? p['open_ports'].filter((n): n is number => typeof n === 'number')
        : null;
      const found =
        ports === null
          ? ''
          : ports.length
            ? `: open ${ports.length === 1 ? 'port' : 'ports'} ${ports.join(', ')}`
            : ': no open ports';
      return `${profileName(text('profile'))} scan of ${text('target') ?? 'the device'}${found}.`;
    }
    case 'scan.failed': {
      const outcome = text('outcome');
      const how =
        outcome === 'cancelled'
          ? 'was cancelled'
          : outcome === 'timed_out'
            ? 'timed out'
            : 'failed';
      const error = outcome === 'failed' && text('error') ? `: ${text('error')}` : '';
      return `${profileName(text('profile'))} scan of ${text('target') ?? 'the device'} ${how}${error}.`;
    }
    case 'port.opened':
    case 'port.closed': {
      const port = portName(p);
      const verb = event.type === 'port.opened' ? 'opened' : 'closed';
      return `${port ? `Port ${port}` : 'A port'} ${verb} (${describeService(p['service'] as ServiceInfo)}) since the previous scan.`;
    }
    case 'service.changed': {
      const port = portName(p);
      return `${port ? `Port ${port}` : 'A port'} changed from ${describeService(p['before'] as ServiceInfo)} to ${describeService(p['after'] as ServiceInfo)}.`;
    }
    default:
      return eventTypeLabel(event.type);
  }
}

/** "80/tcp" from a port event's payload, or null. */
function portName(p: Record<string, unknown>): string | null {
  return typeof p['port'] === 'number' && typeof p['protocol'] === 'string'
    ? `${p['port']}/${p['protocol']}`
    : null;
}

/** "Quick", "Service", "Full", or "Port" for an unknown profile. */
function profileName(profile: string | null): string {
  return profile ? profile.charAt(0).toUpperCase() + profile.slice(1) : 'Port';
}

/** "45 s", "15 min", "3 h", "2 d". */
export function duration(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86_400)} d`;
}
