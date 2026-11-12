/**
 * Timeline events as `GET /api/events` returns them. Payload shapes per type
 * and version are documented in docs/EVENTS.md.
 */
import { AlertDevice } from './alerts.models';
import { NameSource } from './device.models';

export const SEVERITIES = ['info', 'warning', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Types the dashboard knows how to describe; others are shown by name. */
export type KnownEventType =
  'device.discovered' | 'device.online' | 'device.offline' | 'device.named';

export const EVENT_TYPE_LABELS: Record<KnownEventType, string> = {
  'device.discovered': 'Discovered',
  'device.online': 'Online',
  'device.offline': 'Offline',
  'device.named': 'Named',
};

export interface TimelineEvent {
  id: number;
  /** This event's position; send it back as `before` or `after`. */
  cursor: string;
  occurred_at: string;
  type: string;
  schema_version: number;
  severity: Severity;
  /** `null` when the event concerns no device, or the device is gone. */
  device: AlertDevice | null;
  payload: Record<string, unknown>;
}

export interface EventPage {
  /** Newest first. */
  items: TimelineEvent[];
  /** Cursor for the next older page; `null` when there is none. */
  next_before: string | null;
  /** With `after`: more new events exist than fit; reload from the top. */
  truncated: boolean;
}

export interface EventTypeInfo {
  type: string;
  schema_version: number;
  severity: Severity;
}

/** What the timeline is narrowed to; empty strings mean "any". */
export interface EventFilter {
  device: string;
  type: string;
  severity: string;
  /** `datetime-local` values in the browser's time zone. */
  from: string;
  to: string;
}

export const NO_EVENT_FILTER: EventFilter = {
  device: '',
  type: '',
  severity: '',
  from: '',
  to: '',
};

/** Payload of `device.named` (v1). */
export interface DeviceNamedPayload {
  from: string;
  to: string;
  source: NameSource;
}
