import { Component, computed, input, output } from '@angular/core';

import { Device } from '../../core/device.models';
import { DeviceFilter, NO_FILTER } from './device-filter';

/** How recently a device must have first appeared to count as new. */
export const NEW_DEVICE_WINDOW_MS = 24 * 60 * 60 * 1000;

/** The counts shown above the device table. */
export interface DeviceCounts {
  total: number;
  online: number;
  offline: number;
  recentlyAdded: number;
  needsReview: number;
}

/**
 * Count devices for the summary tiles. `now` is passed in so the "new in the
 * last 24 hours" count is testable without a clock.
 */
export function countDevices(devices: Device[], now: number): DeviceCounts {
  const counts: DeviceCounts = {
    total: devices.length,
    online: 0,
    offline: 0,
    recentlyAdded: 0,
    needsReview: 0,
  };
  for (const device of devices) {
    if (device.is_online) {
      counts.online += 1;
    } else {
      counts.offline += 1;
    }
    const firstSeen = Date.parse(device.first_seen);
    // An unparsable timestamp is not evidence that a device is new.
    if (!Number.isNaN(firstSeen) && now - firstSeen <= NEW_DEVICE_WINDOW_MS) {
      counts.recentlyAdded += 1;
    }
    // Trust the operator set deliberately; "unknown" is the unreviewed default.
    if (device.trust_level === 'unknown' || device.trust_level === 'suspicious') {
      counts.needsReview += 1;
    }
  }
  return counts;
}

/**
 * Counts for the current inventory, above the device table.
 *
 * Each tile is a button that applies the filter it describes, so the answer to
 * "what should I look at?" is one click away rather than a dropdown hunt. The
 * tile matching the active filter is marked pressed, which also makes the
 * current view visible when a filter is set from elsewhere.
 */
@Component({
  selector: 'app-device-summary',
  template: `
    <h2 class="visually-hidden">Inventory summary</h2>
    <ul class="tiles">
      @for (tile of tiles(); track tile.key) {
        <li>
          @if (tile.filter; as target) {
            <button
              type="button"
              class="tile"
              [class]="tile.tone"
              [class.active]="tile.active"
              [attr.aria-pressed]="tile.active"
              (click)="apply.emit(target)"
            >
              <span class="value">{{ tile.value }}</span>
              <span class="label">{{ tile.label }}</span>
            </button>
          } @else {
            <!-- No filter expresses this count, so it stays a plain readout
                 rather than a button that would do nothing when clicked. -->
            <p class="tile readout" [class]="tile.tone">
              <span class="value">{{ tile.value }}</span>
              <span class="label">{{ tile.label }}</span>
            </p>
          }
        </li>
      }
    </ul>
  `,
  styles: `
    .tiles {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr));
      gap: 0.7rem;
      margin: 1rem 0 0;
      padding: 0;
      list-style: none;
    }
    .tile {
      display: flex;
      flex-direction: column;
      gap: 0.15rem;
      width: 100%;
      margin: 0;
      padding: 0.8rem 0.9rem;
      border: 1px solid var(--border);
      border-radius: 0.8rem;
      background: var(--bg-card);
      color: inherit;
      font-weight: 400;
      text-align: left;
      cursor: pointer;
    }
    .tile:hover:not(.readout) {
      border-color: var(--muted);
    }
    .tile.readout {
      cursor: default;
    }
    .tile.active {
      border-color: var(--accent);
    }
    .value {
      font-size: 1.5rem;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
      line-height: 1.1;
    }
    .label {
      color: var(--muted);
      font-size: 0.8125rem;
    }
    /* A tile only takes an accent colour when its count is worth attention. */
    .tile.good .value {
      color: var(--accent);
    }
    .tile.warn .value {
      color: var(--warn);
    }
  `,
})
export class DeviceSummary {
  readonly devices = input.required<Device[]>();
  readonly filter = input.required<DeviceFilter>();
  /** Emits the filter the clicked tile stands for. */
  readonly apply = output<DeviceFilter>();

  private readonly counts = computed(() => countDevices(this.devices(), Date.now()));

  protected readonly tiles = computed(() => {
    const counts = this.counts();
    const filter = this.filter();
    return [
      {
        key: 'total',
        label: counts.total === 1 ? 'Device' : 'Devices',
        value: counts.total,
        tone: '',
        filter: NO_FILTER,
        active: filter.status === 'all' && filter.trust === 'all',
      },
      {
        key: 'online',
        label: 'Online',
        value: counts.online,
        tone: counts.online ? 'good' : '',
        filter: { ...NO_FILTER, status: 'online' as const },
        active: filter.status === 'online',
      },
      {
        key: 'offline',
        label: 'Offline',
        value: counts.offline,
        tone: '',
        filter: { ...NO_FILTER, status: 'offline' as const },
        active: filter.status === 'offline',
      },
      {
        key: 'new',
        label: 'New in 24 h',
        value: counts.recentlyAdded,
        tone: counts.recentlyAdded ? 'warn' : '',
        filter: null,
        active: false,
      },
      {
        key: 'review',
        label: 'Unknown or suspicious',
        value: counts.needsReview,
        tone: counts.needsReview ? 'warn' : '',
        filter: { ...NO_FILTER, trust: 'unknown' as const },
        active: filter.trust === 'unknown' || filter.trust === 'suspicious',
      },
    ];
  });
}
