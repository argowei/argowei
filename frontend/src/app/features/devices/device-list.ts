import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { Subject, catchError, forkJoin, map, merge, of, switchMap } from 'rxjs';

import { describeApiError } from '../../core/api-error';
import { DEVICE_POLL_MS, DevicesService } from '../../core/devices.service';
import { DEVICE_TYPES, DEVICE_TYPE_LABELS, Device, TRUST_LEVELS } from '../../core/device.models';
import { Group } from '../../core/group.models';
import { poll } from '../../core/poll';
import { StatusIndicator } from '../../shared/status-indicator';
import { TimeAgoPipe } from '../../shared/time-ago.pipe';
import {
  DeviceFilter,
  NO_FILTER,
  SortDirection,
  SortKey,
  filterDevices,
  sortDevices,
} from './device-filter';

/**
 * All devices, filtered and sorted in the browser, refreshed every
 * `DEVICE_POLL_MS`. A failed refresh keeps the last known list on screen.
 */
@Component({
  selector: 'app-device-list',
  imports: [RouterLink, StatusIndicator, TimeAgoPipe],
  template: `
    <section class="page">
      <header class="page-head">
        <h1>Devices</h1>
        @if (devices().length) {
          <p class="muted" aria-live="polite">{{ shown().length }} of {{ devices().length }}</p>
        }
      </header>

      <form class="filters" role="search" (submit)="$event.preventDefault()">
        <div class="field grow">
          <label for="search">Search</label>
          <input
            id="search"
            type="search"
            placeholder="Name, MAC, IP, vendor, group"
            [value]="filter().query"
            (input)="setQuery($event)"
          />
        </div>
        <div class="field">
          <label for="status">Status</label>
          <select id="status" (change)="setStatus($event)">
            <option value="all" [selected]="filter().status === 'all'">All</option>
            <option value="online" [selected]="filter().status === 'online'">Online</option>
            <option value="offline" [selected]="filter().status === 'offline'">Offline</option>
          </select>
        </div>
        <div class="field">
          <label for="trust">Trust</label>
          <select id="trust" (change)="setTrust($event)">
            <option value="all" [selected]="filter().trust === 'all'">All</option>
            @for (level of trustLevels; track level) {
              <option [value]="level" [selected]="filter().trust === level">{{ level }}</option>
            }
          </select>
        </div>
        <div class="field">
          <label for="type">Type</label>
          <select id="type" (change)="setType($event)">
            <option value="all" [selected]="filter().type === 'all'">All</option>
            @for (type of deviceTypes; track type) {
              <option [value]="type" [selected]="filter().type === type">
                {{ typeLabels[type] }}
              </option>
            }
          </select>
        </div>
        <div class="field">
          <label for="group">Group</label>
          <select id="group" (change)="setGroup($event)">
            <option value="all" [selected]="filter().group === 'all'">All</option>
            @for (group of groups(); track group.id) {
              <option [value]="group.id" [selected]="filter().group === group.id">
                {{ group.name }}
              </option>
            }
          </select>
        </div>
      </form>

      @if (loading()) {
        <p class="state" role="status">Loading devices…</p>
      } @else if (error() && !devices().length) {
        <div class="state" role="alert">
          <p>Could not load devices. {{ error() }}</p>
          <button type="button" (click)="reload()">Retry</button>
        </div>
      } @else if (!devices().length) {
        <div class="state">
          <p><strong>No devices yet.</strong></p>
          <p class="muted">
            Devices appear once discovery has scanned the network. Set
            <code>ARGOWEI_DISCOVERY_INTERFACES</code> and give the API permission to open raw
            sockets.
          </p>
        </div>
      } @else if (!shown().length) {
        <div class="state">
          <p>No device matches these filters.</p>
          <button type="button" class="secondary" (click)="clearFilters()">Clear filters</button>
        </div>
      } @else {
        @if (error()) {
          <p class="banner warn" role="alert">
            Could not refresh: {{ error() }} Showing the last known data.
          </p>
        }
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                @for (column of columns; track column.key) {
                  <th scope="col" [class]="column.class" [attr.aria-sort]="ariaSort(column.key)">
                    <button type="button" class="sort" (click)="sortBy(column.key)">
                      {{ column.label }}<span aria-hidden="true">{{ arrow(column.key) }}</span>
                    </button>
                  </th>
                }
                <th scope="col" class="col-ip">Address</th>
              </tr>
            </thead>
            <tbody>
              @for (device of shown(); track device.id) {
                <tr>
                  <th scope="row" class="name">
                    <a [routerLink]="['/devices', device.id]">{{ device.display_name }}</a>
                    <span class="sub">{{ subtitle(device) }}</span>
                  </th>
                  <td>
                    <app-status-indicator [online]="device.is_online" />
                  </td>
                  <td class="col-type">{{ typeLabels[device.device_type] }}</td>
                  <td>
                    <span class="pill" [class]="'trust-' + device.trust_level">{{
                      device.trust_level
                    }}</span>
                  </td>
                  <td class="col-group">{{ device.group.name }}</td>
                  <td class="col-seen" [title]="device.last_seen">
                    {{ device.last_seen | timeAgo }}
                  </td>
                  <td class="col-ip">{{ address(device) }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
  `,
  styles: `
    .page-head {
      display: flex;
      align-items: baseline;
      gap: 1rem;
    }
    .page-head h1 {
      margin: 0;
      font-size: 1.6rem;
    }
    .filters {
      display: flex;
      flex-wrap: wrap;
      gap: 0.8rem;
      margin: 1rem 0;
      align-items: end;
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 0.3rem;
      min-width: 8rem;
    }
    .field.grow {
      flex: 1 1 14rem;
    }
    .field label {
      margin: 0;
    }
    select {
      padding: 0.7rem 0.6rem;
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      background: var(--bg-input);
      color: inherit;
      font: inherit;
    }
    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 0.8rem;
      background: var(--bg-card);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th,
    td {
      padding: 0.7rem 0.9rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    tbody tr:last-child > * {
      border-bottom: 0;
    }
    thead th {
      font-size: 0.8rem;
      color: var(--muted);
      font-weight: 600;
    }
    button.sort {
      margin: 0;
      padding: 0;
      border: 0;
      background: none;
      color: inherit;
      font: inherit;
      font-weight: 600;
      cursor: pointer;
    }
    button.sort span {
      margin-left: 0.3rem;
    }
    th.name {
      font-weight: 400;
      white-space: normal;
    }
    th.name a {
      color: var(--text);
      font-weight: 600;
    }
    .sub {
      display: block;
      font-size: 0.8rem;
      color: var(--muted);
    }
    code {
      font-size: 0.85em;
    }
    @media (max-width: 900px) {
      .col-ip,
      .col-seen {
        display: none;
      }
    }
    @media (max-width: 640px) {
      .col-group,
      .col-type {
        display: none;
      }
    }
  `,
})
export class DeviceList {
  private readonly api = inject(DevicesService);
  private readonly pollMs = inject(DEVICE_POLL_MS);

  protected readonly trustLevels = TRUST_LEVELS;
  protected readonly deviceTypes = DEVICE_TYPES;
  protected readonly typeLabels = DEVICE_TYPE_LABELS;
  protected readonly columns: { key: SortKey; label: string; class: string }[] = [
    { key: 'name', label: 'Name', class: 'col-name' },
    { key: 'status', label: 'Status', class: 'col-status' },
    { key: 'type', label: 'Type', class: 'col-type' },
    { key: 'trust', label: 'Trust', class: 'col-trust' },
    { key: 'group', label: 'Group', class: 'col-group' },
    { key: 'last_seen', label: 'Last seen', class: 'col-seen' },
  ];

  protected readonly devices = signal<Device[]>([]);
  protected readonly groups = signal<Group[]>([]);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly filter = signal<DeviceFilter>(NO_FILTER);
  protected readonly sort = signal<{ key: SortKey; direction: SortDirection }>({
    key: 'last_seen',
    direction: 'desc',
  });

  protected readonly shown = computed(() =>
    sortDevices(
      filterDevices(this.devices(), this.filter()),
      this.sort().key,
      this.sort().direction,
    ),
  );

  private readonly reloads = new Subject<void>();

  constructor() {
    // Polls on a timer; "Retry" triggers an immediate load. switchMap drops a
    // slow response when a newer request has started.
    merge(poll(this.pollMs), this.reloads)
      .pipe(
        switchMap(() =>
          forkJoin({
            devices: this.api.list(),
            // Groups only feed the filter; a failure must not hide the devices.
            groups: this.api.groups().pipe(catchError(() => of(this.groups()))),
          }).pipe(
            map((data) => ({ ok: true as const, ...data })),
            catchError((error: unknown) => of({ ok: false as const, error })),
          ),
        ),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe((result) => {
        if (result.ok) {
          this.devices.set(result.devices);
          this.groups.set(result.groups);
          this.error.set(null);
        } else {
          // Keep showing the last known devices; the template says so.
          this.error.set(describeApiError(result.error));
        }
        this.loading.set(false);
      });
  }

  protected reload(): void {
    this.loading.set(true);
    this.error.set(null);
    this.reloads.next();
  }

  protected setQuery(event: Event): void {
    this.filter.update((f) => ({ ...f, query: (event.target as HTMLInputElement).value }));
  }

  protected setStatus(event: Event): void {
    const value = (event.target as HTMLSelectElement).value as DeviceFilter['status'];
    this.filter.update((f) => ({ ...f, status: value }));
  }

  protected setTrust(event: Event): void {
    const value = (event.target as HTMLSelectElement).value as DeviceFilter['trust'];
    this.filter.update((f) => ({ ...f, trust: value }));
  }

  protected setType(event: Event): void {
    const value = (event.target as HTMLSelectElement).value as DeviceFilter['type'];
    this.filter.update((f) => ({ ...f, type: value }));
  }

  protected setGroup(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    const group = value === 'all' ? value : Number(value);
    this.filter.update((f) => ({ ...f, group }));
  }

  protected clearFilters(): void {
    this.filter.set(NO_FILTER);
  }

  protected sortBy(key: SortKey): void {
    this.sort.update((s) =>
      s.key === key
        ? { key, direction: s.direction === 'asc' ? 'desc' : 'asc' }
        : { key, direction: key === 'last_seen' ? 'desc' : 'asc' },
    );
  }

  protected ariaSort(key: SortKey): 'ascending' | 'descending' | 'none' {
    const sort = this.sort();
    if (sort.key !== key) return 'none';
    return sort.direction === 'asc' ? 'ascending' : 'descending';
  }

  protected arrow(key: SortKey): string {
    const sort = this.sort();
    if (sort.key !== key) return '';
    return sort.direction === 'asc' ? '▲' : '▼';
  }

  protected subtitle(device: Device): string {
    if (device.vendor) return device.vendor;
    if (device.locally_administered_mac) return 'Private MAC';
    return device.mac_address;
  }

  /** The most recently seen address, plus how many others there are. */
  protected address(device: Device): string {
    if (!device.addresses.length) return '—';
    const sorted = [...device.addresses].sort(
      (a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime(),
    );
    const extra = sorted.length - 1;
    return extra > 0 ? `${sorted[0].ip_address} +${extra}` : sorted[0].ip_address;
  }
}
