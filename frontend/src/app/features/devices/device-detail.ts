import { Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { forkJoin } from 'rxjs';

import { describeApiError } from '../../core/api-error';
import { DevicesService } from '../../core/devices.service';
import {
  DEVICE_TYPES,
  DEVICE_TYPE_LABELS,
  Device,
  DevicePatch,
  DeviceType,
  Evidence,
  Group,
  TRUST_LEVELS,
  TrustLevel,
} from '../../core/models';
import { timeAgo } from '../../core/time';

/** Tabs that later features will fill in (scans, DNS, CVEs, policy). */
const FUTURE_TABS = ['Scans', 'DNS', 'CVEs', 'Policy'];

@Component({
  selector: 'app-device-detail',
  imports: [FormsModule, RouterLink],
  template: `
    <section class="page">
      <p><a routerLink="/devices">← All devices</a></p>

      @if (loading()) {
        <p class="state" role="status">Loading device…</p>
      } @else if (loadError()) {
        <div class="state" role="alert">
          <p>{{ loadError() }}</p>
          <a routerLink="/devices">Back to the device list</a>
        </div>
      } @else if (device(); as d) {
        <header class="head">
          <h1>{{ d.display_name }}</h1>
          <span class="status" [class.online]="d.is_online">
            <span class="dot" aria-hidden="true"></span>{{ d.is_online ? 'Online' : 'Offline' }}
          </span>
        </header>

        <div class="tabs" role="tablist" aria-label="Device sections">
          <button type="button" role="tab" aria-selected="true" class="tab active">Overview</button>
          @for (tab of futureTabs; track tab) {
            <button type="button" role="tab" class="tab" disabled title="Coming soon">{{ tab }}</button>
          }
        </div>

        <div class="grid">
          <form class="card" (ngSubmit)="save()" aria-labelledby="edit-title">
            <h2 id="edit-title">Details</h2>

            <label for="label">Label</label>
            <input id="label" name="label" maxlength="64" autocomplete="off"
                   [placeholder]="d.name" [ngModel]="form().label" (ngModelChange)="patchForm({ label: $event })" />
            <p class="hint">Shown instead of the discovered name ({{ d.name }}).</p>

            <label for="group">Group</label>
            <select id="group" name="group" [ngModel]="form().group" (ngModelChange)="patchForm({ group: $event })">
              @for (group of groups(); track group.id) {
                <option [ngValue]="group.id">{{ group.name }}</option>
              }
            </select>

            <label for="type">Device type</label>
            <select id="type" name="type" [ngModel]="form().type" (ngModelChange)="patchForm({ type: $event })">
              <option [ngValue]="null">{{ automaticLabel(d) }}</option>
              @for (type of deviceTypes; track type) {
                <option [ngValue]="type">{{ typeLabels[type] }}</option>
              }
            </select>
            <p class="hint">Pick a type to override the automatic guess; "Automatic" goes back to it.</p>

            <label for="trust">Trust level</label>
            <select id="trust" name="trust" [ngModel]="form().trust" (ngModelChange)="patchForm({ trust: $event })">
              @for (level of trustLevels; track level) {
                <option [ngValue]="level">{{ level }}</option>
              }
            </select>

            <label for="notes">Notes</label>
            <textarea id="notes" name="notes" rows="5" maxlength="2000"
                      [ngModel]="form().notes" (ngModelChange)="patchForm({ notes: $event })"></textarea>

            @if (saveError()) {
              <p class="error" role="alert">{{ saveError() }}</p>
            }
            @if (saved()) {
              <p class="ok" role="status">Saved.</p>
            }
            <div class="actions">
              <button type="submit" [disabled]="!dirty() || saving()">{{ saving() ? 'Saving…' : 'Save' }}</button>
              <button type="button" class="secondary" [disabled]="!dirty() || saving()" (click)="reset()">Reset</button>
            </div>
          </form>

          <div class="card">
            <h2>Profile</h2>
            <dl>
              <dt>MAC address</dt>
              <dd>
                <code>{{ d.mac_address }}</code>
                @if (d.locally_administered_mac) {
                  <span class="pill" title="Not assigned by a manufacturer: usually MAC randomization, but also used by virtual interfaces">private MAC</span>
                }
              </dd>
              <dt>Type</dt>
              <dd>
                {{ typeLabels[d.device_type] }}
                <span class="pill">{{ d.type_source === 'manual' ? 'set by you' : d.inferred.confidence + ' % sure' }}</span>
              </dd>
              <dt>Manufacturer</dt>
              <dd>{{ d.vendor ?? (d.locally_administered_mac ? 'Unknown (private MAC)' : 'Unknown') }}</dd>
              <dt>First seen</dt>
              <dd [title]="d.first_seen">{{ ago(d.first_seen) }}</dd>
              <dt>Last seen</dt>
              <dd [title]="d.last_seen">{{ ago(d.last_seen) }}</dd>
            </dl>

            <h2>Why this type?</h2>
            @if (d.inferred.evidence.length) {
              <p class="muted hint">
                The automatic guess is {{ typeLabels[d.inferred.device_type] }}
                @if (d.inferred.device_type !== 'unknown') { ({{ d.inferred.confidence }} % sure) }
                based on:
              </p>
              <ul class="evidence">
                @for (item of d.inferred.evidence; track $index) {
                  <li>
                    <strong>{{ kindLabel(item) }}</strong>: {{ item.detail }}
                    → {{ typeLabels[item.type] }} <span class="muted">(+{{ item.weight }} %)</span>
                  </li>
                }
              </ul>
            } @else {
              <p class="muted">Nothing recognisable yet, so the type stays unknown.</p>
            }

            <h2>Addresses</h2>
            @if (d.addresses.length) {
              <table>
                <thead>
                  <tr><th scope="col">IP address</th><th scope="col">Source</th><th scope="col">Last seen</th></tr>
                </thead>
                <tbody>
                  @for (address of d.addresses; track address.id) {
                    <tr>
                      <td><code>{{ address.ip_address }}</code></td>
                      <td>{{ address.source.toUpperCase() }}</td>
                      <td [title]="address.last_seen">{{ ago(address.last_seen) }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            } @else {
              <p class="muted">No addresses recorded.</p>
            }
          </div>
        </div>
      }
    </section>
  `,
  styles: `
    .head { display: flex; align-items: baseline; gap: 1rem; flex-wrap: wrap; }
    .head h1 { margin: 0; font-size: 1.6rem; overflow-wrap: anywhere; }
    .status { display: inline-flex; align-items: center; gap: 0.4rem; color: var(--muted); }
    .status.online { color: var(--accent); }
    .dot { width: 0.55rem; height: 0.55rem; border-radius: 50%; background: currentColor; }
    .tabs { display: flex; gap: 0.3rem; margin: 1rem 0; border-bottom: 1px solid var(--border); overflow-x: auto; }
    .tab { margin: 0; padding: 0.5rem 0.9rem; border: 0; border-bottom: 2px solid transparent;
           border-radius: 0; background: none; color: var(--muted); font-weight: 600; cursor: pointer; }
    .tab.active { color: var(--text); border-bottom-color: var(--accent); }
    .tab:disabled { opacity: 0.45; cursor: not-allowed; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; align-items: start; }
    .card { width: auto; padding: 1.4rem; border: 1px solid var(--border); border-radius: 0.8rem;
            background: var(--bg-card); box-shadow: none; min-width: 0; }
    .card h2 { margin: 0 0 0.6rem; font-size: 1rem; }
    .card h2:not(:first-child) { margin-top: 1.4rem; }
    select, textarea { width: 100%; padding: 0.7rem 0.8rem; border: 1px solid var(--border); border-radius: 0.5rem;
                       background: var(--bg-input); color: inherit; font: inherit; }
    textarea { resize: vertical; }
    .actions { display: flex; align-items: center; gap: 0.6rem; margin-top: 1.5rem; }
    .actions button { margin: 0; }
    .actions button.secondary { padding: 0.7rem 1.2rem; }
    .ok { margin: 1rem 0 0; color: var(--accent); }
    dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.4rem 1rem; margin: 0; }
    dt { color: var(--muted); }
    .evidence { margin: 0.4rem 0 0; padding-left: 1.2rem; }
    .evidence li { margin: 0.25rem 0; overflow-wrap: anywhere; }
    dd { margin: 0; overflow-wrap: anywhere; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.5rem 0.4rem; text-align: left; border-bottom: 1px solid var(--border); }
    thead th { font-size: 0.8rem; color: var(--muted); }
    .state { padding: 2rem; text-align: center; border: 1px dashed var(--border); border-radius: 0.8rem; }
  `,
})
export class DeviceDetail {
  private readonly api = inject(DevicesService);

  /** The `:id` route parameter (bound through `withComponentInputBinding`). */
  readonly id = input.required<string>();

  protected readonly futureTabs = FUTURE_TABS;
  protected readonly trustLevels = TRUST_LEVELS;
  protected readonly deviceTypes = DEVICE_TYPES;
  protected readonly typeLabels = DEVICE_TYPE_LABELS;

  protected readonly device = signal<Device | null>(null);
  protected readonly groups = signal<Group[]>([]);
  protected readonly loading = signal(true);
  protected readonly loadError = signal<string | null>(null);

  protected readonly form = signal<FormState>({
    label: '',
    group: 0,
    trust: 'unknown',
    type: null,
    notes: '',
  });
  protected readonly saving = signal(false);
  protected readonly saved = signal(false);
  protected readonly saveError = signal<string | null>(null);

  /** What changed compared to the stored device; empty when nothing did. */
  private readonly changes = computed<DevicePatch>(() => {
    const device = this.device();
    return device ? diff(device, this.form()) : {};
  });
  protected readonly dirty = computed(() => Object.keys(this.changes()).length > 0);

  constructor() {
    // Also runs again when the route changes from one device to another.
    effect(() => {
      const id = Number(this.id());
      untracked(() => this.load(id));
    });
  }

  private load(id: number): void {
    this.loading.set(true);
    this.loadError.set(null);
    this.saveError.set(null);
    this.saved.set(false);
    if (!Number.isInteger(id)) {
      this.loadError.set('This is not a valid device.');
      this.loading.set(false);
      return;
    }

    forkJoin({ device: this.api.get(id), groups: this.api.groups() }).subscribe({
      next: ({ device, groups }) => {
        this.groups.set(groups);
        this.show(device);
        this.loading.set(false);
      },
      error: (error: unknown) => {
        this.loadError.set(describeApiError(error));
        this.loading.set(false);
      },
    });
  }

  private show(device: Device): void {
    this.device.set(device);
    this.form.set(toForm(device));
  }

  protected patchForm(change: Partial<FormState>): void {
    this.saved.set(false);
    this.form.update((form) => ({ ...form, ...change }));
  }

  protected reset(): void {
    const device = this.device();
    if (device) this.form.set(toForm(device));
    this.saveError.set(null);
  }

  protected save(): void {
    const device = this.device();
    const patch = this.changes();
    if (!device || this.saving() || Object.keys(patch).length === 0) return;

    this.saving.set(true);
    this.saveError.set(null);
    this.api.update(device.id, patch).subscribe({
      next: (updated) => {
        this.show(updated);
        this.saving.set(false);
        this.saved.set(true);
      },
      error: (error: unknown) => {
        this.saveError.set(describeApiError(error));
        this.saving.set(false);
      },
    });
  }

  /** The first dropdown entry shows what "automatic" currently means. */
  protected automaticLabel(device: Device): string {
    const { device_type, confidence } = device.inferred;
    return device_type === 'unknown'
      ? 'Automatic (unknown)'
      : `Automatic (${DEVICE_TYPE_LABELS[device_type]}, ${confidence} %)`;
  }

  protected kindLabel(item: Evidence): string {
    return KIND_LABELS[item.kind];
  }

  protected ago(iso: string): string {
    return timeAgo(iso);
  }
}

/** How an evidence kind is called in the explanation. */
const KIND_LABELS: Record<Evidence['kind'], string> = {
  vendor: 'Manufacturer',
  private_mac: 'MAC address',
  hostname: 'Hostname',
  port: 'Open port',
  mdns: 'Service announcement',
};

interface FormState {
  label: string;
  group: number;
  trust: TrustLevel;
  /** `null` means automatic: no manual override. */
  type: DeviceType | null;
  notes: string;
}

function toForm(device: Device): FormState {
  return {
    label: device.label ?? '',
    group: device.group_id,
    trust: device.trust_level,
    type: device.type_override,
    notes: device.notes,
  };
}

/** Only what differs from the stored device, in the shape the API takes. */
export function diff(device: Device, form: FormState): DevicePatch {
  const patch: DevicePatch = {};
  if (form.label.trim() !== (device.label ?? '')) patch.label = form.label.trim() || null;
  if (form.notes.trim() !== device.notes) patch.notes = form.notes.trim();
  if (form.group !== device.group_id) patch.group_id = form.group;
  if (form.trust !== device.trust_level) patch.trust_level = form.trust;
  if (form.type !== device.type_override) patch.type_override = form.type;
  return patch;
}
