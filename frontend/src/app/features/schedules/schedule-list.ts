import { Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed, toObservable } from '@angular/core/rxjs-interop';
import {
  Observable,
  catchError,
  debounceTime,
  distinctUntilChanged,
  map,
  of,
  switchMap,
} from 'rxjs';

import { describeApiError } from '../../core/api-error';
import { Device } from '../../core/device.models';
import { DevicesService } from '../../core/devices.service';
import { Group } from '../../core/group.models';
import { SCAN_PROFILES, SCAN_PROFILE_LABELS, ScanProfile } from '../../core/scan.models';
import {
  CronPreview,
  ScanSchedule,
  ScheduleInput,
  ScheduleTarget,
} from '../../core/schedule.models';
import { SchedulesService } from '../../core/schedules.service';

/** Wait this long after typing before asking the server about a cron expression. */
const PREVIEW_DELAY_MS = 300;

interface FormState {
  name: string;
  cron: string;
  profile: ScanProfile;
  targetKind: ScheduleTarget['kind'];
  /** Device or group id as selected; '' until chosen. */
  targetId: string;
}

const EMPTY_FORM: FormState = {
  name: '',
  cron: '0 3 * * *',
  profile: 'quick',
  targetKind: 'all',
  targetId: '',
};

/**
 * Scheduled port scans: when, how and what to scan. Runs follow the server's
 * time zone; a run missed while the server was down is skipped, and a run
 * waits while the previous one is still going.
 */
@Component({
  selector: 'app-schedule-list',
  template: `
    <section class="page">
      <header class="page-head">
        <h1>Scan schedules</h1>
      </header>

      @if (loading()) {
        <p class="state" role="status">Loading schedules…</p>
      } @else if (loadError()) {
        <div class="state" role="alert">
          <p>Could not load the schedules. {{ loadError() }}</p>
          <button type="button" (click)="load()">Retry</button>
        </div>
      } @else if (!schedules().length) {
        <div class="state">
          <p><strong>No schedules yet.</strong></p>
          <p class="muted">Create one below to scan devices regularly, e.g. every night.</p>
        </div>
      } @else {
        <ul class="schedules">
          @for (s of schedules(); track s.id) {
            <li class="schedule" [class.off]="!s.enabled">
              <div class="top">
                <h2>{{ s.name }}</h2>
                <span class="pill" [class.on]="s.enabled">{{ s.enabled ? 'on' : 'off' }}</span>
              </div>
              <p class="meta">
                <code>{{ s.cron }}</code>
                @if (s.description) {
                  · {{ plain(s.description) }}
                }
                · {{ s.profile }} scan of {{ targetLabel(s) }}
              </p>
              <p class="meta">
                @if (s.next_run_at) {
                  Next: <time [attr.datetime]="s.next_run_at">{{ when(s.next_run_at) }}</time>
                } @else {
                  Not planned while off
                }
                @if (s.last_run_at) {
                  · last: <time [attr.datetime]="s.last_run_at">{{ when(s.last_run_at) }}</time>
                }
              </p>
              <div class="actions">
                <button type="button" class="secondary" [disabled]="busy()" (click)="toggle(s)">
                  {{ s.enabled ? 'Turn off' : 'Turn on' }}
                </button>
                <button type="button" class="secondary" [disabled]="busy()" (click)="edit(s)">
                  Edit
                </button>
                <button type="button" class="secondary" [disabled]="busy()" (click)="remove(s)">
                  Delete
                </button>
              </div>
            </li>
          }
        </ul>
      }
      @if (actionError()) {
        <p class="error" role="alert">{{ actionError() }}</p>
      }

      <form class="card" (submit)="$event.preventDefault(); save()" aria-labelledby="form-title">
        <h2 id="form-title">{{ editing() === null ? 'New schedule' : 'Edit schedule' }}</h2>

        <label for="sched-name">Name</label>
        <input
          id="sched-name"
          maxlength="64"
          autocomplete="off"
          [value]="form().name"
          (input)="set('name', $event)"
        />

        <label for="sched-cron">When (cron: minute hour day month weekday)</label>
        <input
          id="sched-cron"
          autocomplete="off"
          spellcheck="false"
          [value]="form().cron"
          (input)="set('cron', $event)"
        />
        <p class="hint" aria-live="polite">
          @if (preview(); as p) {
            @if (p.ok) {
              {{ plain(p.description) }}. Next: {{ upcomingText(p.upcoming) }}
            } @else {
              <span class="error-text">{{ p.error }}</span>
            }
          } @else {
            Server time zone; at most every 15 minutes.
          }
        </p>

        <label for="sched-profile">Profile</label>
        <select id="sched-profile" (change)="set('profile', $event)">
          @for (p of profiles; track p) {
            <option [value]="p" [selected]="form().profile === p">{{ profileLabels[p] }}</option>
          }
        </select>

        <label for="sched-target">Scan</label>
        <select id="sched-target" (change)="set('targetKind', $event)">
          <option value="all" [selected]="form().targetKind === 'all'">All devices</option>
          <option value="group" [selected]="form().targetKind === 'group'">A group</option>
          <option value="device" [selected]="form().targetKind === 'device'">One device</option>
        </select>
        @if (form().targetKind === 'group') {
          <label for="sched-group">Group</label>
          <select id="sched-group" (change)="set('targetId', $event)">
            <option value="" [selected]="form().targetId === ''">Choose a group</option>
            @for (g of groups(); track g.id) {
              <option [value]="g.id" [selected]="form().targetId === '' + g.id">
                {{ g.name }}
              </option>
            }
          </select>
        } @else if (form().targetKind === 'device') {
          <label for="sched-device">Device</label>
          <select id="sched-device" (change)="set('targetId', $event)">
            <option value="" [selected]="form().targetId === ''">Choose a device</option>
            @for (d of devices(); track d.id) {
              <option [value]="d.id" [selected]="form().targetId === '' + d.id">
                {{ d.display_name }}
              </option>
            }
          </select>
        }

        @if (saveError()) {
          <p class="error" role="alert">{{ saveError() }}</p>
        }
        <div class="form-actions">
          <button type="submit" [disabled]="saving() || !valid()">
            {{ saving() ? 'Saving…' : editing() === null ? 'Create schedule' : 'Save changes' }}
          </button>
          @if (editing() !== null) {
            <button type="button" class="secondary" (click)="cancelEdit()">Cancel</button>
          }
        </div>
      </form>
    </section>
  `,
  styles: `
    .page-head h1 {
      margin: 0 0 1rem;
      font-size: 1.6rem;
    }
    .schedules {
      list-style: none;
      margin: 0 0 1rem;
      padding: 0;
      display: grid;
      gap: 0.8rem;
    }
    .schedule {
      padding: 1rem 1.2rem;
      border: 1px solid var(--border);
      border-radius: 0.8rem;
      background: var(--bg-card);
    }
    .schedule.off {
      opacity: 0.75;
    }
    .top {
      display: flex;
      align-items: center;
      gap: 0.7rem;
    }
    .top h2 {
      margin: 0;
      font-size: 1rem;
      flex: 1;
      overflow-wrap: anywhere;
    }
    .pill.on {
      color: var(--accent);
      border-color: var(--accent);
    }
    .meta {
      margin: 0.35rem 0 0;
      color: var(--muted);
      font-size: 0.875rem;
      overflow-wrap: anywhere;
    }
    .actions,
    .form-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-top: 0.8rem;
    }
    .form-actions button {
      margin: 0;
    }
    .card {
      width: auto;
      max-width: 40rem;
      padding: 1.4rem;
      box-shadow: none;
    }
    .card h2 {
      margin: 0;
      font-size: 1rem;
    }
    select {
      width: 100%;
      padding: 0.7rem 0.6rem;
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      background: var(--bg-input);
      color: inherit;
      font: inherit;
    }
    .error-text {
      color: var(--danger);
    }
  `,
})
export class ScheduleList {
  private readonly api = inject(SchedulesService);
  private readonly devicesApi = inject(DevicesService);

  protected readonly profiles = SCAN_PROFILES;
  protected readonly profileLabels = SCAN_PROFILE_LABELS;

  protected readonly schedules = signal<ScanSchedule[]>([]);
  protected readonly loading = signal(true);
  protected readonly loadError = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly actionError = signal<string | null>(null);

  protected readonly form = signal<FormState>(EMPTY_FORM);
  /** The schedule being edited; null while creating a new one. */
  protected readonly editing = signal<number | null>(null);
  protected readonly saving = signal(false);
  protected readonly saveError = signal<string | null>(null);
  protected readonly preview = signal<
    ({ ok: true } & CronPreview) | { ok: false; error: string } | null
  >(null);

  protected readonly devices = signal<Device[]>([]);
  protected readonly groups = signal<Group[]>([]);

  constructor() {
    this.load();
    this.devicesApi.list().subscribe({ next: (d) => this.devices.set(d), error: () => undefined });
    this.devicesApi.groups().subscribe({ next: (g) => this.groups.set(g), error: () => undefined });

    // Explain the expression while it is typed, asking the server (which
    // owns the rules) once typing pauses.
    toObservable(this.form)
      .pipe(
        map((form) => form.cron.trim()),
        distinctUntilChanged(),
        debounceTime(PREVIEW_DELAY_MS),
        switchMap((cron) =>
          cron
            ? this.api.preview(cron).pipe(
                map((p) => ({ ok: true as const, ...p })),
                catchError((error: unknown) =>
                  of({ ok: false as const, error: describeApiError(error) }),
                ),
              )
            : of(null),
        ),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe((preview) => this.preview.set(preview));
  }

  protected load(): void {
    this.loading.set(true);
    this.loadError.set(null);
    this.api.list().subscribe({
      next: (schedules) => {
        this.schedules.set(schedules);
        this.loading.set(false);
      },
      error: (error: unknown) => {
        this.loadError.set(describeApiError(error));
        this.loading.set(false);
      },
    });
  }

  protected set(key: keyof FormState, event: Event): void {
    const value = (event.target as HTMLInputElement | HTMLSelectElement).value;
    this.form.update((form) => ({
      ...form,
      [key]: value,
      // A different kind of target needs a new choice.
      ...(key === 'targetKind' ? { targetId: '' } : {}),
    }));
  }

  protected valid(): boolean {
    const f = this.form();
    return (
      f.name.trim() !== '' && f.cron.trim() !== '' && (f.targetKind === 'all' || f.targetId !== '')
    );
  }

  private input(): ScheduleInput {
    const f = this.form();
    const target: ScheduleTarget =
      f.targetKind === 'all' ? { kind: 'all' } : { kind: f.targetKind, id: Number(f.targetId) };
    return { name: f.name.trim(), cron: f.cron.trim(), profile: f.profile, target };
  }

  protected save(): void {
    if (this.saving() || !this.valid()) return;
    const id = this.editing();
    this.saving.set(true);
    this.saveError.set(null);
    const request = id === null ? this.api.create(this.input()) : this.api.update(id, this.input());
    request.subscribe({
      next: (saved) => {
        this.saving.set(false);
        this.schedules.update((all) =>
          id === null
            ? [...all, saved].sort((a, b) => a.name.localeCompare(b.name))
            : all.map((s) => (s.id === saved.id ? saved : s)),
        );
        this.cancelEdit();
      },
      error: (error: unknown) => {
        this.saving.set(false);
        this.saveError.set(describeApiError(error));
      },
    });
  }

  protected edit(schedule: ScanSchedule): void {
    this.editing.set(schedule.id);
    this.saveError.set(null);
    const target = schedule.target ?? { kind: 'all' as const };
    this.form.set({
      name: schedule.name,
      cron: schedule.cron,
      profile: schedule.profile,
      targetKind: target.kind,
      targetId: target.kind === 'all' ? '' : String(target.id),
    });
  }

  protected cancelEdit(): void {
    this.editing.set(null);
    this.form.set(EMPTY_FORM);
  }

  protected toggle(schedule: ScanSchedule): void {
    this.run(this.api.update(schedule.id, { enabled: !schedule.enabled }), (saved) =>
      this.schedules.update((all) => all.map((s) => (s.id === saved.id ? saved : s))),
    );
  }

  protected remove(schedule: ScanSchedule): void {
    this.run(this.api.remove(schedule.id), () => {
      this.schedules.update((all) => all.filter((s) => s.id !== schedule.id));
      if (this.editing() === schedule.id) this.cancelEdit();
    });
  }

  private run<T>(request: Observable<T>, done: (result: T) => void): void {
    this.busy.set(true);
    this.actionError.set(null);
    request.subscribe({
      next: (result) => {
        this.busy.set(false);
        done(result);
      },
      error: (error: unknown) => {
        this.busy.set(false);
        this.actionError.set(describeApiError(error));
      },
    });
  }

  protected targetLabel(schedule: ScanSchedule): string {
    const target = schedule.target;
    if (!target || target.kind === 'all') return 'all devices';
    const name = schedule.target_name ?? `a removed ${target.kind}`;
    return target.kind === 'group' ? `the group ${name}` : name;
  }

  /** A description without its final period, to continue the sentence. */
  protected plain(description: string): string {
    return description.replace(/\.+$/, '');
  }

  /** Local date and time, e.g. "12.11.2026, 03:00". */
  protected when(iso: string): string {
    return new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  }

  protected upcomingText(runs: string[]): string {
    return runs.map((run) => this.when(run)).join(', ');
  }
}
