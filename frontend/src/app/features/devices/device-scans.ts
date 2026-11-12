import {
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  input,
  signal,
  untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { EMPTY, Observable, catchError, filter, forkJoin, map, of, switchMap, tap } from 'rxjs';

import { describeApiError } from '../../core/api-error';
import { poll } from '../../core/poll';
import {
  SCAN_PROFILES,
  SCAN_PROFILE_LABELS,
  SCAN_STATUS_LABELS,
  Scan,
  ScanComparison,
  ScanProfile,
  ScanWithPorts,
  isActive,
} from '../../core/scan.models';
import { SCAN_POLL_MS, ScansService } from '../../core/scans.service';
import { TimeAgoPipe } from '../../shared/time-ago.pipe';
import { ScanDiff } from './scan-diff';
import { ScanPorts } from './scan-ports';

/**
 * The Scans tab of a device: start an nmap scan with a fixed profile, follow
 * it while it runs, cancel it, and read the ports of any past scan. Polls
 * only while a scan is queued or running.
 */
@Component({
  selector: 'app-device-scans',
  imports: [ScanPorts, ScanDiff, TimeAgoPipe],
  template: `
    <div class="card">
      <h2>Start a scan</h2>
      <form class="start" (submit)="$event.preventDefault(); start()">
        <div class="field">
          <label for="scan-profile">Profile</label>
          <select id="scan-profile" (change)="pick($event)">
            @for (p of profiles; track p) {
              <option [value]="p" [selected]="profile() === p">{{ profileLabels[p] }}</option>
            }
          </select>
        </div>
        <button type="submit" [disabled]="starting() || active() !== null">
          {{ starting() ? 'Starting…' : 'Start scan' }}
        </button>
      </form>
      <p class="hint">
        Scans only reach this device's address on the local network and run without special
        privileges (TCP connect scans, no OS detection). Firewalls can hide ports, so a missing port
        is not proof that nothing listens.
      </p>
      @if (startError()) {
        <p class="error" role="alert">{{ startError() }}</p>
      }
    </div>

    <div class="card">
      <h2>History</h2>
      @if (loading()) {
        <p class="state" role="status">Loading scans…</p>
      } @else if (loadError() && !scans().length) {
        <div class="state" role="alert">
          <p>Could not load the scans. {{ loadError() }}</p>
          <button type="button" (click)="reload()">Retry</button>
        </div>
      } @else if (!scans().length) {
        <p class="muted">This device has not been scanned yet.</p>
      } @else {
        <table class="compact history">
          <thead>
            <tr>
              <th scope="col">Started</th>
              <th scope="col">Profile</th>
              <th scope="col">Status</th>
              <th scope="col" class="col-open">Open</th>
              <th scope="col"><span class="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            @for (scan of scans(); track scan.id) {
              <tr [class.selected]="selectedId() === scan.id">
                <td [title]="scan.created_at">{{ scan.created_at | timeAgo }}</td>
                <td>{{ scan.profile }}</td>
                <td>
                  <span class="pill" [class]="'st-' + scan.status">{{
                    statusLabels[scan.status]
                  }}</span>
                </td>
                <td class="col-open">{{ scan.status === 'completed' ? scan.open_ports : '—' }}</td>
                <td class="actions">
                  <button
                    type="button"
                    class="secondary"
                    [attr.aria-pressed]="selectedId() === scan.id"
                    (click)="select(scan.id)"
                  >
                    Show
                  </button>
                  @if (isActive(scan)) {
                    <button
                      type="button"
                      class="secondary"
                      [disabled]="cancelling()"
                      (click)="cancel(scan)"
                    >
                      Cancel
                    </button>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      }
    </div>

    @if (selected(); as scan) {
      <div class="card result" aria-live="polite">
        <h2>Scan of {{ scan.target_ip }} ({{ scan.profile }})</h2>
        <p class="muted">
          Requested by {{ scan.requested_by }}
          @if (scan.finished_at) {
            · finished <span [title]="scan.finished_at">{{ scan.finished_at | timeAgo }}</span>
          }
          @if (scan.nmap_version) {
            · nmap {{ scan.nmap_version }}
          }
        </p>
        @switch (scan.status) {
          @case ('completed') {
            <app-scan-ports [ports]="scan.ports" />
            @if (comparable().length) {
              <h3>Changes</h3>
              <label for="scan-against">Compare with</label>
              <select id="scan-against" (change)="compareWith($event)">
                @for (other of comparable(); track other.id) {
                  <option [value]="other.id" [selected]="against() === other.id">
                    {{ other.profile }} scan, {{ other.created_at | timeAgo }}
                  </option>
                }
              </select>
              @if (comparison(); as c) {
                <app-scan-diff [comparison]="c" />
              } @else if (compareError()) {
                <p class="error" role="alert">{{ compareError() }}</p>
              } @else {
                <p class="muted" role="status">Comparing…</p>
              }
            }
          }
          @case ('queued') {
            <p role="status">Waiting for a free slot…</p>
          }
          @case ('running') {
            <p role="status">Scanning… results appear here when it finishes.</p>
          }
          @default {
            <p class="error">{{ statusLabels[scan.status] }}: {{ scan.error }}</p>
          }
        }
      </div>
    }
  `,
  styles: `
    :host {
      display: grid;
      gap: 1rem;
    }
    .card {
      padding: 1.4rem;
      border: 1px solid var(--border);
      border-radius: 0.8rem;
      background: var(--bg-card);
      min-width: 0;
    }
    .card h3 {
      margin: 1.2rem 0 0.4rem;
      font-size: 0.95rem;
    }
    .card h2 {
      margin: 0 0 0.6rem;
      font-size: 1rem;
      overflow-wrap: anywhere;
    }
    .start {
      display: flex;
      flex-wrap: wrap;
      gap: 0.8rem;
      align-items: end;
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 0.3rem;
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
    .start button {
      margin: 0;
    }
    .actions {
      display: flex;
      gap: 0.4rem;
      justify-content: end;
    }
    tr.selected td {
      background: var(--bg-input);
    }
    .pill.st-completed {
      color: var(--accent);
      border-color: var(--accent);
    }
    .pill.st-running,
    .pill.st-queued {
      color: var(--warn);
      border-color: var(--warn);
    }
    .pill.st-failed,
    .pill.st-timed_out {
      color: var(--danger);
      border-color: var(--danger);
    }
    .actions button {
      padding: 0.3rem 0.6rem;
    }
    @media (max-width: 480px) {
      .col-open {
        display: none;
      }
      .card {
        padding: 1rem;
      }
    }
  `,
})
export class DeviceScans {
  private readonly api = inject(ScansService);
  private readonly pollMs = inject(SCAN_POLL_MS);

  readonly deviceId = input.required<number>();

  protected readonly profiles = SCAN_PROFILES;
  protected readonly profileLabels = SCAN_PROFILE_LABELS;
  protected readonly statusLabels = SCAN_STATUS_LABELS;
  protected readonly isActive = isActive;

  protected readonly profile = signal<ScanProfile>('quick');
  protected readonly scans = signal<Scan[]>([]);
  protected readonly loading = signal(true);
  protected readonly loadError = signal<string | null>(null);
  protected readonly starting = signal(false);
  protected readonly startError = signal<string | null>(null);
  protected readonly cancelling = signal(false);
  protected readonly selectedId = signal<number | null>(null);
  protected readonly selected = signal<ScanWithPorts | null>(null);

  /** The scan the selected one is compared with; null until chosen. */
  protected readonly against = signal<number | null>(null);
  protected readonly comparison = signal<ScanComparison | null>(null);
  protected readonly compareError = signal<string | null>(null);

  /** Other completed scans the selected one can be compared with, newest first. */
  protected readonly comparable = computed(() => {
    const id = this.selectedId();
    return this.scans().filter((s) => s.id !== id && s.status === 'completed');
  });

  /** The scan in progress, if any; a device has at most one. */
  protected readonly active = computed(() => this.scans().find(isActive) ?? null);

  constructor() {
    effect(() => {
      const id = this.deviceId();
      untracked(() => {
        this.selectedId.set(null);
        this.selected.set(null);
        this.reload(id);
      });
    });

    // Follow scans in progress; quiet otherwise.
    poll(this.pollMs, { immediate: false })
      .pipe(
        filter(
          () => this.active() !== null || isActive(this.selected() ?? { status: 'completed' }),
        ),
        switchMap(() => this.refresh()),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe();
  }

  protected pick(event: Event): void {
    this.profile.set((event.target as HTMLSelectElement).value as ScanProfile);
  }

  protected reload(deviceId = this.deviceId()): void {
    this.loading.set(true);
    this.loadError.set(null);
    this.api.history(deviceId).subscribe({
      next: (scans) => {
        if (deviceId !== this.deviceId()) return;
        this.scans.set(scans);
        this.loading.set(false);
        if (this.selectedId() === null && scans.length) this.select(scans[0].id);
      },
      error: (error: unknown) => {
        this.loadError.set(describeApiError(error));
        this.loading.set(false);
      },
    });
  }

  protected start(): void {
    if (this.starting() || this.active()) return;
    const deviceId = this.deviceId();
    this.starting.set(true);
    this.startError.set(null);
    this.api.start(deviceId, this.profile()).subscribe({
      next: (scan) => {
        this.starting.set(false);
        this.scans.update((scans) => [scan, ...scans]);
        this.select(scan.id);
      },
      error: (error: unknown) => {
        this.starting.set(false);
        this.startError.set(describeApiError(error));
      },
    });
  }

  protected cancel(scan: Scan): void {
    this.cancelling.set(true);
    this.api.cancel(scan.id).subscribe({
      next: (updated) => {
        this.cancelling.set(false);
        this.replace(updated);
        if (this.selectedId() === updated.id) this.select(updated.id);
      },
      error: (error: unknown) => {
        this.cancelling.set(false);
        this.startError.set(describeApiError(error));
        // Usually the scan finished meanwhile: show its real state at once.
        this.reload();
        if (this.selectedId() === scan.id) this.select(scan.id);
      },
    });
  }

  protected select(id: number): void {
    const changed = this.selectedId() !== id;
    this.selectedId.set(id);
    if (changed) {
      this.against.set(null);
      this.comparison.set(null);
      this.compareError.set(null);
    }
    this.api.get(id).subscribe({
      next: (scan) => {
        if (this.selectedId() === id) this.show(scan, changed);
      },
      error: (error: unknown) => this.loadError.set(describeApiError(error)),
    });
  }

  /**
   * Shows the selected scan. Once it is completed, newly selected or just
   * finished, it is compared with the scan before it by default.
   */
  private show(scan: ScanWithPorts, newlySelected: boolean): void {
    const finishedNow = scan.status === 'completed' && this.selected()?.status !== 'completed';
    this.selected.set(scan);
    if (scan.status === 'completed' && (newlySelected || finishedNow)) {
      const previous = this.comparable().find((s) => s.id < scan.id) ?? this.comparable()[0];
      if (previous) this.compare(previous.id);
    }
  }

  protected compareWith(event: Event): void {
    this.compare(Number((event.target as HTMLSelectElement).value));
  }

  private compare(against: number): void {
    const id = this.selectedId();
    if (id === null) return;
    this.against.set(against);
    this.comparison.set(null);
    this.compareError.set(null);
    this.api.diff(id, against).subscribe({
      next: (comparison) => {
        if (this.selectedId() === id && this.against() === against) this.comparison.set(comparison);
      },
      error: (error: unknown) => this.compareError.set(describeApiError(error)),
    });
  }

  /** History and the selected scan, in the background. */
  private refresh(): Observable<unknown> {
    const deviceId = this.deviceId();
    const id = this.selectedId();
    return forkJoin({
      scans: this.api.history(deviceId),
      selected: id === null ? of(null) : this.api.get(id),
    }).pipe(
      tap(({ scans, selected }) => {
        if (deviceId !== this.deviceId()) return;
        this.scans.set(scans);
        if (selected && this.selectedId() === selected.id) this.show(selected, false);
        this.loadError.set(null);
      }),
      map(() => undefined),
      catchError((error: unknown) => {
        this.loadError.set(describeApiError(error));
        return EMPTY;
      }),
    );
  }

  private replace(updated: Scan): void {
    this.scans.update((scans) => scans.map((s) => (s.id === updated.id ? updated : s)));
  }
}
