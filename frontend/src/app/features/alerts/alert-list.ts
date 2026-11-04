import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { EMPTY, Observable, catchError, merge, switchMap, tap } from 'rxjs';

import { describeApiError } from '../../core/api-error';
import { ALERT_POLL_MS, AlertsService } from '../../core/alerts.service';
import { Alert, AlertView, SuggestedAction } from '../../core/alerts.models';
import { DevicesService } from '../../core/devices.service';
import { TrustLevel } from '../../core/device.models';
import { poll } from '../../core/poll';
import { TimeAgoPipe } from '../../shared/time-ago.pipe';

/** Actions that only classify the device; the rest need enforcement. */
const TRUST_FOR_ACTION: Partial<Record<SuggestedAction['action'], TrustLevel>> = {
  trust: 'trusted',
  restrict: 'restricted',
};

/**
 * Alerts, active or resolved, with what can be done about each: acknowledge,
 * resolve, or classify the device (trust, restrict) and resolve in one go.
 */
@Component({
  selector: 'app-alert-list',
  imports: [RouterLink, TimeAgoPipe],
  template: `
    <section class="page">
      <header class="page-head">
        <h1>Alerts</h1>
        <div class="views" role="group" aria-label="Which alerts to show">
          <button
            type="button"
            class="view"
            [attr.aria-pressed]="view() === 'active'"
            (click)="show('active')"
          >
            Active
            @if (activeCount() > 0) {
              <span class="count">{{ activeCount() }}</span>
            }
          </button>
          <button
            type="button"
            class="view"
            [attr.aria-pressed]="view() === 'resolved'"
            (click)="show('resolved')"
          >
            Resolved
          </button>
        </div>
      </header>

      @if (baseline(); as b) {
        @if (b.state === 'pending') {
          <p class="banner info" role="status">
            <strong>Baseline pending.</strong> No scan has finished yet. Devices found in the first
            scan are taken as your baseline and do not raise alerts.
          </p>
        } @else if (b.state === 'learning') {
          <p class="banner info" role="status">
            <strong>Learning your network</strong> until {{ endsAt(b.ends_at) }}. New devices are
            added silently and do not raise alerts until then.
          </p>
        }
      }

      @if (loading()) {
        <p class="state" role="status">Loading alerts…</p>
      } @else if (error() && !alerts().length) {
        <div class="state" role="alert">
          <p>Could not load alerts. {{ error() }}</p>
          <button type="button" (click)="reload()">Retry</button>
        </div>
      } @else if (!alerts().length) {
        <div class="state">
          @if (view() === 'active') {
            <p><strong>No active alerts.</strong></p>
            <p class="muted">
              You will see an alert here when a device appears that Argowei has not seen before.
            </p>
          } @else {
            <p>No resolved alerts yet.</p>
          }
        </div>
      } @else {
        @if (error()) {
          <p class="banner warn" role="alert">
            Could not refresh: {{ error() }} Showing the last known alerts.
          </p>
        }
        <ul class="alerts">
          @for (alert of alerts(); track alert.id) {
            <li class="alert" [class.resolved]="alert.status === 'resolved'">
              <div class="top">
                <span class="pill" [class]="'sev-' + alert.severity">{{ alert.severity }}</span>
                <h2>
                  {{ title(alert) }}
                  @if (alert.device; as device) {
                    : <a [routerLink]="['/devices', device.id]">{{ device.display_name }}</a>
                  }
                </h2>
                <span class="pill status" [class]="'st-' + alert.status">{{ alert.status }}</span>
              </div>

              <p class="meta">
                {{ details(alert) }} ·
                <span [title]="alert.created_at">{{ alert.created_at | timeAgo }}</span>
                @if (alert.status === 'acknowledged' && alert.acknowledged_by) {
                  · acknowledged by {{ alert.acknowledged_by }}
                }
                @if (alert.status === 'resolved' && alert.resolved_by) {
                  · resolved by {{ alert.resolved_by }}
                }
              </p>

              @if (alert.status !== 'resolved') {
                <div class="actions">
                  @for (action of actions(alert); track action.action) {
                    <button
                      type="button"
                      class="secondary"
                      [disabled]="!action.available || busy(alert.id)"
                      [title]="action.available ? (action.effect ?? '') : (action.reason ?? '')"
                      (click)="apply(alert, action)"
                    >
                      {{ action.label }}
                    </button>
                  }
                  <span class="spacer"></span>
                  @if (alert.status === 'open') {
                    <button
                      type="button"
                      class="secondary"
                      [disabled]="busy(alert.id)"
                      (click)="acknowledge(alert)"
                    >
                      Acknowledge
                    </button>
                  }
                  <button
                    type="button"
                    class="secondary"
                    [disabled]="busy(alert.id)"
                    (click)="resolve(alert)"
                  >
                    Resolve
                  </button>
                </div>
                @if (failure(alert.id); as message) {
                  <p class="error" role="alert">{{ message }}</p>
                }
              }
            </li>
          }
        </ul>
        @if (nextBefore() !== null) {
          <button
            type="button"
            class="secondary more"
            [disabled]="loadingMore()"
            (click)="loadMore()"
          >
            {{ loadingMore() ? 'Loading…' : 'Load more' }}
          </button>
        }
      }
    </section>
  `,
  styles: `
    .page-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .page-head h1 {
      margin: 0;
      font-size: 1.6rem;
    }
    .views {
      display: flex;
      gap: 0.4rem;
    }
    .view {
      margin: 0;
      padding: 0.4rem 0.9rem;
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      background: transparent;
      color: var(--muted);
      font-weight: 600;
      cursor: pointer;
    }
    .view[aria-pressed='true'] {
      color: var(--text);
      border-color: var(--accent);
    }
    .count {
      margin-left: 0.4rem;
      padding: 0 0.45rem;
      border-radius: 1rem;
      background: var(--warn);
      color: var(--bg);
      font-size: 0.75rem;
    }
    .state {
      margin-top: 1rem;
    }
    .alerts {
      list-style: none;
      margin: 1rem 0 0;
      padding: 0;
      display: grid;
      gap: 0.8rem;
    }
    .alert {
      padding: 1rem 1.2rem;
      border: 1px solid var(--border);
      border-radius: 0.8rem;
      background: var(--bg-card);
    }
    .alert.resolved {
      opacity: 0.7;
    }
    .top {
      display: flex;
      align-items: center;
      gap: 0.7rem;
      flex-wrap: wrap;
    }
    .top h2 {
      margin: 0;
      font-size: 1rem;
      flex: 1 1 12rem;
      overflow-wrap: anywhere;
    }
    .meta {
      margin: 0.4rem 0 0.8rem;
      color: var(--muted);
      font-size: 0.875rem;
      overflow-wrap: anywhere;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
    }
    .actions button {
      margin: 0;
      padding: 0.4rem 0.8rem;
    }
    .actions button:disabled {
      opacity: 0.45;
      cursor: not-allowed;
    }
    .spacer {
      flex: 1;
    }
    .pill.sev-warning,
    .pill.st-open {
      color: var(--warn);
      border-color: var(--warn);
    }
    .pill.sev-critical {
      color: var(--danger);
      border-color: var(--danger);
    }
    .pill.st-acknowledged {
      color: var(--accent);
      border-color: var(--accent);
    }
    .more {
      margin-top: 1rem;
    }
  `,
})
export class AlertList {
  private readonly api = inject(AlertsService);
  private readonly devices = inject(DevicesService);
  private readonly pollMs = inject(ALERT_POLL_MS);

  protected readonly view = signal<AlertView>('active');
  protected readonly alerts = signal<Alert[]>([]);
  protected readonly nextBefore = signal<number | null>(null);
  protected readonly loading = signal(true);
  protected readonly loadingMore = signal(false);
  protected readonly error = signal<string | null>(null);
  private readonly pagesLoaded = signal(1);
  private readonly working = signal<ReadonlySet<number>>(new Set());
  private readonly failures = signal<Readonly<Record<number, string>>>({});

  protected readonly baseline = computed(() => this.api.status()?.baseline ?? null);
  protected readonly activeCount = computed(() => {
    const status = this.api.status();
    return status ? status.open + status.acknowledged : 0;
  });

  constructor() {
    this.load();
    this.api.loadStatus().subscribe({ error: () => undefined });

    // The first page was just loaded; refresh it in the background from the
    // next interval on.
    poll(this.pollMs, { immediate: false })
      .pipe(
        switchMap(() => merge(this.refresh(), this.api.loadStatus().pipe(catchError(() => EMPTY)))),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe();
  }

  protected show(view: AlertView): void {
    if (this.view() === view) return;
    this.view.set(view);
    this.alerts.set([]);
    this.nextBefore.set(null);
    this.load();
  }

  protected reload(): void {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.pagesLoaded.set(1);
    const view = this.view();
    this.api.list(view).subscribe({
      next: (page) => {
        if (view !== this.view()) return;
        this.alerts.set(page.items);
        this.nextBefore.set(page.next_before);
        this.loading.set(false);
      },
      error: (error: unknown) => {
        this.error.set(describeApiError(error));
        this.loading.set(false);
      },
    });
  }

  /**
   * Refreshes the first page in the background. Skipped while a load is under
   * way or older pages are on screen, so a poll never collapses what the user
   * is reading.
   */
  private refresh(): Observable<unknown> {
    if (this.loading() || this.loadingMore() || this.pagesLoaded() > 1) return EMPTY;

    const view = this.view();
    return this.api.list(view).pipe(
      tap((page) => {
        if (view !== this.view()) return;
        this.alerts.set(page.items);
        this.nextBefore.set(page.next_before);
        this.error.set(null);
      }),
      catchError((error: unknown) => {
        this.error.set(describeApiError(error));
        return EMPTY;
      }),
    );
  }

  protected loadMore(): void {
    const before = this.nextBefore();
    if (before === null || this.loadingMore()) return;
    this.loadingMore.set(true);
    this.api.list(this.view(), before).subscribe({
      next: (page) => {
        this.alerts.update((current) => [...current, ...page.items]);
        this.nextBefore.set(page.next_before);
        this.pagesLoaded.update((n) => n + 1);
        this.loadingMore.set(false);
      },
      error: (error: unknown) => {
        this.error.set(describeApiError(error));
        this.loadingMore.set(false);
      },
    });
  }

  protected busy(id: number): boolean {
    return this.working().has(id);
  }

  protected failure(id: number): string | null {
    return this.failures()[id] ?? null;
  }

  protected actions(alert: Alert): SuggestedAction[] {
    return alert.payload.suggested_actions ?? [];
  }

  protected acknowledge(alert: Alert): void {
    this.run(alert, this.api.acknowledge(alert.id));
  }

  protected resolve(alert: Alert): void {
    this.run(alert, this.api.resolve(alert.id));
  }

  /** Trust and Restrict classify the device, then close the alert. */
  protected apply(alert: Alert, action: SuggestedAction): void {
    const trust = TRUST_FOR_ACTION[action.action];
    if (!trust || !alert.device || !action.available) return;
    this.run(
      alert,
      this.devices
        .update(alert.device.id, { trust_level: trust })
        .pipe(switchMap(() => this.api.resolve(alert.id))),
    );
  }

  private run(alert: Alert, request: Observable<Alert>): void {
    this.working.update((set) => new Set(set).add(alert.id));
    this.failures.update((all) =>
      Object.fromEntries(Object.entries(all).filter(([id]) => Number(id) !== alert.id)),
    );
    request.subscribe({
      next: () => {
        this.finish(alert.id);
        this.load();
        this.api.loadStatus().subscribe({ error: () => undefined });
      },
      error: (error: unknown) => {
        this.finish(alert.id);
        this.failures.update((all) => ({ ...all, [alert.id]: describeApiError(error) }));
      },
    });
  }

  private finish(id: number): void {
    this.working.update((set) => {
      const next = new Set(set);
      next.delete(id);
      return next;
    });
  }

  protected title(alert: Alert): string {
    return alert.type === 'device.new' ? 'New device' : alert.type;
  }

  protected details(alert: Alert): string {
    const { payload, device } = alert;
    const parts = [
      device?.vendor ?? payload.vendor ?? 'Unknown manufacturer',
      device?.mac_address ?? payload.mac,
      payload.ip ? `${payload.ip} on ${payload.interface ?? 'the network'}` : undefined,
    ];
    return parts.filter(Boolean).join(' · ');
  }

  protected endsAt(iso: string | null): string {
    return iso ? new Date(iso).toLocaleString() : 'later';
  }
}
