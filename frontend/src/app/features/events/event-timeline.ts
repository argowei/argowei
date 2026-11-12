import { Component, DestroyRef, effect, inject, input, signal, untracked } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { EMPTY, Observable, catchError, switchMap, tap } from 'rxjs';

import { describeApiError } from '../../core/api-error';
import { Device } from '../../core/device.models';
import { DevicesService } from '../../core/devices.service';
import { describeEvent, eventTypeLabel } from '../../core/event-text';
import {
  EventFilter,
  EventTypeInfo,
  NO_EVENT_FILTER,
  SEVERITIES,
  TimelineEvent,
} from '../../core/event.models';
import { EVENT_POLL_MS, EventsService } from '../../core/events.service';
import { poll } from '../../core/poll';
import { TimeAgoPipe } from '../../shared/time-ago.pipe';

/**
 * Everything that happened on the network, newest first: discovery,
 * presence and naming today, scans and policy changes later. Filters narrow
 * it; new events are added at the top while the page is open, without
 * collapsing older pages the user has loaded.
 */
@Component({
  selector: 'app-event-timeline',
  imports: [RouterLink, TimeAgoPipe],
  template: `
    <section class="page">
      <header class="page-head">
        <h1>Timeline</h1>
      </header>

      <form class="filters" role="search" (submit)="$event.preventDefault()">
        <div class="field">
          <label for="ev-device">Device</label>
          <select id="ev-device" (change)="set('device', $event)">
            <option value="" [selected]="filter().device === ''">All devices</option>
            @for (d of devices(); track d.id) {
              <option [value]="d.id" [selected]="filter().device === '' + d.id">
                {{ d.display_name }}
              </option>
            }
          </select>
        </div>
        <div class="field">
          <label for="ev-type">Type</label>
          <select id="ev-type" (change)="set('type', $event)">
            <option value="" [selected]="filter().type === ''">All types</option>
            @for (t of types(); track t.type) {
              <option [value]="t.type" [selected]="filter().type === t.type">
                {{ typeLabel(t.type) }}
              </option>
            }
          </select>
        </div>
        <div class="field">
          <label for="ev-severity">Severity</label>
          <select id="ev-severity" (change)="set('severity', $event)">
            <option value="" [selected]="filter().severity === ''">Any</option>
            @for (s of severities; track s) {
              <option [value]="s" [selected]="filter().severity === s">{{ s }}</option>
            }
          </select>
        </div>
        <div class="field">
          <label for="ev-from">From</label>
          <input
            id="ev-from"
            type="datetime-local"
            [value]="filter().from"
            (change)="set('from', $event)"
          />
        </div>
        <div class="field">
          <label for="ev-to">To</label>
          <input
            id="ev-to"
            type="datetime-local"
            [value]="filter().to"
            (change)="set('to', $event)"
          />
        </div>
      </form>

      @if (loading()) {
        <p class="state" role="status">Loading events…</p>
      } @else if (error() && !events().length) {
        <div class="state" role="alert">
          <p>Could not load the timeline. {{ error() }}</p>
          <button type="button" (click)="load()">Retry</button>
        </div>
      } @else if (!events().length) {
        <div class="state">
          @if (filtered()) {
            <p>No event matches these filters.</p>
            <button type="button" class="secondary" (click)="clearFilters()">Clear filters</button>
          } @else {
            <p><strong>Nothing has happened yet.</strong></p>
            <p class="muted">Events appear here once discovery has scanned the network.</p>
          }
        </div>
      } @else {
        @if (error()) {
          <p class="banner warn" role="alert">
            Could not refresh: {{ error() }} Showing the last known events.
          </p>
        }
        @if (gap()) {
          <p class="banner info" role="status">
            More new events arrived than fit on the page.
            <button type="button" class="secondary" (click)="load()">Show newest</button>
          </p>
        }
        <ol class="events" aria-label="Events, newest first">
          @for (event of events(); track event.id) {
            <li class="event">
              <time [attr.datetime]="event.occurred_at" [title]="event.occurred_at">{{
                event.occurred_at | timeAgo
              }}</time>
              <span class="pill" [class]="'sev-' + event.severity">{{
                typeLabel(event.type)
              }}</span>
              <span class="what">
                @if (event.device; as device) {
                  <a [routerLink]="['/devices', device.id]">{{ device.display_name }}</a>:
                }
                {{ describe(event) }}
              </span>
            </li>
          }
        </ol>
        @if (nextBefore() !== null) {
          <button
            type="button"
            class="secondary more"
            [disabled]="loadingMore()"
            (click)="loadMore()"
          >
            {{ loadingMore() ? 'Loading…' : 'Load older' }}
          </button>
        }
      }
    </section>
  `,
  styles: `
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
      min-width: 9rem;
      flex: 1 1 9rem;
    }
    .field label {
      margin: 0;
    }
    select,
    .field input {
      padding: 0.6rem;
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      background: var(--bg-input);
      color: inherit;
      font: inherit;
    }
    .events {
      list-style: none;
      margin: 0;
      padding: 0;
      border: 1px solid var(--border);
      border-radius: 0.8rem;
      background: var(--bg-card);
    }
    .event {
      display: grid;
      grid-template-columns: 6.5rem 7rem 1fr;
      gap: 0.8rem;
      align-items: baseline;
      padding: 0.7rem 0.9rem;
      border-bottom: 1px solid var(--border);
    }
    .event:last-child {
      border-bottom: 0;
    }
    time {
      color: var(--muted);
      font-size: 0.85rem;
      white-space: nowrap;
    }
    .pill {
      justify-self: start;
    }
    .pill.sev-warning {
      color: var(--warn);
      border-color: var(--warn);
    }
    .pill.sev-critical {
      color: var(--danger);
      border-color: var(--danger);
    }
    .what {
      overflow-wrap: anywhere;
    }
    .banner button {
      margin-left: 0.5rem;
    }
    .more {
      margin-top: 1rem;
    }
    @media (max-width: 640px) {
      .event {
        grid-template-columns: auto 1fr;
      }
      .what {
        grid-column: 1 / -1;
      }
    }
  `,
})
export class EventTimeline {
  private readonly api = inject(EventsService);
  private readonly devicesApi = inject(DevicesService);
  private readonly pollMs = inject(EVENT_POLL_MS);

  /** `?device=<id>` from the URL, e.g. the link on a device page. */
  readonly device = input<string | undefined>();

  protected readonly severities = SEVERITIES;
  protected readonly filter = signal<EventFilter>(NO_EVENT_FILTER);
  protected readonly events = signal<TimelineEvent[]>([]);
  protected readonly nextBefore = signal<string | null>(null);
  protected readonly loading = signal(true);
  protected readonly loadingMore = signal(false);
  protected readonly error = signal<string | null>(null);
  /** More news arrived than one poll returns: offer a reload instead. */
  protected readonly gap = signal(false);
  protected readonly devices = signal<Device[]>([]);
  protected readonly types = signal<EventTypeInfo[]>([]);

  constructor() {
    // The filter options are a convenience: without them the list still works.
    this.devicesApi.list().subscribe({ next: (d) => this.devices.set(d), error: () => undefined });
    this.api.types().subscribe({ next: (t) => this.types.set(t), error: () => undefined });

    effect(() => {
      const device = this.device() ?? '';
      untracked(() => {
        this.filter.set({ ...NO_EVENT_FILTER, device });
        this.load();
      });
    });

    poll(this.pollMs, { immediate: false })
      .pipe(
        switchMap(() => this.newer()),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe();
  }

  protected filtered(): boolean {
    return Object.values(this.filter()).some((value) => value !== '');
  }

  protected set(key: keyof EventFilter, event: Event): void {
    const value = (event.target as HTMLInputElement | HTMLSelectElement).value;
    this.filter.update((f) => ({ ...f, [key]: value }));
    this.load();
  }

  protected clearFilters(): void {
    this.filter.set(NO_EVENT_FILTER);
    this.load();
  }

  /** The first page for the current filter, replacing what is shown. */
  protected load(): void {
    const filter = this.filter();
    this.loading.set(true);
    this.error.set(null);
    this.gap.set(false);
    this.api.list(filter).subscribe({
      next: (page) => {
        if (filter !== this.filter()) return; // a newer filter is loading
        this.events.set(page.items);
        this.nextBefore.set(page.next_before);
        this.loading.set(false);
      },
      error: (error: unknown) => {
        if (filter !== this.filter()) return;
        this.error.set(describeApiError(error));
        this.loading.set(false);
      },
    });
  }

  protected loadMore(): void {
    const before = this.nextBefore();
    if (before === null || this.loadingMore()) return;
    const filter = this.filter();
    this.loadingMore.set(true);
    this.api.list(filter, { before }).subscribe({
      next: (page) => {
        if (filter === this.filter()) {
          this.events.update((current) => [...current, ...page.items]);
          this.nextBefore.set(page.next_before);
        }
        this.loadingMore.set(false);
      },
      error: (error: unknown) => {
        this.error.set(describeApiError(error));
        this.loadingMore.set(false);
      },
    });
  }

  /**
   * Adds events newer than the top one; with nothing shown yet, quietly
   * fetches the first page instead. Skipped while a load is under way.
   */
  private newer(): Observable<unknown> {
    if (this.loading() || this.loadingMore() || this.gap()) return EMPTY;
    const filter = this.filter();
    const top = this.events()[0]?.cursor;
    return this.api.list(filter, top ? { after: top } : null).pipe(
      tap((page) => {
        if (filter !== this.filter()) return;
        this.error.set(null);
        if (!top) {
          this.events.set(page.items);
          this.nextBefore.set(page.next_before);
        } else if (page.truncated) {
          this.gap.set(true);
        } else if (page.items.length) {
          this.events.update((current) => [...page.items, ...current]);
        }
      }),
      catchError((error: unknown) => {
        this.error.set(describeApiError(error));
        return EMPTY;
      }),
    );
  }

  protected typeLabel(type: string): string {
    return eventTypeLabel(type);
  }

  protected describe(event: TimelineEvent): string {
    return describeEvent(event);
  }
}
