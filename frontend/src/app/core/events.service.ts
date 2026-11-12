import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, InjectionToken, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { API_BASE } from './api';
import { EventFilter, EventPage, EventTypeInfo } from './event.models';

/** How often the timeline asks for newer events, in ms. 0 turns polling off. */
export const EVENT_POLL_MS = new InjectionToken<number>('EVENT_POLL_MS', {
  providedIn: 'root',
  factory: () => 10_000,
});

/** Where to read from: older than a cursor, newer than one, or the top. */
export type EventPosition = { before: string } | { after: string } | null;

@Injectable({ providedIn: 'root' })
export class EventsService {
  private readonly http = inject(HttpClient);

  list(filter: EventFilter, position: EventPosition = null): Observable<EventPage> {
    let params = new HttpParams();
    for (const key of ['device', 'type', 'severity'] as const) {
      if (filter[key]) params = params.set(key, filter[key]);
    }
    // `datetime-local` has no zone: it is the user's local time.
    if (filter.from) params = params.set('from', new Date(filter.from).toISOString());
    if (filter.to) params = params.set('to', new Date(filter.to).toISOString());
    if (position && 'before' in position) params = params.set('before', position.before);
    if (position && 'after' in position) params = params.set('after', position.after);
    return this.http.get<EventPage>(`${API_BASE}/events`, { params });
  }

  types(): Observable<EventTypeInfo[]> {
    return this.http.get<EventTypeInfo[]>(`${API_BASE}/events/types`);
  }
}
