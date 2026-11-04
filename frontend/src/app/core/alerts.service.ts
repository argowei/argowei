import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, InjectionToken, inject, signal } from '@angular/core';
import { Observable, tap } from 'rxjs';

import { Alert, AlertPage, AlertView, AlertsStatus } from './alerts.models';

/** How often the alert list and the navigation badge refresh, in ms. 0 turns polling off. */
export const ALERT_POLL_MS = new InjectionToken<number>('ALERT_POLL_MS', {
  providedIn: 'root',
  factory: () => 15_000,
});

@Injectable({ providedIn: 'root' })
export class AlertsService {
  private readonly http = inject(HttpClient);

  /** Latest counts and baseline state; `null` until first loaded. */
  readonly status = signal<AlertsStatus | null>(null);

  list(view: AlertView, before: number | null = null): Observable<AlertPage> {
    let params = new HttpParams().set('status', view);
    if (before !== null) params = params.set('before', before);
    return this.http.get<AlertPage>('/api/alerts', { params });
  }

  /** Also publishes the result on `status`, so the navigation badge follows. */
  loadStatus(): Observable<AlertsStatus> {
    return this.http.get<AlertsStatus>('/api/alerts/status').pipe(
      tap((status) => this.status.set(status)),
    );
  }

  acknowledge(id: number): Observable<Alert> {
    return this.http.post<Alert>(`/api/alerts/${id}/acknowledge`, null);
  }

  resolve(id: number): Observable<Alert> {
    return this.http.post<Alert>(`/api/alerts/${id}/resolve`, null);
  }
}
