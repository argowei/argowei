import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { API_BASE } from './api';
import { CronPreview, ScanSchedule, ScheduleInput } from './schedule.models';

@Injectable({ providedIn: 'root' })
export class SchedulesService {
  private readonly http = inject(HttpClient);
  private readonly base = `${API_BASE}/scan-schedules`;

  list(): Observable<ScanSchedule[]> {
    return this.http.get<ScanSchedule[]>(this.base);
  }

  create(input: ScheduleInput): Observable<ScanSchedule> {
    return this.http.post<ScanSchedule>(this.base, input);
  }

  update(id: number, change: Partial<ScheduleInput>): Observable<ScanSchedule> {
    return this.http.patch<ScanSchedule>(`${this.base}/${id}`, change);
  }

  remove(id: number): Observable<void> {
    return this.http.delete<void>(`${this.base}/${id}`);
  }

  /** Checks an expression and returns its next runs (422 when invalid). */
  preview(cron: string): Observable<CronPreview> {
    return this.http.get<CronPreview>(`${this.base}/preview`, {
      params: new HttpParams().set('cron', cron),
    });
  }
}
