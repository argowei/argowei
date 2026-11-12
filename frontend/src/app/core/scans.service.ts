import { HttpClient } from '@angular/common/http';
import { Injectable, InjectionToken, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { API_BASE } from './api';
import { Scan, ScanProfile, ScanWithPorts } from './scan.models';

/** How often a device's scans refresh while one is in progress, in ms. 0 turns polling off. */
export const SCAN_POLL_MS = new InjectionToken<number>('SCAN_POLL_MS', {
  providedIn: 'root',
  factory: () => 3_000,
});

@Injectable({ providedIn: 'root' })
export class ScansService {
  private readonly http = inject(HttpClient);

  start(deviceId: number, profile: ScanProfile): Observable<Scan> {
    return this.http.post<Scan>(`${API_BASE}/devices/${deviceId}/scans`, { profile });
  }

  history(deviceId: number): Observable<Scan[]> {
    return this.http.get<Scan[]>(`${API_BASE}/devices/${deviceId}/scans`);
  }

  get(id: number): Observable<ScanWithPorts> {
    return this.http.get<ScanWithPorts>(`${API_BASE}/scans/${id}`);
  }

  cancel(id: number): Observable<Scan> {
    return this.http.post<Scan>(`${API_BASE}/scans/${id}/cancel`, null);
  }
}
