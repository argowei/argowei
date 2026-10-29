import { HttpClient } from '@angular/common/http';
import { Injectable, InjectionToken, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { Device, DevicePatch, Group } from './models';

/** How often the device list refreshes itself, in ms. 0 turns polling off. */
export const DEVICE_POLL_MS = new InjectionToken<number>('DEVICE_POLL_MS', {
  providedIn: 'root',
  factory: () => 10_000,
});

@Injectable({ providedIn: 'root' })
export class DevicesService {
  private readonly http = inject(HttpClient);

  list(): Observable<Device[]> {
    return this.http.get<Device[]>('/api/devices');
  }

  get(id: number): Observable<Device> {
    return this.http.get<Device>(`/api/devices/${id}`);
  }

  update(id: number, patch: DevicePatch): Observable<Device> {
    return this.http.patch<Device>(`/api/devices/${id}`, patch);
  }

  groups(): Observable<Group[]> {
    return this.http.get<Group[]>('/api/groups');
  }
}
