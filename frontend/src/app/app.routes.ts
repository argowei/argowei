import { Routes } from '@angular/router';

import { authGuard, loginGuard, setupGuard } from './core/auth.guard';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'devices' },
  {
    path: 'devices',
    canActivate: [authGuard],
    loadComponent: () => import('./features/devices/device-list').then((m) => m.DeviceList),
  },
  {
    path: 'devices/:id',
    canActivate: [authGuard],
    loadComponent: () => import('./features/devices/device-detail').then((m) => m.DeviceDetail),
  },
  {
    path: 'alerts',
    canActivate: [authGuard],
    loadComponent: () => import('./features/alerts/alert-list').then((m) => m.AlertList),
  },
  {
    path: 'events',
    canActivate: [authGuard],
    loadComponent: () => import('./features/events/event-timeline').then((m) => m.EventTimeline),
  },
  {
    path: 'schedules',
    canActivate: [authGuard],
    loadComponent: () => import('./features/schedules/schedule-list').then((m) => m.ScheduleList),
  },
  {
    path: 'login',
    canActivate: [loginGuard],
    loadComponent: () => import('./features/login/login').then((m) => m.Login),
  },
  {
    path: 'setup',
    canActivate: [setupGuard],
    loadComponent: () => import('./features/setup/setup').then((m) => m.Setup),
  },
  { path: '**', redirectTo: 'devices' },
];
