import { Routes } from '@angular/router';

import { authGuard, loginGuard, setupGuard } from './core/auth.guard';

export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    canActivate: [authGuard],
    loadComponent: () => import('./features/dashboard/dashboard').then((m) => m.Dashboard),
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
  { path: '**', redirectTo: '' },
];
