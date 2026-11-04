import { HttpClient } from '@angular/common/http';
import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed, toObservable } from '@angular/core/rxjs-interop';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { EMPTY, catchError, map, of, switchMap, timer } from 'rxjs';

import { ALERT_POLL_MS, AlertsService } from './core/alerts.service';
import { AuthService } from './core/auth.service';

interface HealthResponse {
  status: string;
}

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    @if (username(); as name) {
      <header class="topbar">
        <a class="brand" routerLink="/devices">Argowei</a>
        <nav aria-label="Main">
          <a routerLink="/devices" routerLinkActive="active">Devices</a>
          <a routerLink="/alerts" routerLinkActive="active">
            Alerts
            @if (openAlerts() > 0) {
              <span class="badge" aria-hidden="true">{{ openAlerts() }}</span>
              <span class="visually-hidden">({{ openAlerts() }} open)</span>
            }
          </a>
        </nav>
        <span class="spacer"></span>
        <span class="health" [class.online]="backend() === 'connected'" [title]="'Backend: ' + backend()">
          <span class="dot" aria-hidden="true"></span>
          <span class="visually-hidden">Backend: </span>{{ backend() }}
        </span>
        <span class="user">{{ name }}</span>
        <button type="button" class="secondary" (click)="logout()">Sign out</button>
      </header>
    }
    <main>
      <router-outlet />
    </main>
  `,
  styles: `
    .topbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.4rem 1rem;
      padding: 0.7rem 1.2rem;
      border-bottom: 1px solid var(--border);
      background: var(--bg-card);
      color: var(--muted);
    }

    .brand { color: var(--accent); font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
             font-size: 0.85rem; text-decoration: none; }
    nav a { color: var(--muted); text-decoration: none; padding: 0.3rem 0.1rem; }
    nav { display: flex; gap: 1rem; }
    nav a.active { color: var(--text); border-bottom: 2px solid var(--accent); }
    .badge { margin-left: 0.3rem; padding: 0 0.45rem; border-radius: 1rem; background: var(--warn);
             color: var(--bg); font-size: 0.75rem; font-weight: 700; }
    .spacer { flex: 1; }
    .health { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }
    .health.online { color: var(--accent); }
    .dot { width: 0.55rem; height: 0.55rem; border-radius: 50%; background: var(--danger); }
    .health.online .dot { background: var(--accent); }

    main {
      max-width: 72rem;
      margin: 0 auto;
      padding: 1.5rem 1.2rem 3rem;
    }
  `,
})
export class App {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly http = inject(HttpClient);
  private readonly alerts = inject(AlertsService);
  private readonly alertPollMs = inject(ALERT_POLL_MS);

  protected readonly backend = signal('checking…');

  protected readonly username = computed(() => {
    const session = this.auth.session();
    return session?.kind === 'authenticated' ? session.username : null;
  });

  /** Alerts nobody has looked at yet, shown as a badge in the navigation. */
  protected readonly openAlerts = computed(() => this.alerts.status()?.open ?? 0);

  constructor() {
    timer(0, 30_000)
      .pipe(
        switchMap(() =>
          this.http.get<HealthResponse>('/api/health').pipe(
            map(({ status }) => (status === 'ok' ? 'connected' : 'unknown')),
            catchError(() => of('unavailable')),
          ),
        ),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe((state) => this.backend.set(state));

    // Only ask for alerts while signed in; before that the API answers 401.
    const alertTicks$ = this.alertPollMs > 0 ? timer(0, this.alertPollMs) : timer(0);
    toObservable(this.username)
      .pipe(
        switchMap((name) =>
          name
            ? alertTicks$.pipe(
                switchMap(() => this.alerts.loadStatus().pipe(catchError(() => EMPTY))),
              )
            : EMPTY,
        ),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe();
  }

  protected logout(): void {
    const leave = () => void this.router.navigate(['/login']);
    // The session is gone either way; a failed request must not trap the user.
    this.auth.logout().subscribe({
      next: leave,
      error: () => {
        this.auth.markExpired();
        leave();
      },
    });
  }
}
