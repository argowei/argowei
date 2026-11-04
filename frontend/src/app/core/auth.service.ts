import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, catchError, map, of, switchMap, tap, throwError } from 'rxjs';

export type Session =
  | { kind: 'setup' }
  | { kind: 'anonymous' }
  | { kind: 'authenticated'; username: string };

interface StatusResponse {
  setup_required: boolean;
}

interface UserResponse {
  username: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);

  /** `null` until the first status check has completed. */
  readonly session = signal<Session | null>(null);

  /** Resolves the current session once and serves it from memory afterwards. */
  resolve(): Observable<Session> {
    const known = this.session();
    if (known) {
      return of(known);
    }

    return this.http.get<StatusResponse>('/api/auth/status').pipe(
      switchMap(
        ({ setup_required }): Observable<Session> =>
          setup_required
            ? of({ kind: 'setup' })
            : this.http.get<UserResponse>('/api/auth/me').pipe(
                map(({ username }): Session => ({ kind: 'authenticated', username })),
                catchError((error: HttpErrorResponse) =>
                  error.status === 401
                    ? of<Session>({ kind: 'anonymous' })
                    : throwError(() => error),
                ),
              ),
      ),
      tap((session) => this.session.set(session)),
    );
  }

  login(username: string, password: string): Observable<void> {
    return this.http.post<UserResponse>('/api/auth/login', { username, password }).pipe(
      tap(({ username }) => this.session.set({ kind: 'authenticated', username })),
      map(() => undefined),
    );
  }

  /** Creates the admin account, then signs in with it. */
  setup(setupToken: string, username: string, password: string): Observable<void> {
    return this.http
      .post('/api/auth/setup', { setup_token: setupToken, username, password })
      .pipe(switchMap(() => this.login(username, password)));
  }

  logout(): Observable<void> {
    return this.http
      .post<void>('/api/auth/logout', null)
      .pipe(tap(() => this.session.set({ kind: 'anonymous' })));
  }

  /** The server rejected our session (expired or revoked). */
  markExpired(): void {
    this.session.set({ kind: 'anonymous' });
  }
}

/** Turns an auth API failure into a message safe to show the user. */
export function describeAuthError(error: unknown): string {
  if (!(error instanceof HttpErrorResponse)) {
    return 'Something went wrong. Please try again.';
  }

  switch (error.status) {
    case 400:
      return error.error?.error ?? 'Please check your input.';
    case 401:
      return 'Invalid username or password.';
    case 403:
      return 'Invalid setup token.';
    case 409:
      return 'Setup has already been completed.';
    case 429: {
      const seconds = Number(error.headers.get('Retry-After'));
      return seconds > 0
        ? `Too many attempts. Try again in ${seconds} s.`
        : 'Too many attempts. Try again shortly.';
    }
    default:
      return 'The server is unavailable. Please try again later.';
  }
}
