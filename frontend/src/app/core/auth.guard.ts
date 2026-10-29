import { inject } from '@angular/core';
import { CanActivateFn, Router, UrlTree } from '@angular/router';
import { catchError, map, of } from 'rxjs';

import { AuthService, Session } from './auth.service';

type Page = 'app' | 'login' | 'setup';

function guard(page: Page): CanActivateFn {
  return (_route, state) => {
    const router = inject(Router);

    const decide = (session: Session): boolean | UrlTree => {
      switch (session.kind) {
        case 'setup':
          return page === 'setup' ? true : router.createUrlTree(['/setup']);
        case 'anonymous':
          if (page === 'login') return true;
          return router.createUrlTree(['/login'], {
            queryParams: page === 'app' ? { returnUrl: state.url } : {},
          });
        case 'authenticated':
          return page === 'app' ? true : router.createUrlTree(['/']);
      }
    };

    return inject(AuthService)
      .resolve()
      .pipe(
        map(decide),
        // Backend unreachable: show the login page, which reports errors on submit.
        catchError(() => of(page === 'login' ? true : router.createUrlTree(['/login']))),
      );
  };
}

/** Protects pages that need a signed-in admin. */
export const authGuard = guard('app');
/** Login page: only for signed-out users. */
export const loginGuard = guard('login');
/** First-run setup page: only while no admin exists. */
export const setupGuard = guard('setup');

/** Accepts only same-app paths, so `?returnUrl=` cannot cause an open redirect. */
export function safeReturnUrl(value: string | null): string {
  return value && value.startsWith('/') && !value.startsWith('//') ? value : '/';
}
