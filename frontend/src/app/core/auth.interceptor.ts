import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { tap } from 'rxjs';

import { AuthService } from './auth.service';
import { API_BASE } from './api';

/**
 * Sends the user to the login page when the API reports an expired or
 * revoked session. The auth endpoints themselves are exempt: a 401 from
 * login or the session probe is an expected answer, not an expiry.
 */
export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  return next(request).pipe(
    tap({
      error: (error: unknown) => {
        if (
          error instanceof HttpErrorResponse &&
          error.status === 401 &&
          !request.url.startsWith(`${API_BASE}/auth/`)
        ) {
          auth.markExpired();
          void router.navigate(['/login'], {
            queryParams: { returnUrl: router.url },
          });
        }
      },
    }),
  );
};
