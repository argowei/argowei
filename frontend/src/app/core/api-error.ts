import { HttpErrorResponse } from '@angular/common/http';

/** A message safe to show for a failed API call. */
export function describeApiError(error: unknown): string {
  if (!(error instanceof HttpErrorResponse)) {
    return 'Something went wrong. Please try again.';
  }
  if (error.status === 0 || error.status >= 500) {
    return 'The server is unavailable. Please try again later.';
  }
  if (error.status === 404) {
    return 'This item no longer exists.';
  }
  const message = (error.error as { error?: unknown } | null)?.error;
  return typeof message === 'string' ? message : 'The request was rejected.';
}
