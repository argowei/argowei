import { EMPTY, Observable, timer } from 'rxjs';

/**
 * Ticks for a polling loop: one now and then every `intervalMs`, or, with
 * `immediate: false`, only the later ones. An interval of 0 turns polling
 * off: an immediate loop then ticks once (the initial load), a delayed one
 * never.
 *
 * Pair it with `switchMap` so a slow response is dropped once the next tick
 * has started a newer request.
 */
export function poll(intervalMs: number, { immediate = true } = {}): Observable<number> {
  if (intervalMs <= 0) return immediate ? timer(0) : EMPTY;
  return timer(immediate ? 0 : intervalMs, intervalMs);
}
