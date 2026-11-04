import { Pipe, PipeTransform } from '@angular/core';

import { timeAgo } from '../core/time';

/**
 * `{{ device.last_seen | timeAgo }}`: "5 min ago" and the like (see
 * `timeAgo`).
 *
 * Impure on purpose: the text depends on the current time, not only on the
 * input, so it is recomputed on every change detection, as polling triggers
 * it, instead of staying at "just now" until the value changes.
 */
@Pipe({ name: 'timeAgo', pure: false })
export class TimeAgoPipe implements PipeTransform {
  transform(iso: string): string {
    return timeAgo(iso);
  }
}
