import { Component, input } from '@angular/core';

import { ScanComparison, describeService } from '../../core/scan.models';

/** What changed between two scans: opened, closed and changed ports. */
@Component({
  selector: 'app-scan-diff',
  template: `
    @let c = comparison();
    @if (c.diff.profile_mismatch) {
      <p class="banner info" role="note">
        These scans used different profiles ({{ c.older.profile }} and {{ c.newer.profile }}). Only
        ports both looked at are compared; the others are listed as not comparable.
      </p>
    }
    @if (c.diff.address_changed; as moved) {
      <p class="banner info" role="note">
        The device was scanned at {{ moved[0] }} before and at {{ moved[1] }} now.
      </p>
    }
    @if (!c.diff.opened.length && !c.diff.closed.length && !c.diff.changed.length) {
      <p class="unchanged">No changes: {{ c.diff.unchanged }} open port(s) look the same.</p>
    } @else {
      <ul class="changes">
        @for (p of c.diff.opened; track p.protocol + p.port) {
          <li class="opened">
            <strong>Opened</strong> {{ p.port }}/{{ p.protocol }} — {{ describe(p.service) }}
          </li>
        }
        @for (p of c.diff.closed; track p.protocol + p.port) {
          <li class="closed">
            <strong>Closed</strong> {{ p.port }}/{{ p.protocol }} — {{ describe(p.service) }}
          </li>
        }
        @for (p of c.diff.changed; track p.protocol + p.port) {
          <li class="changed">
            <strong>Changed</strong> {{ p.port }}/{{ p.protocol }} — {{ describe(p.before) }} →
            {{ describe(p.after) }}
          </li>
        }
      </ul>
      @if (c.diff.unchanged) {
        <p class="muted">{{ c.diff.unchanged }} other open port(s) unchanged.</p>
      }
    }
    @if (c.diff.not_comparable.length) {
      <p class="muted">
        Not comparable (only one scan looked):
        @for (p of c.diff.not_comparable; track p.protocol + p.port; let last = $last) {
          {{ p.port }}/{{ p.protocol }}{{ last ? '' : ', ' }}
        }
      </p>
    }
  `,
  styles: `
    .changes {
      list-style: none;
      margin: 0.5rem 0;
      padding: 0;
      display: grid;
      gap: 0.3rem;
    }
    .changes li {
      padding: 0.4rem 0.6rem;
      border-left: 3px solid var(--border);
      overflow-wrap: anywhere;
    }
    .opened {
      border-left-color: var(--warn) !important;
    }
    .opened strong {
      color: var(--warn);
    }
    .closed {
      color: var(--muted);
    }
    .changed {
      border-left-color: var(--accent) !important;
    }
    .changed strong {
      color: var(--accent);
    }
    .unchanged {
      color: var(--accent);
    }
  `,
})
export class ScanDiff {
  readonly comparison = input.required<ScanComparison>();

  protected describe = describeService;
}
