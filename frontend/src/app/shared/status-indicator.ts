import { Component, input } from '@angular/core';

/** A device's presence: a colored dot and "Online" or "Offline". */
@Component({
  selector: 'app-status-indicator',
  template: `
    <span class="status" [class.online]="online()">
      <span class="dot" aria-hidden="true"></span>{{ online() ? 'Online' : 'Offline' }}
    </span>
  `,
  styles: `
    .status {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      color: var(--muted);
    }
    .status.online {
      color: var(--accent);
    }
    .dot {
      width: 0.55rem;
      height: 0.55rem;
      border-radius: 50%;
      background: currentColor;
    }
  `,
})
export class StatusIndicator {
  readonly online = input.required<boolean>();
}
